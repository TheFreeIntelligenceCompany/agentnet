//! Mapping of [`ApiError`] and validation failures onto MCP error behaviour.
//!
//! Policy (MCP 2026-07-28, `server/tools.mdx` "Error Handling" and
//! `server/resources.mdx` "Error Handling"):
//!
//! * Tools: "Protocol Errors indicate issues with the request structure itself
//!   that models are less likely to be able to fix: unknown tool, malformed
//!   requests, server errors" are JSON-RPC errors. "Tool Execution Errors contain
//!   actionable feedback that language models can use to self-correct ... API
//!   failures, input validation errors (e.g. date in wrong format, value out of
//!   range), business logic errors" are results with `isError: true`.
//!   So every [`ApiError`] class except `internal` (and every validation failure
//!   made by this crate) is a tool execution error; `internal` is JSON-RPC
//!   `-32603`.
//! * Resources: "If the requested resource does not exist, servers MUST return a
//!   JSON-RPC error with code -32602 (Invalid Params). Servers SHOULD return
//!   -32603 for internal errors." Resource reads have no `isError`, so argument
//!   problems are `-32602` and internal/unavailable problems are `-32603`.
//!
//! Only the already-sanitized [`ApiError::message`] is ever forwarded.

use agentnet_core::api::{ApiError, ErrorCode};
use rmcp::{
    handler::server::tool::IntoCallToolResult,
    model::{CallToolResponse, CallToolResult, ContentBlock, ProtocolVersion},
    ErrorData,
};
use serde_json::{json, Value};

/// Stable machine-readable code string for an [`ErrorCode`].
pub fn code_str(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::InvalidArgument => "invalid_argument",
        ErrorCode::NotFound => "not_found",
        ErrorCode::PolicyDenied => "policy_denied",
        ErrorCode::Unavailable => "unavailable",
        ErrorCode::TooLarge => "too_large",
        ErrorCode::Conflict => "conflict",
        ErrorCode::Internal => "internal",
    }
}

/// Failure of a tool call. Converts into either an `isError: true` result or a
/// JSON-RPC error, per the policy in the module docs.
#[derive(Debug)]
pub struct ToolFailure(Kind);

#[derive(Debug)]
enum Kind {
    /// `isError: true` result carrying `{"error": {code, message, retryable}}`.
    Execution {
        code: &'static str,
        message: String,
        retryable: bool,
    },
    /// JSON-RPC error.
    Protocol(ErrorData),
}

impl ToolFailure {
    /// A request argument violated a documented limit or format.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self(Kind::Execution {
            code: "invalid_argument",
            message: message.into(),
            retryable: false,
        })
    }

    /// Map an engine error.
    pub fn from_api(error: ApiError) -> Self {
        tracing::debug!(code = code_str(error.code), "tool call failed");
        match error.code {
            ErrorCode::Internal => Self(Kind::Protocol(ErrorData::internal_error(
                error.message,
                Some(json!({ "code": "internal" })),
            ))),
            code => Self(Kind::Execution {
                code: code_str(code),
                message: error.message,
                retryable: code == ErrorCode::Unavailable,
            }),
        }
    }

    /// The `isError` payload, if this is a tool execution error (used by tests
    /// and docs examples).
    pub fn execution_payload(&self) -> Option<Value> {
        match &self.0 {
            Kind::Execution {
                code,
                message,
                retryable,
            } => Some(json!({"error": {"code": code, "message": message, "retryable": retryable}})),
            Kind::Protocol(_) => None,
        }
    }
}

impl From<ApiError> for ToolFailure {
    fn from(e: ApiError) -> Self {
        Self::from_api(e)
    }
}

impl IntoCallToolResult for ToolFailure {
    fn into_call_tool_result(self) -> Result<CallToolResponse, ErrorData> {
        match self.0 {
            Kind::Protocol(e) => Err(e),
            Kind::Execution {
                code,
                message,
                retryable,
            } => {
                let payload =
                    json!({"error": {"code": code, "message": message, "retryable": retryable}});
                Ok(CallToolResult::error(vec![ContentBlock::text(payload.to_string())]).into())
            }
        }
    }
}

/// True if `version` is 2026-07-28 or newer (the era where resource-not-found is
/// `-32602`; earlier revisions used `-32002`).
fn is_modern(version: Option<&ProtocolVersion>) -> bool {
    version.is_none_or(|v| v.as_str() >= ProtocolVersion::V_2026_07_28.as_str())
}

/// Standard "resource not found" error for the negotiated protocol version.
pub fn resource_not_found(uri: &str, version: Option<&ProtocolVersion>) -> ErrorData {
    let data = Some(json!({ "uri": uri, "code": "not_found" }));
    if is_modern(version) {
        ErrorData::invalid_params("Resource not found", data)
    } else {
        ErrorData::resource_not_found("Resource not found", data)
    }
}

/// An argument of a resource read (cursor, limit, query) was invalid.
pub fn resource_invalid(uri: &str, message: impl Into<String>) -> ErrorData {
    ErrorData::invalid_params(
        message.into(),
        Some(json!({ "uri": uri, "code": "invalid_argument" })),
    )
}

/// Map an engine error raised while reading a resource.
pub fn resource_error(error: ApiError, uri: &str, version: Option<&ProtocolVersion>) -> ErrorData {
    tracing::debug!(code = code_str(error.code), "resource read failed");
    match error.code {
        ErrorCode::NotFound => resource_not_found(uri, version),
        ErrorCode::InvalidArgument
        | ErrorCode::TooLarge
        | ErrorCode::Conflict
        | ErrorCode::PolicyDenied => ErrorData::invalid_params(
            error.message,
            Some(json!({ "uri": uri, "code": code_str(error.code) })),
        ),
        ErrorCode::Unavailable | ErrorCode::Internal => ErrorData::internal_error(
            error.message,
            Some(json!({ "uri": uri, "code": code_str(error.code) })),
        ),
    }
}
