//! Wire format of the control and event socket (`agentnet.sock`).
//!
//! Newline-delimited JSON, one object per line, UTF-8. See
//! `docs/host-integration.md` for the protocol description.

use agentnet_core::api::{ApiError, ChangeHint};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Protocol version announced in the hello reply.
pub const PROTOCOL_VERSION: u32 = 1;
/// Longest request line the server accepts (1 MiB).
pub const MAX_REQUEST_LINE: usize = 1024 * 1024;
/// Longest hello line the server accepts.
pub const MAX_HELLO_LINE: usize = 4096;
/// Longest response/event line the client accepts (a full `read_inbox` page of
/// 200 maximum-size bodies stays below this).
pub const MAX_RESPONSE_LINE: usize = 64 * 1024 * 1024;

/// `{"hello":{"token":"...","client":"..."}}`
#[derive(Debug, Deserialize)]
pub struct HelloFrame {
    /// The hello payload.
    pub hello: Hello,
}

/// Contents of the first line a client sends.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Contents of `control.token`. Never logged.
    pub token: String,
    /// Free-form client name for diagnostics.
    #[serde(default)]
    pub client: Option<String>,
}

impl std::fmt::Debug for Hello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hello")
            .field("token", &"<redacted>")
            .field("client", &self.client)
            .finish()
    }
}

/// `{"id":n,"method":"...","params":{...}}`
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Caller-chosen correlation id, echoed in the response.
    pub id: u64,
    /// Method name.
    pub method: String,
    /// Method parameters (object, or absent).
    #[serde(default)]
    pub params: Value,
}

/// A successful response line.
pub fn ok_line(id: u64, result: Value) -> String {
    json!({"id": id, "result": result}).to_string()
}

/// An error response line (`id` is null when the request could not be parsed).
pub fn err_line(id: Option<u64>, e: &ApiError) -> String {
    json!({"id": id, "error": e}).to_string()
}

/// A streamed event line.
pub fn event_line<T: Serialize>(ev: &T) -> String {
    json!({"event": ev}).to_string()
}

/// A streamed change-hint line.
pub fn change_line(h: &ChangeHint) -> String {
    json!({"change": h}).to_string()
}

/// One hint of every kind that can be enumerated, used when hints were missed.
pub fn all_hints() -> Vec<ChangeHint> {
    vec![
        ChangeHint::Inbox,
        ChangeHint::Outbox,
        ChangeHint::Triggers,
        ChangeHint::Identity,
        ChangeHint::Events,
    ]
}

/// Outcome of [`read_line`].
#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// Clean end of stream (an unterminated trailing fragment is discarded).
    Eof,
    /// The line exceeded the limit; the stream position is undefined afterwards.
    TooLong,
    /// A complete line without its terminator.
    Line(Vec<u8>),
}

/// Read one `\n`-terminated line of at most `max` bytes without buffering more
/// than `max` bytes.
pub async fn read_line<R: AsyncBufRead + Unpin>(r: &mut R, max: usize) -> std::io::Result<Line> {
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let avail = r.fill_buf().await?;
        if avail.is_empty() {
            return Ok(Line::Eof);
        }
        match avail.iter().position(|b| *b == b'\n') {
            Some(i) => {
                if buf.len() + i > max {
                    return Ok(Line::TooLong);
                }
                buf.extend_from_slice(&avail[..i]);
                r.consume(i + 1);
                return Ok(Line::Line(buf));
            }
            None => {
                let n = avail.len();
                if buf.len() + n > max {
                    return Ok(Line::TooLong);
                }
                buf.extend_from_slice(avail);
                r.consume(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn bounded_line_reader() {
        let data = b"abc\nlonglonglong\n\npartial".to_vec();
        let mut r = BufReader::with_capacity(4, &data[..]);
        assert_eq!(
            read_line(&mut r, 8).await.unwrap(),
            Line::Line(b"abc".to_vec())
        );
        assert_eq!(read_line(&mut r, 8).await.unwrap(), Line::TooLong);
        let mut r = BufReader::with_capacity(4, &b"x\n\nrest"[..]);
        assert_eq!(
            read_line(&mut r, 8).await.unwrap(),
            Line::Line(b"x".to_vec())
        );
        assert_eq!(read_line(&mut r, 8).await.unwrap(), Line::Line(Vec::new()));
        assert_eq!(read_line(&mut r, 8).await.unwrap(), Line::Eof);
    }

    #[test]
    fn hello_debug_hides_the_token() {
        let h: HelloFrame =
            serde_json::from_str(r#"{"hello":{"token":"sekrit","client":"x"}}"#).unwrap();
        assert!(!format!("{h:?}").contains("sekrit"));
    }
}
