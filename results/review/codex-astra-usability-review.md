The biggest usability problems are misleading health checks, incomplete event-to-message retrieval, and onboarding examples that require unstated adjustments.

I reviewed the three paths—new developer, operator, then harness integrator—against the source. This was static, read-only review: no files changed, no network or Docker commands, and no runtime tests.

Findings are ranked by user impact.

1. **High — `doctor` success does not mean messaging is operational.**  
   [docs/runbook.md:92](/Users/dennison/develop/FIC-elipsis/docs/runbook.md:92) defines exit 0 as “all ok.” However, an unavailable daemon is only a warning, transport `ready=false` is only a warning, and dependent checks can be skipped. Only failed checks produce exit 7. See [doctor.rs:294](/Users/dennison/develop/FIC-elipsis/crates/cli/src/doctor.rs:294), [doctor.rs:466](/Users/dennison/develop/FIC-elipsis/crates/cli/src/doctor.rs:466), and [main.rs:795](/Users/dennison/develop/FIC-elipsis/crates/cli/src/main.rs:795).

   **User experience:** a supervisor or operator can treat a stopped daemon as healthy.

   **Change:** add a readiness mode that fails for unavailable daemons, unready transport, or skipped required checks. Immediately replace the documentation with:  
   > “Exit 0 means no checks failed; warnings and skipped checks can still mean messaging is unavailable. For readiness, require `daemon socket` and `transport ready` to report `ok`.”

2. **High — The relay Store troubleshooting check actually tests the local database.**  
   [docs/runbook.md:187](/Users/dennison/develop/FIC-elipsis/docs/runbook.md:187) recommends `doctor`’s `store query` for missing offline messages. The implementation calls `read_inbox`, then prints `store query: inbox query works`; it does not query relay history. See [doctor.rs:479](/Users/dennison/develop/FIC-elipsis/crates/cli/src/doctor.rs:479).

   **User experience:** a green result falsely appears to eliminate the relay Store as the cause.

   **Change:** rename the check **“local inbox database”** and say:  
   > “Doctor checks the local inbox database, not relay Store retrieval. Check the last history-sync time and inspect the service node separately.”

   A separate relay Store probe would make this playbook substantially more useful.

3. **High — An event-driven harness cannot directly retrieve the message named by an event.**  
   [docs/host-integration.md:15](/Users/dennison/develop/FIC-elipsis/docs/host-integration.md:15) tells the harness to obtain message content through `read_inbox`. Events supply a `message_id`, but `read_inbox` has no message-ID filter, and there is no direct message lookup. See [api.rs:153](/Users/dennison/develop/FIC-elipsis/crates/core/src/api.rs:153) and [api.rs:435](/Users/dennison/develop/FIC-elipsis/crates/core/src/api.rs:435).

   **User experience:** the obvious integration—receive event, fetch message, process it—requires scanning or maintaining an inbox index. The mock harness does not demonstrate this missing step.

   **Change:** expose `get_message(message_id)` or an inbox message-ID filter, with a complete fetch-and-handle example. Until then document explicitly:  
   > “The event cursor is not an inbox cursor. Page through `read_inbox` to locate the event’s `message_id`, or maintain an inbox index.”

4. **Medium — The recovery playbook suggests a resend that may send nothing.**  
   [docs/runbook.md:160](/Users/dennison/develop/FIC-elipsis/docs/runbook.md:160) advises sending again after expiry/failure and says an idempotency key makes that safe. Reusing the original key returns the existing message—including its terminal status—without requeuing it. See [send.rs:141](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:141).

   **Change:**  
   > “Reuse the original idempotency key when retrying an uncertain send request. To create a new message after failure or expiry, use a new key or omit it. Reusing the old key returns the original message without resending. A missing receipt does not prove non-delivery.”

5. **Medium — The first relay-start command can hide its failure and has an undocumented prerequisite.**  
   The prerequisites list Rust, Docker, standalone Compose, `jq`, `curl`, Unix and a compiler, but the helper also invokes `python3`. More significantly, it discards Compose errors, continues after readiness-loop exhaustion, and does not explicitly fail startup. See [README.md:32](/Users/dennison/develop/FIC-elipsis/README.md:32) and [up.sh:10](/Users/dennison/develop/FIC-elipsis/spike/relay/scripts/up.sh:10).

   **User experience:** missing Compose, image-start failures, or missing Python can become long waits and confusing peer output instead of an actionable startup error.

   **Change:** preflight required executables, preserve startup stderr, and exit nonzero when readiness times out. Add **“Python 3, used by the relay startup helper”** to prerequisites.

6. **Medium — The quickstart is a manual transcript, with gaps between successive steps.**  
   Getting through the first message takes six stages and roughly two dozen shell lines. Then:

   - “Two terminals” requires carrying `$A` and `$B` into those terminals.
   - Daemons are backgrounded immediately before commands that require them.
   - Step 7 replaces the demo directory with `/home/you/.agentnet`.
   - The harness starts in the background immediately before its output file is read.

   See [README.md:74](/Users/dennison/develop/FIC-elipsis/README.md:74), [README.md:105](/Users/dennison/develop/FIC-elipsis/README.md:105), and [README.md:127](/Users/dennison/develop/FIC-elipsis/README.md:127). The verification script inserts waits absent from these instructions and requires scratch-build environment variables: [readme-quickstart.sh:9](/Users/dennison/develop/FIC-elipsis/results/audit/readme-quickstart.sh:9).

   **Change:** provide a user-facing demo script with prerequisite checks, bounded readiness/delivery waits, captured process IDs and cleanup. Keep the manual instructions as its explanation. Immediately say **“Run these commands in the same shell”**, and generate the MCP configuration using the actual binary path and `$A`. Mark MCP and triggers as optional extensions after the first-message success point.

7. **Medium — MCP advertises session identifiers the engine rejects.**  
   [dto.rs:245](/Users/dennison/develop/FIC-elipsis/crates/mcp/src/dto.rs:245) permits 256 characters without control characters. The engine accepts at most 128 bytes, restricted to ASCII `!` through `~`; spaces and Unicode are rejected. See [triggers.rs:177](/Users/dennison/develop/FIC-elipsis/crates/core/src/triggers.rs:177). The documentation repeats the broader limit at [docs/mcp-api.md:89](/Users/dennison/develop/FIC-elipsis/docs/mcp-api.md:89).

   **User experience:** an integrator follows the published schema and still cannot create a trigger.

   **Change:** align schema, validation and documentation:  
   > “Host-allowlisted session identifier: 1–128 ASCII characters from `!` through `~`; no spaces.”

8. **Medium — The model-facing send description overpromises retry duration.**  
   [server.rs:276](/Users/dennison/develop/FIC-elipsis/crates/mcp/src/server.rs:276) says retries continue until TTL expiry. The implementation stops publishing after `max_attempts` accepted publishes, leaving the message `sent`. This is correctly explained in [docs/protocol.md:453](/Users/dennison/develop/FIC-elipsis/docs/protocol.md:453) and implemented at [send.rs:341](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:341).

   **Change:**  
   > “Retries are bounded by the message TTL and the host’s accepted-publish attempt limit. A message can remain `sent` after retries stop. Check `get_message_status` for delivery and retry information.”

9. **Medium — MCP cannot inspect the existing address book.**  
   Contact listing exists in the core/socket API but has no MCP tool or resource, as acknowledged at [docs/mcp-api.md:248](/Users/dennison/develop/FIC-elipsis/docs/mcp-api.md:248). The resource list confirms the omission: [server.rs:749](/Users/dennison/develop/FIC-elipsis/crates/mcp/src/server.rs:749).

   **User experience:** a fresh agent session asked to “message Alice” cannot look up a contact the user already saved. Discovery is not a substitute for the local address book.

   **Change:** expose read-only `list_contacts`, including alias, address and trust. Suggested description:  
   > “List this agent’s saved contacts, local aliases and trust decisions. Use the returned address with `send_message`.”

10. **Medium — The discovery activation example leaves discovery disabled.**  
    Under “Enabling it,” the copyable block contains `enabled = false`: [docs/discovery.md:28](/Users/dennison/develop/FIC-elipsis/docs/discovery.md:28). Actual CLI usage follows extensive wire-format details.

    **User experience:** copying the activation example produces policy-denied errors.

    **Change:** lead with:
    ```toml
    [discovery]
    enabled = true
    topics = ["general"]
    ```
    Then say **“Restart both daemons after changing this configuration. Both agents must authorize the same topic.”** Follow immediately with concrete advertise/list commands; move the default reference and wire format below them.

11. **Medium — Some corrective CLI messages prescribe the wrong command or directory.**  
    `init --data-dir …` ends with `Next: agentnet serve`, omitting the selected directory: [main.rs:237](/Users/dennison/develop/FIC-elipsis/crates/cli/src/main.rs:237). Missing-daemon errors similarly suggest bare `agentnet serve`: [client.rs:29](/Users/dennison/develop/FIC-elipsis/crates/daemon/src/client.rs:29). Unknown-recipient errors say `add_contact first`, although the CLI command is `contact add`: [send.rs:179](/Users/dennison/develop/FIC-elipsis/crates/core/src/send.rs:179).

    **User experience:** following the suggested fix can target another identity or invoke a nonexistent command.

    **Change:** print a shell-quoted command preserving the actual data directory. In CLI presentation, translate contact remediation to:  
    > “Recipient is not a known contact. Add their signed record with `agentnet --data-dir <dir> contact add @<file> --expect <address>`.”

12. **Low — Configuration defaults are documented before the minimum runnable configuration.**  
    [docs/configuration.md:4](/Users/dennison/develop/FIC-elipsis/docs/configuration.md:4) says every section is optional, but default private-mode configuration cannot start without peers; validation enforces this at [config.rs:248](/Users/dennison/develop/FIC-elipsis/crates/daemon/src/config.rs:248).

    **Change:** begin with:  
    > “Omitted keys use defaults, but private mode requires at least one relay address in `[network].peers`.”

    Follow with a minimal `[network]` example containing `node_url` and `peers`. Keep the complete defaults tables below it.

13. **Low — The documentation leads with audit/library detail instead of the reader’s next action.**  
    The README places dense caveats before the product explanation: [README.md:3](/Users/dennison/develop/FIC-elipsis/README.md:3). The MCP guide begins with Rust constructors and negotiation details rather than client connection instructions: [docs/mcp-api.md:11](/Users/dennison/develop/FIC-elipsis/docs/mcp-api.md:11).

    **Change:** put the product explanation first, followed by one compact status statement:  
    > “Experimental MVP, validated on one host. Requires a Logos Delivery sidecar for each agent. Not independently audited; cross-machine operation remains unvalidated.”

    Add early links for **Run the local demo**, **Operate a deployment**, and **Connect a harness**. Lead the MCP guide with connection configuration and a successful `get_identity` example; move Rust embedding and negotiation later.

14. **Low — Stale statements make current status and expected output inconsistent.**  
    Concrete examples:

    - [README.md:5](/Users/dennison/develop/FIC-elipsis/README.md:5) calls `MIT OR Apache-2.0` provisional; [README.md:244](/Users/dennison/develop/FIC-elipsis/README.md:244) says MIT was chosen, matching `Cargo.toml`.
    - [README.md:95](/Users/dennison/develop/FIC-elipsis/README.md:95) describes a 60-second history-sync interval; the current default is 15 seconds.
    - [README.md:79](/Users/dennison/develop/FIC-elipsis/README.md:79) promises every doctor line is `[ok]`; the single-instance warning is unconditional.
    - [docs/relay-setup.md:215](/Users/dennison/develop/FIC-elipsis/docs/relay-setup.md:215) describes a successful single-host tailnet run and then says no tailnet/client was available.

    **Change:** retain historical values only beside dated measurements. Use **“Expect zero failing checks; the single-instance warning is expected”**, and distinguish single-host tailnet validation from untested cross-machine operation consistently.

The best **quick wins—each plausibly under an hour—**are:

- Correct the resend/idempotency and MCP retry wording.
- Rename `store query` and clarify doctor’s exit-code semantics.
- Fix the discovery activation block and add restart instructions.
- Preserve `--data-dir` in printed next steps.
- Add Python 3 to prerequisites and correct the MCP demo path.
- Reconcile the session-ID schema with the engine.
- Remove stale licence, timing and validation-status statements.

Several things are already good and should be preserved:

- The architecture diagram clearly separates daemon, sidecar and relay.
- CLI/MCP explanations distinguish **queued**, **sent**, **delivered**, and local acknowledgement unusually well.
- Human output, JSON output and documented exit codes provide a useful foundation for both interactive use and scripts.
- The runbook’s symptom/cause/check/action structure is effective.
- Cursor replay, event deduplication and lossy notification semantics are explained concretely.
- Configuration tables and generated example configs are valuable; improve their entry point rather than replacing them.
- Discovery clearly distinguishes capability discovery from network-peer discovery.