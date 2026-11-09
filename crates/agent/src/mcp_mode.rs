//! M3.5 sandbox-side MCP control-plane server (plan §3): `sync-agent mcp`.
//!
//! Spawned by OpenCode in the sandbox via `mcpServers` (cwd anywhere — the sync
//! root resolves from `--root` / `$SYNC_AGENT_ROOT` / `/sandbox` exactly like
//! serve mode). Speaks MCP over STDIO: stdout is the TRANSPORT, so every log
//! line here goes to stderr.
//!
//! CONTROL PLANE ONLY (plan §3 — never bulk file data): the tools read the
//! daemon-written `<root>/.sync-agent/sync-state.json` and write
//! `<root>/.sync-agent/control-requests.json`. No scans, no hashing, no
//! file-content reads/writes outside `.sync-agent/`.
//!
//! Layering: [`ToolCtx`] holds ALL the tool logic as plain functions returning
//! `Result<String, String>` (unit-testable without a transport); the rmcp
//! wrapper (`SyncMcpServer`) is a thin shell mapping those to MCP results.
//!
//! rmcp API deltas vs the older 0.x docs (verified against rmcp 3.9.0 source):
//! - `get_info` returns `ServerConfig` (alias of `InitializeResult`); `ServerInfo`
//!   is deprecated.
//! - `#[tool]` fns take arguments as `Parameters<T>` (one struct per tool,
//!   `Deserialize + JsonSchema`); there is no per-arg `#[tool(param)]` syntax.
//! - Tool errors that the CALLER should read are
//!   `Ok(CallToolResult::error(..))` (isError=true); `Err(McpError)` is for
//!   protocol-level failures only.
//! - Content items are `ContentBlock` (3.9 name), not `Content`.

use std::error::Error;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig};
use rmcp::schemars::JsonSchema;
use rmcp::{tool, tool_handler, tool_router, ErrorData as McpError, ServerHandler, ServiceExt};
use serde::Deserialize;
use sync_proto::control::{self, ConflictResolution, ControlRequests, SyncState};

// ---------------------------------------------------------------------------
// Tool layer (pure logic over the control-plane files)
// ---------------------------------------------------------------------------

/// The sync root every tool operates on. All state lives under
/// `<root>/.sync-agent/`; corrupt files read as default per control.rs.
#[derive(Debug, Clone)]
pub(crate) struct ToolCtx {
    root: PathBuf,
}

impl ToolCtx {
    pub(crate) fn new(root: PathBuf) -> Self {
        ToolCtx { root }
    }

    /// `sync_status` — compact JSON + a human summary line (the LLM reads both).
    pub(crate) fn sync_status(&self) -> Result<String, String> {
        let state = control::read_sync_state(&self.root)
            .map_err(|e| format!("sync_status: cannot read sync state: {e}"))?;
        let pending = control::read_control_requests(&self.root)
            .map_err(|e| format!("sync_status: cannot read control requests: {e}"))?;
        let pending = pending.unwrap_or_default();
        Ok(render_status(state.as_ref(), &pending))
    }

    /// `sync_pause` — stop syncing entirely until resume.
    pub(crate) fn sync_pause(&self) -> Result<String, String> {
        merge_and_report(
            &self.root,
            ControlRequests {
                paused: true,
                ..ControlRequests::default()
            },
            "paused (takes effect on the next sync pass)",
        )
    }

    /// `sync_resume` — the bare-default write IS the resume marker per
    /// control.rs merge semantics (all-default except paused=false).
    pub(crate) fn sync_resume(&self) -> Result<String, String> {
        merge_and_report(&self.root, ControlRequests::default(), "resumed")
    }

    /// `sync_resolve_conflict` — record how the next pass must settle `path`.
    pub(crate) fn sync_resolve_conflict(&self, path: &str, choice: &str) -> Result<String, String> {
        // Validation first, against the CURRENT reported state: an unknown
        // choice or a path that is not a known conflict is caller error, and
        // the error must list what IS valid/known (no silent no-ops).
        validate_choice(choice)?;
        let state = control::read_sync_state(&self.root)
            .map_err(|e| format!("sync_resolve_conflict: cannot read sync state: {e}"))?;
        validate_conflict_path(path, state.as_ref())?;
        merge_and_report(
            &self.root,
            ControlRequests {
                resolutions: vec![ConflictResolution {
                    path: path.to_string(),
                    choice: choice.to_string(),
                }],
                ..ControlRequests::default()
            },
            &format!(
                "resolution recorded: {path} -> {choice} (honored on the next sync pass; \
                 the losing side's divergent content will be dropped)"
            ),
        )
    }

    /// `sync_now` — nudge the daemon to run a pass.
    pub(crate) fn sync_now(&self) -> Result<String, String> {
        merge_and_report(
            &self.root,
            ControlRequests {
                sync_now: true,
                ..ControlRequests::default()
            },
            "sync requested (runs on the next sync pass / daemon loop)",
        )
    }

    /// `sync_ignore_add` — append a pattern to the laptop's `.syncignore`.
    pub(crate) fn sync_ignore_add(&self, pattern: &str) -> Result<String, String> {
        validate_ignore_pattern(pattern)?;
        merge_and_report(
            &self.root,
            ControlRequests {
                ignore_add: vec![pattern.to_string()],
                ..ControlRequests::default()
            },
            &format!(
                "pattern recorded (appended to the laptop's .syncignore on the next pass): {pattern}"
            ),
        )
    }
}

/// Merge `update` into the pending control requests and report the merged
/// state so the caller sees what actually stuck (merge semantics accumulate).
fn merge_and_report(root: &Path, update: ControlRequests, ok_msg: &str) -> Result<String, String> {
    let merged = control::merge_control_requests(root, update)
        .map_err(|e| format!("cannot write control requests: {e}"))?;
    if merged.is_empty() {
        // Only reachable via sync_resume over an empty pending set.
        Ok(ok_msg.to_string())
    } else {
        Ok(format!(
            "{ok_msg}\npending now: {}",
            pending_summary(&merged)
        ))
    }
}

/// One-line human description of what is pending (for tool results).
fn pending_summary(pending: &ControlRequests) -> String {
    let mut parts = Vec::new();
    if pending.paused {
        parts.push("paused".to_string());
    }
    if !pending.resolutions.is_empty() {
        let list: Vec<String> = pending
            .resolutions
            .iter()
            .map(|r| format!("{} -> {}", r.path, r.choice))
            .collect();
        parts.push(format!("resolution(s): {}", list.join(", ")));
    }
    if !pending.ignore_add.is_empty() {
        parts.push(format!(
            "ignore pattern(s): {}",
            pending.ignore_add.join(", ")
        ));
    }
    if pending.sync_now {
        parts.push("sync-now".to_string());
    }
    if parts.is_empty() {
        "nothing".to_string()
    } else {
        parts.join("; ")
    }
}

/// A resolution choice must be one control.rs knows.
fn validate_choice(choice: &str) -> Result<(), String> {
    if control::is_valid_choice(choice) {
        Ok(())
    } else {
        Err(format!(
            "invalid choice {choice:?}: valid choices are \"keep-local\" (laptop wins) or \
             \"keep-remote\" (sandbox wins)"
        ))
    }
}

/// The path must BE a known conflict in the daemon-reported state — resolving
/// a non-conflicting path would silently queue a request the daemon has to
/// report as stale (better to catch it here with the live conflict list).
fn validate_conflict_path(path: &str, state: Option<&SyncState>) -> Result<(), String> {
    let Some(state) = state else {
        return Err(
            "no sync state reported yet (the daemon has not run a pass); \
             there are no conflicts to resolve"
                .to_string(),
        );
    };
    if state.conflicts.iter().any(|c| c.path == path) {
        return Ok(());
    }
    let known: Vec<String> = state
        .conflicts
        .iter()
        .map(|c| format!("{} ({})", c.path, c.kind))
        .collect();
    if known.is_empty() {
        Err(format!(
            "path {path:?} is not a known conflict: the last reported sync has no conflicts"
        ))
    } else {
        Err(format!(
            "path {path:?} is not a known conflict; current conflicts: {}",
            known.join(", ")
        ))
    }
}

/// An ignore pattern must be a real string (mutagen glob syntax is the
/// daemon's problem; whitespace-only or empty is ours).
fn validate_ignore_pattern(pattern: &str) -> Result<(), String> {
    if pattern.trim().is_empty() {
        Err("ignore pattern must be a non-empty string (mutagen glob syntax, e.g. \"*.log\" or \"node_modules\")".to_string())
    } else {
        Ok(())
    }
}

/// Compact JSON status + a human summary line (single text content).
fn render_status(state: Option<&SyncState>, pending: &ControlRequests) -> String {
    let json = status_json(state, pending);
    format!("{}\n{}", status_summary_line(state, pending), json)
}

/// The status JSON: exact task shape, plus a `never_synced` marker when the
/// daemon has not reported a pass yet.
fn status_json(state: Option<&SyncState>, pending: &ControlRequests) -> String {
    let never_synced = state.is_none();
    let default = SyncState::default();
    let state = state.unwrap_or(&default);
    serde_json::json!({
        "last_sync_unix": state.last_sync_unix,
        "never_synced": never_synced,
        "paused": state.paused,
        "conflicts": state.conflicts.iter().map(|c| serde_json::json!({
            "path": c.path,
            "kind": c.kind,
            "description": c.description,
        })).collect::<Vec<_>>(),
        "applied": state.applied,
        "deleted": state.deleted,
        "failed": state.failed,
        "problems": state.problems.iter().map(|(p, m)| serde_json::json!([p, m])).collect::<Vec<_>>(),
        "pending": {
            "paused": pending.paused,
            "resolutions": pending.resolutions.iter().map(|r| serde_json::json!({
                "path": r.path,
                "choice": r.choice,
            })).collect::<Vec<_>>(),
            "ignore_add": pending.ignore_add,
            "sync_now": pending.sync_now,
        },
    })
    .to_string()
}

/// The human-readable status line (the LLM's quick read).
fn status_summary_line(state: Option<&SyncState>, pending: &ControlRequests) -> String {
    let mut line = match state {
        None => "never synced (the laptop daemon has not reported a pass yet)".to_string(),
        Some(state) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let age = now.saturating_sub(state.last_sync_unix);
            let mut l = format!(
                "last sync {age}s ago — applied {}, deleted {}, failed {}, {} conflict(s), {} problem(s)",
                state.applied,
                state.deleted,
                state.failed,
                state.conflicts.len(),
                state.problems.len()
            );
            if state.paused {
                l = format!("PAUSED — {l}");
            }
            l
        }
    };
    if !pending.is_empty() {
        line.push_str(&format!("; pending requests: {}", pending_summary(pending)));
    }
    line
}

// ---------------------------------------------------------------------------
// rmcp wrapper (thin: args in, ToolCtx call out, text/error result)
// ---------------------------------------------------------------------------

/// Arguments for `sync_resolve_conflict`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResolveConflictArgs {
    /// Root-relative path of the conflict to resolve (from sync_status).
    pub path: String,
    /// "keep-local" (laptop wins) or "keep-remote" (sandbox wins). The winning
    /// side's content propagates; the loser's divergent content is dropped.
    pub choice: String,
}

/// Arguments for `sync_ignore_add`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct IgnoreAddArgs {
    /// Ignore pattern in mutagen glob syntax (e.g. "*.log", "node_modules"),
    /// appended to the laptop's .syncignore on the next pass.
    pub pattern: String,
}

/// The rmcp server shell. Name/version come from CARGO_PKG_*.
#[derive(Clone)]
pub struct SyncMcpServer {
    ctx: ToolCtx,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl SyncMcpServer {
    pub fn new(root: PathBuf) -> Self {
        Self {
            ctx: ToolCtx::new(root),
            tool_router: Self::tool_router(),
        }
    }

    /// Inspect the current sync state: last sync time, paused, conflicts,
    /// counters, problems, and what control requests are pending.
    #[tool(
        description = "Report the current sync status of this sandbox: when the last \
        sync pass ran, whether syncing is paused, any conflicts awaiting a resolution \
        decision, the last run's counters, and the control requests already queued for \
        the laptop daemon. Returns a human summary line followed by compact JSON."
    )]
    async fn sync_status(&self) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_status())
    }

    /// Pause the sync until sync_resume.
    #[tool(
        description = "Pause the $HOME <-> sandbox sync. No files are synced until \
        sync_resume is called (the pause takes effect on the next sync pass)."
    )]
    async fn sync_pause(&self) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_pause())
    }

    /// Resume the sync after a pause.
    #[tool(
        description = "Resume the $HOME <-> sandbox sync after a pause (takes effect \
        on the next sync pass)."
    )]
    async fn sync_resume(&self) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_resume())
    }

    /// Resolve one conflict: how the next pass settles it.
    #[tool(
        description = "Resolve a sync conflict reported by sync_status. `path` must be \
        a root-relative path of a known conflict; `choice` is \"keep-local\" (the laptop's \
        version wins) or \"keep-remote\" (this sandbox's version wins). The winning side's \
        content propagates and the losing side's divergent content is dropped — an explicit \
        decision, honored on the next sync pass."
    )]
    async fn sync_resolve_conflict(
        &self,
        Parameters(args): Parameters<ResolveConflictArgs>,
    ) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_resolve_conflict(&args.path, &args.choice))
    }

    /// Ask for an immediate sync pass.
    #[tool(
        description = "Request a sync pass now (the laptop daemon runs it on its next \
        loop iteration). Use after making changes you want mirrored to the laptop without \
        waiting for the periodic pass."
    )]
    async fn sync_now(&self) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_now())
    }

    /// Add an ignore pattern to the laptop's .syncignore.
    #[tool(
        description = "Add an ignore pattern (mutagen glob syntax, e.g. \"*.log\" or \
        \"node_modules\") so it is never synced; appended to the laptop's .syncignore on \
        the next pass. Duplicates are deduplicated."
    )]
    async fn sync_ignore_add(
        &self,
        Parameters(args): Parameters<IgnoreAddArgs>,
    ) -> Result<CallToolResult, McpError> {
        tool_text(&self.ctx.sync_ignore_add(&args.pattern))
    }
}

/// Map the tool layer's `Result<String, String>` to an MCP result: Ok -> a
/// single text content item; Err -> a tool-level ERROR result whose message
/// the caller can actually read (per rmcp 3.9: Ok(CallToolResult::error) is
/// the right shape for caller-visible failures; Err(McpError) is protocol-
/// level only and renders opaquely on the client).
fn tool_text(res: &Result<String, String>) -> Result<CallToolResult, McpError> {
    match res {
        Ok(text) => Ok(CallToolResult::success(vec![ContentBlock::text(text)])),
        Err(msg) => Ok(CallToolResult::error(vec![ContentBlock::text(msg)])),
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SyncMcpServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                env!("CARGO_PKG_NAME"),
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Control plane for this sandbox's $HOME <-> laptop sync. Start with \
                 sync_status; resolve any listed conflicts with sync_resolve_conflict. \
                 These tools never move file data — only sync state and control requests.",
            )
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the MCP server over STDIO until the client disconnects. Blocks; logs to
/// stderr only (stdout is the transport).
pub fn run(root: &Path) -> Result<(), Box<dyn Error>> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    eprintln!(
        "sync-agent {}: MCP control-plane server on stdio, sync root {}",
        env!("CARGO_PKG_VERSION"),
        root.display()
    );
    rt.block_on(serve_stdio(root.to_path_buf()))
}

async fn serve_stdio(root: PathBuf) -> Result<(), Box<dyn Error>> {
    // Plain stdio() (blocking handles on the tokio blocking pool): stdio_pipes
    // would be faster but reopens /proc/self/fd, which a Landlock-bounded
    // sandbox policy may deny (and it panics when that fails) — not worth the
    // risk for a control-plane channel that sends one small message per call.
    let server = SyncMcpServer::new(root);
    let running = server.serve(rmcp::transport::stdio()).await?;
    let quit = running.waiting().await?;
    eprintln!("sync-agent: MCP server quit: {quit:?}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests: tool-layer logic is authoritative; one rmcp in-memory roundtrip
// proves the wrapper wiring (initialize -> tools/call over a duplex).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::model::CallToolRequestParams;
    use rmcp::{service::serve_client, ClientHandler};
    use serde_json::Value;

    fn ctx() -> (tempfile::TempDir, ToolCtx) {
        let td = tempfile::tempdir().unwrap();
        let root = td.path().to_path_buf();
        let ctx = ToolCtx::new(root.clone());
        (td, ctx)
    }

    /// The tool layer's Err, unwrapped for assertions.
    fn err_of(res: Result<String, String>) -> String {
        res.unwrap_err()
    }

    /// One text content item from a result (our tools always return exactly one).
    fn one_text(result: &CallToolResult) -> String {
        assert_eq!(result.content.len(), 1, "single text content item");
        match &result.content[0] {
            ContentBlock::Text(t) => t.text.clone(),
            other => panic!("expected a text content item, got {other:?}"),
        }
    }

    // ----- status shapes -----

    #[test]
    fn status_never_synced_shape() {
        let (_td, ctx) = ctx();
        let text = ctx.sync_status().unwrap();
        let json = json_part(&text);
        assert_eq!(json["never_synced"], Value::Bool(true));
        assert_eq!(json["last_sync_unix"], 0);
        assert_eq!(json["paused"], Value::Bool(false));
        assert_eq!(json["conflicts"], serde_json::json!([]));
        assert_eq!(json["pending"]["paused"], Value::Bool(false));
        assert!(
            text.starts_with("never synced"),
            "summary line first: {text}"
        );
    }

    #[test]
    fn status_with_conflicts_and_state() {
        let (_td, ctx) = ctx();
        control::write_sync_state(
            &ctx.root,
            &SyncState {
                last_sync_unix: 1_700_000_000,
                conflicts: vec![sync_proto::control::ConflictInfo {
                    path: "notes.md".into(),
                    kind: "dir-conflict".into(),
                    description: "both sides changed it".into(),
                }],
                applied: 12,
                deleted: 2,
                failed: 1,
                problems: vec![("x".into(), "unreadable".into())],
                daemon_version: "0.1.0".into(),
                paused: false,
            },
        )
        .unwrap();
        let text = ctx.sync_status().unwrap();
        let json = json_part(&text);
        assert_eq!(json["never_synced"], Value::Bool(false));
        assert_eq!(json["last_sync_unix"], 1_700_000_000u64);
        assert_eq!(json["conflicts"][0]["path"], "notes.md");
        assert_eq!(json["conflicts"][0]["kind"], "dir-conflict");
        assert_eq!(json["applied"], 12);
        assert_eq!(json["failed"], 1);
        assert_eq!(json["problems"], serde_json::json!([["x", "unreadable"]]));
        assert!(text.contains("1 conflict(s)"), "{text}");
    }

    #[test]
    fn status_reflects_pending_pause() {
        let (_td, ctx) = ctx();
        ctx.sync_pause().unwrap();
        let text = ctx.sync_status().unwrap();
        let json = json_part(&text);
        // The pause is a REQUEST until the daemon honors it: pending.paused
        // flips immediately; state.paused only after the next SyncReport.
        assert_eq!(json["pending"]["paused"], Value::Bool(true));
        assert_eq!(json["paused"], Value::Bool(false));
        assert!(text.contains("pending requests: paused"), "{text}");
    }

    #[test]
    fn status_reflects_reported_paused_state() {
        let (_td, ctx) = ctx();
        // The daemon honored a pause and reported it back.
        control::write_sync_state(
            &ctx.root,
            &SyncState {
                paused: true,
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let text = ctx.sync_status().unwrap();
        assert!(text.contains("PAUSED"), "{text}");
        let json = json_part(&text);
        assert_eq!(json["paused"], Value::Bool(true));
    }

    #[test]
    fn status_reads_state_written_by_the_daemon() {
        let (_td, ctx) = ctx();
        control::write_sync_state(
            &ctx.root,
            &SyncState {
                last_sync_unix: 123,
                applied: 7,
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let text = ctx.sync_status().unwrap();
        let json = json_part(&text);
        assert_eq!(json["last_sync_unix"], 123);
        assert_eq!(json["applied"], 7);
    }

    // ----- pause / resume / sync_now -----

    #[test]
    fn pause_then_resume_clears_the_pending_pause() {
        let (_td, ctx) = ctx();

        let text = ctx.sync_pause().unwrap();
        assert!(text.contains("paused"), "{text}");
        let pending = control::read_control_requests(&ctx.root).unwrap().unwrap();
        assert!(pending.paused);

        let text = ctx.sync_resume().unwrap();
        assert!(text.contains("resumed"), "{text}");
        let pending = control::read_control_requests(&ctx.root).unwrap().unwrap();
        assert!(!pending.paused, "resume clears the pause");
        assert!(pending.is_empty(), "nothing else pending: {pending:?}");
    }

    #[test]
    fn sync_now_sticks_across_other_requests() {
        let (_td, ctx) = ctx();

        assert!(ctx.sync_now().unwrap().contains("sync requested"));
        // A later unrelated request must not erase the sync-now nudge.
        ctx.sync_pause().unwrap();
        let pending = control::read_control_requests(&ctx.root).unwrap().unwrap();
        assert!(pending.sync_now, "sync_now sticks");
        assert!(pending.paused, "later pause merged on top");
    }

    // ----- resolve -----

    #[test]
    fn resolve_rejects_invalid_choice_and_unknown_path() {
        let (_td, ctx) = ctx();

        let msg = err_of(ctx.sync_resolve_conflict("d", "keep-mine"));
        assert!(
            msg.contains("keep-local") && msg.contains("keep-remote"),
            "error lists the valid choices: {msg}"
        );

        // Unknown path with a valid choice -> names the problem, writes nothing.
        // (State present, but the path is not among the reported conflicts.)
        control::write_sync_state(
            &ctx.root,
            &SyncState {
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let msg = err_of(ctx.sync_resolve_conflict("ghost", "keep-local"));
        assert!(msg.contains("not a known conflict"), "{msg}");
        assert!(
            control::read_control_requests(&ctx.root).unwrap().is_none(),
            "a rejected resolve must not write anything"
        );
    }

    #[test]
    fn resolve_without_state_reports_no_conflicts_yet() {
        let (_td, ctx) = ctx();
        let msg = err_of(ctx.sync_resolve_conflict("x", "keep-local"));
        assert!(msg.contains("no sync state reported yet"), "{msg}");
    }

    #[test]
    fn resolve_records_resolution_for_a_known_conflict() {
        let (_td, ctx) = ctx();

        control::write_sync_state(
            &ctx.root,
            &SyncState {
                conflicts: vec![
                    sync_proto::control::ConflictInfo {
                        path: "a.txt".into(),
                        kind: "dir-conflict".into(),
                        description: "x".into(),
                    },
                    sync_proto::control::ConflictInfo {
                        path: "b.txt".into(),
                        kind: "symlink-conflict".into(),
                        description: "y".into(),
                    },
                ],
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();

        let text = ctx.sync_resolve_conflict("a.txt", "keep-remote").unwrap();
        assert!(text.contains("a.txt -> keep-remote"), "{text}");
        assert!(text.contains("dropped"), "{text}");

        // The recorded resolution is exactly what the daemon's take() returns.
        let taken = control::take_control_requests(&ctx.root).unwrap().unwrap();
        assert_eq!(taken.resolutions.len(), 1);
        assert_eq!(taken.resolutions[0].path, "a.txt");
        assert_eq!(taken.resolutions[0].choice, "keep-remote");

        // A later resolution for the SAME path replaces the earlier one
        // (merge semantics) — re-record after the take.
        ctx.sync_resolve_conflict("a.txt", "keep-local").unwrap();
        ctx.sync_resolve_conflict("a.txt", "keep-remote").unwrap();
        let pending = control::read_control_requests(&ctx.root).unwrap().unwrap();
        assert_eq!(pending.resolutions.len(), 1, "same path collapses");
        assert_eq!(pending.resolutions[0].choice, "keep-remote");
    }

    #[test]
    fn resolve_unknown_path_lists_current_conflicts() {
        let (_td, ctx) = ctx();
        control::write_sync_state(
            &ctx.root,
            &SyncState {
                conflicts: vec![sync_proto::control::ConflictInfo {
                    path: "real.txt".into(),
                    kind: "dir-conflict".into(),
                    description: "x".into(),
                }],
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();
        let msg = err_of(ctx.sync_resolve_conflict("wrong.txt", "keep-local"));
        assert!(
            msg.contains("real.txt (dir-conflict)"),
            "error must list the live conflict set: {msg}"
        );
    }

    // ----- ignore_add -----

    #[test]
    fn ignore_add_validates_and_dedups_via_merge() {
        let (_td, ctx) = ctx();

        for bad in ["", "   ", "\t"] {
            let msg = err_of(ctx.sync_ignore_add(bad));
            assert!(
                msg.contains("non-empty"),
                "empty-ish pattern rejected: {msg}"
            );
        }

        ctx.sync_ignore_add("*.log").unwrap();
        ctx.sync_ignore_add("*.log").unwrap();
        ctx.sync_ignore_add("node_modules").unwrap();
        let pending = control::read_control_requests(&ctx.root).unwrap().unwrap();
        assert_eq!(
            pending.ignore_add,
            vec!["*.log".to_string(), "node_modules".to_string()],
            "merge dedups identical patterns"
        );
    }

    // ----- pure helpers -----

    #[test]
    fn summary_line_never_synced_and_pending() {
        let mut pending = ControlRequests::default();
        assert!(status_summary_line(None, &pending).starts_with("never synced"));
        pending.sync_now = true;
        let line = status_summary_line(None, &pending);
        assert!(line.contains("sync-now"), "{line}");
    }

    // ----- ONE in-memory client/server roundtrip through rmcp -----
    // Proves the WRAPPER wiring end to end (initialize -> tools/list -> the
    // Parameters<T> argument extraction -> isError results) over a duplex; the
    // ToolCtx tests above remain the authoritative logic coverage.

    /// Minimal client handler for the duplex roundtrip.
    #[derive(Debug, Clone, Default)]
    struct NoopClient;

    impl ClientHandler for NoopClient {
        fn get_info(&self) -> rmcp::model::ClientConfig {
            rmcp::model::ClientConfig::default()
        }
    }

    #[tokio::test]
    async fn mcp_roundtrip_pause_resolve_and_status_over_the_wire() {
        let (td, _ctx) = ctx();
        let root = td.path().to_path_buf();
        assert!(control::read_control_requests(&root).unwrap().is_none());
        // The daemon has reported one conflict, so resolve has a target.
        control::write_sync_state(
            &root,
            &SyncState {
                conflicts: vec![sync_proto::control::ConflictInfo {
                    path: "notes.md".into(),
                    kind: "dir-conflict".into(),
                    description: "both sides changed it".into(),
                }],
                daemon_version: "0.1.0".into(),
                ..Default::default()
            },
        )
        .unwrap();

        let (server_transport, client_transport) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let server = SyncMcpServer::new(root);
            let running = server.serve(server_transport).await?;
            running.waiting().await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });

        // serve_client auto-initializes (ClientLifecycleMode::Initialize).
        let client = serve_client(NoopClient, client_transport).await.unwrap();

        // tools/list sees exactly the six control-plane tools.
        let tools = client.peer().list_all_tools().await.unwrap();
        let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                "sync_ignore_add",
                "sync_now",
                "sync_pause",
                "sync_resolve_conflict",
                "sync_resume",
                "sync_status",
            ]
        );

        // sync_pause over the wire -> the control file changed on disk.
        let result = client
            .peer()
            .call_tool(CallToolRequestParams::new("sync_pause"))
            .await
            .unwrap();
        assert!(!result.is_error.unwrap_or(false), "sync_pause succeeded");
        let pending = control::read_control_requests(td.path()).unwrap().unwrap();
        assert!(pending.paused, "the MCP roundtrip wrote the pause");

        // sync_resolve_conflict WITH arguments — exercises the Parameters<T>
        // JSON extraction path end to end.
        let result = client
            .peer()
            .call_tool(
                CallToolRequestParams::new("sync_resolve_conflict").with_arguments(
                    serde_json::json!({"path": "notes.md", "choice": "keep-remote"})
                        .as_object()
                        .expect("object")
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert!(
            !result.is_error.unwrap_or(false),
            "resolve over the wire succeeded: {result:?}"
        );
        let pending = control::read_control_requests(td.path()).unwrap().unwrap();
        assert_eq!(pending.resolutions[0].choice, "keep-remote");

        // sync_status over the wire reports both (single text content item).
        let result = client
            .peer()
            .call_tool(CallToolRequestParams::new("sync_status"))
            .await
            .unwrap();
        let text = one_text(&result);
        assert!(text.contains("pending requests: paused"), "{text}");
        assert!(text.contains("notes.md"), "{text}");

        // An invalid argument surfaces as a caller-readable isError result.
        let result = client
            .peer()
            .call_tool(
                CallToolRequestParams::new("sync_resolve_conflict").with_arguments(
                    serde_json::json!({"path": "notes.md", "choice": "nope"})
                        .as_object()
                        .expect("object")
                        .clone(),
                ),
            )
            .await
            .unwrap();
        assert!(
            result.is_error.unwrap_or(false),
            "invalid choice is an error result"
        );
        assert!(one_text(&result).contains("keep-local"));

        drop(client);
        let _ = server_task.await;
    }

    /// The JSON blob is the LAST line of the status text (summary first).
    fn json_part(text: &str) -> Value {
        let last = text.lines().last().expect("status has a JSON line");
        serde_json::from_str(last).expect("status JSON parses")
    }
}
