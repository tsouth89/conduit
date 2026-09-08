//! Server-side tool orchestration ("code mode"): run ONE agent-submitted script that
//! calls multiple downstream tools, loops, and branches, and returns a single aggregated
//! value. This is the results-layer twin of lazy discovery: lazy discovery collapses N
//! tool *definitions* to a handful of meta-tools; code mode collapses N tool *calls +
//! results* to one `run_script` round-trip, so the intermediate results never land in the
//! model's context.
//!
//! The engine is [`boa_engine`], a pure-Rust JS interpreter, so this adds no C toolchain
//! or FFI to the build. Because Toolport is single-user and local, the agent is already
//! trusted and the servers already run on the host: the sandbox's job is round-trip and
//! token reduction, NOT a security boundary. It still fails closed on resource limits so a
//! runaway or buggy script can't wedge the gateway.
//!
//! Scripts get:
//! - `toolport.call(name, args)` — synchronous host call (v1)
//! - `toolport.callAsync(name, args)` — returns a Promise; independent calls fan out with
//!   bounded host-side parallelism (v2)
//! - `toolport.callAll([{name, args}, ...])` — `Promise.all` sugar over `callAsync`
//! - `servers.<server>.<tool>(args)` — typed stubs from the scoped catalog (sync); use
//!   `.async(args)` for the Promise form. CamelCase aliases are added when they differ
//!   from the sanitized tool segment (e.g. `create_refund` and `createRefund`).
//! - `toolport.listTools()` / `toolport.listServers()` — catalog introspection
//! - `toolport.fetchResult({cursor, offset?, len?, projection?})` — page a previously
//!   shaped result (cursor handoff / structured projection) without leaving the script
//!
//! Downstream calls from a script still pass scope, HITL, and content-defense gates, but
//! intermediate results are **not** byte-budget shaped: full bodies stay in the sandbox
//! (they never enter model context). The gateway shapes only the script's final aggregate
//! for the client. The gateway runs this interpreter in [`crate::codemode_worker`],
//! which adds a memory budget, bounded IPC, and an independent wall-clock supervisor
//! to the call, concurrency, promise-job, loop, and recursion limits below.
//!
//! # Interpreter counters and worker containment
//!
//! Inside this interpreter, [`Limits::wall_clock`] is checked
//! when a script reserves a host call ([`reserve_budget`]) and between promise jobs
//! ([`BoundedJobExecutor`]), and boa 0.21 exposes no time-based interrupt to check it
//! anywhere else. The gateway's parent process enforces the deadline even during
//! synchronous JS and result serialization. Direct in-process callers of this module
//! have only Boa's own counters on that path:
//!
//!   * `loop_iteration_limit` — total loop iterations, across nested loops, not per-loop.
//!   * recursion limit — depth, which trips almost immediately.
//!
//! These count iterations and depth, not allocation or elapsed time. Production
//! execution, dry runs, and saved routines all require the worker boundary to contain
//! allocation failures and terminate expensive built-ins.
//!
//! `pure_js_runaways_are_bounded_by_count_not_wall_clock` pins this so a boa upgrade that
//! drops either counter is caught, independently of the process-isolation tests.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use boa_engine::builtins::promise::{PromiseState, ResolvingFunctions};
use boa_engine::job::{GenericJob, Job, JobExecutor, PromiseJob};
use boa_engine::object::builtins::JsPromise;
use boa_engine::property::Attribute;
use boa_engine::{js_string, Context, JsError, JsNativeError, JsValue, NativeFunction, Source};
use boa_gc::{Finalize, Trace};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Host binding used for every downstream tool invocation from a script.
///
/// `Send + Sync` so independent `callAsync` work can run on a small thread pool without
/// serializing every host call on the JS thread.
pub type CallBinding = Arc<dyn Fn(&str, Value) -> Value + Send + Sync>;

/// Internal worker binding carries the ledger position across concurrent IPC.
pub(crate) type IndexedCallBinding = Arc<dyn Fn(usize, &str, Value) -> Value + Send + Sync>;

pub(crate) type CheckpointBinding = Arc<dyn Fn(&Value) -> Result<(), String> + Send + Sync>;

/// Arguments for [`FetchBinding`] / `toolport.fetchResult`.
#[derive(Debug, Clone)]
pub struct FetchArgs {
    pub cursor: String,
    pub offset: usize,
    pub len: usize,
    pub projection: Option<String>,
}

/// Host binding for paging a shaped result by cursor (same cache as `toolport_fetch_result`).
pub type FetchBinding = Arc<dyn Fn(FetchArgs) -> Value + Send + Sync>;

/// The JSON payload exposed to a script. Ordinary Code Mode keeps its historical mutable
/// `data` global. Persisted routines get a distinct, deeply frozen `input` global so a saved
/// definition cannot mutate the arguments it was invoked with or observe a writable alias.
#[derive(Debug, Clone)]
pub enum ScriptInput {
    Data(Value),
    ImmutableInput(Value),
}

/// Resource limits for one script run. All are fail-closed: exceeding any of them aborts
/// the script with an error result the agent can read and recover from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Limits {
    /// Max number of `toolport.call` / `callAsync` / `fetchResult` invocations.
    /// Bounds fan-out, load, and unbounded result paging (WS2-2).
    pub max_calls: usize,
    /// Wall-clock budget for the whole run, enforced by the parent worker supervisor
    /// and checked by the interpreter at host calls and between promise jobs.
    pub wall_clock: Duration,
    /// Max concurrent host tool calls when scripts fan out with `callAsync` / `Promise.all`.
    pub max_parallel: usize,
    /// Max promise/microtask jobs drained during one script (bounds a self-requeuing
    /// `Promise.resolve().then(loop)` chain that would otherwise pin `run_jobs` forever).
    pub max_promise_jobs: usize,
    /// Max total loop iterations across the script (boa runtime limit); bounds a pure-JS
    /// `while(true){}` that never calls a tool.
    pub loop_iteration_limit: u64,
    /// Max recursion depth (boa runtime limit).
    pub recursion_limit: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_calls: 64,
            wall_clock: Duration::from_secs(60),
            max_parallel: 8,
            max_promise_jobs: 100_000,
            loop_iteration_limit: 10_000_000,
            recursion_limit: 400,
        }
    }
}

/// Job executor that drains promise/generic jobs with wall-clock + job-count caps.
///
/// Default boa `SimpleJobExecutor` runs until the queue is empty, so a malicious or buggy
/// script that keeps enqueueing microtasks can pin the gateway thread past the script
/// wall-clock (CodeRabbit #480). This executor checks the deadline between jobs.
struct BoundedJobExecutor {
    promise_jobs: RefCell<VecDeque<PromiseJob>>,
    generic_jobs: RefCell<VecDeque<GenericJob>>,
    /// Async/timeout jobs are rare in code-mode scripts; we refuse them fail-closed rather
    /// than reimplement boa's full async drain (keeps this executor small and deadline-safe).
    rejected_unsupported: Cell<bool>,
    deadline: Instant,
    max_jobs: usize,
    jobs_run: Cell<usize>,
}

impl BoundedJobExecutor {
    fn new(deadline: Instant, max_jobs: usize) -> Self {
        Self {
            promise_jobs: RefCell::new(VecDeque::new()),
            generic_jobs: RefCell::new(VecDeque::new()),
            rejected_unsupported: Cell::new(false),
            deadline,
            max_jobs: max_jobs.max(1),
            jobs_run: Cell::new(0),
        }
    }

    fn clear(&self) {
        self.promise_jobs.borrow_mut().clear();
        self.generic_jobs.borrow_mut().clear();
    }

    fn check_budget(&self) -> Result<(), JsError> {
        if Instant::now() >= self.deadline {
            self.clear();
            return Err(JsError::from_native(JsNativeError::error().with_message(
                "toolport script wall-clock deadline exceeded during promise jobs",
            )));
        }
        if self.jobs_run.get() >= self.max_jobs {
            self.clear();
            return Err(JsError::from_native(JsNativeError::error().with_message(
                format!(
                    "toolport script promise-job budget exceeded ({} jobs)",
                    self.max_jobs
                ),
            )));
        }
        Ok(())
    }
}

impl JobExecutor for BoundedJobExecutor {
    fn enqueue_job(self: Rc<Self>, job: Job, _context: &mut Context) {
        match job {
            Job::PromiseJob(p) => self.promise_jobs.borrow_mut().push_back(p),
            Job::GenericJob(g) => self.generic_jobs.borrow_mut().push_back(g),
            // Async/timer (and any future Job variants): code mode does not host timers;
            // refuse rather than hang the drain loop.
            Job::AsyncJob(_) | Job::TimeoutJob(_) | _ => {
                self.rejected_unsupported.set(true);
            }
        }
    }

    fn run_jobs(self: Rc<Self>, context: &mut Context) -> Result<(), JsError> {
        if self.rejected_unsupported.get() {
            self.clear();
            return Err(JsError::from_native(JsNativeError::error().with_message(
                "toolport script used unsupported async/timer jobs inside code mode",
            )));
        }

        loop {
            self.check_budget()?;

            let promise = self.promise_jobs.borrow_mut().pop_front();
            if let Some(job) = promise {
                self.jobs_run.set(self.jobs_run.get() + 1);
                if let Err(err) = job.call(context) {
                    // Match SimpleJobExecutor: drop remaining jobs on first failure.
                    self.clear();
                    return Err(err);
                }
                context.clear_kept_objects();
                continue;
            }

            let generic = self.generic_jobs.borrow_mut().pop_front();
            if let Some(job) = generic {
                self.jobs_run.set(self.jobs_run.get() + 1);
                if let Err(err) = job.call(context) {
                    self.clear();
                    return Err(err);
                }
                context.clear_kept_objects();
                continue;
            }

            break;
        }

        if self.rejected_unsupported.get() {
            self.clear();
            return Err(JsError::from_native(JsNativeError::error().with_message(
                "toolport script used unsupported async/timer jobs inside code mode",
            )));
        }

        Ok(())
    }
}

/// One downstream tool call that actually reached the host binding.
///
/// Deliberately carries no arguments. A ledger is model-facing, and call
/// arguments routinely hold credentials and personal data; #646 scopes payloads
/// out for exactly that reason. The cost is that the ledger is ORDINAL — it says
/// which positions in the call sequence completed, not which argument values
/// did. See [`ScriptOutcome::progress`] for what that means for the caller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallRecord {
    /// Position in the call sequence, from zero. Explicit rather than implied by
    /// array order so the ordinal contract survives serialization and is legible
    /// to the agent reading the payload.
    pub index: usize,
    /// Exposed tool name (`server__tool`) as the script asked for it.
    pub name: String,
    /// False when the downstream result carried `isError: true`. A recorded call
    /// ran either way — `ok` says how it ended, not whether it happened.
    pub ok: bool,
    /// Serialized result size only. The ledger never retains a downstream result body.
    pub result_bytes: usize,
}

/// The outcome of running a script.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptOutcome {
    /// The script's return value as JSON (`null` if it returned nothing). Meaningful only
    /// when `error` is `None`.
    pub value: Value,
    /// How many host tool invocations the script actually made — used to account
    /// round-trips saved (calls - 1) and to report fan-out.
    pub calls: usize,
    /// Every downstream call that reached the host binding, in execution order
    /// (batch order within a parallel `callAsync` flush).
    ///
    /// Distinct from `calls` in two ways, both deliberate. `calls` counts a call
    /// when it is ISSUED, so queued `callAsync` work that never ran — a flush
    /// that hits the wall-clock deadline abandons its batch — is still counted;
    /// this list only holds calls whose side effects have actually committed.
    /// And `fetchResult` counts against `calls` but is absent here, because
    /// paging a cached result commits nothing downstream.
    ///
    /// The point is recovery: a script that dies on call 40 of 64 can tell the
    /// agent what it already did, instead of forcing a re-run that repeats every
    /// one of those side effects (#646).
    ///
    /// This is an ORDINAL record, and the distinction matters. A script that
    /// calls the same tool with different arguments — `create_row({id:1})` then
    /// `create_row({id:2})` — produces two entries with the same `name`, so
    /// deduplicating by name would skip a call that never ran. Resume by
    /// position: entries `0..n` completed, everything from `n` on did not. For a
    /// script whose call sequence depends on data returned mid-run, even that
    /// holds only if the re-run takes the same branches.
    pub progress: Vec<CallRecord>,
    /// Serialized size of the final aggregate. The outcome already owns `value`; callers
    /// can use this aggregate without retaining another copy of the result.
    pub final_result_bytes: usize,
    /// Last value the script passed to `toolport.checkpoint()`, if any. Author-chosen,
    /// so unlike `progress` this can safely carry script-relevant state — the script
    /// decides what's safe to surface. `None` if the script never called it. See #663.
    pub checkpoint: Option<Value>,
    /// `Some(message)` if the script threw, hit a limit, or failed to compile. Fail-closed:
    /// the caller surfaces this to the agent as an error result.
    pub error: Option<String>,
}

/// True unless the downstream result carried `isError: true`.
fn result_ok(result: &Value) -> bool {
    !result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// One deferred `callAsync` waiting for host execution + promise settlement.
struct PendingCall {
    name: String,
    args: Value,
    resolvers: ResolvingFunctions,
}

impl Finalize for PendingCall {
    fn finalize(&self) {
        self.resolvers.finalize();
    }
}

// SAFETY: only `resolvers` points into the boa heap; name/args are ordinary Rust data.
unsafe impl Trace for PendingCall {
    unsafe fn trace(&self, tracer: &mut boa_gc::Tracer) {
        // SAFETY: resolvers is a live GC graph while the pending call exists.
        unsafe { self.resolvers.trace(tracer) };
    }
    unsafe fn trace_non_roots(&self) {
        // SAFETY: same as `trace`.
        unsafe { self.resolvers.trace_non_roots() };
    }
    fn run_finalizer(&self) {
        self.finalize();
    }
}

/// Host state shared with the `__toolport_call` / `__toolport_call_async` native functions.
struct HostState {
    call: IndexedCallBinding,
    /// Shared with the run so the count survives after the closure is moved into boa.
    calls_made: Rc<Cell<usize>>,
    /// Ledger of calls that actually executed, shared with the run the same way
    /// `calls_made` is. Appended after the host binding returns, never before, so
    /// it records committed work rather than intent (#646).
    executed: Rc<RefCell<Vec<CallRecord>>>,
    /// Last checkpoint value the script recorded via `toolport.checkpoint(value)`.
    /// Last-write-wins — a fresh call overwrites, it doesn't append (#663).
    checkpoint: Rc<RefCell<Option<Value>>>,
    checkpoint_binding: Option<CheckpointBinding>,
    /// Maximum serialized checkpoint size for this run. This is capped against
    /// the active result budget so an accepted checkpoint can always be surfaced
    /// immediately when the script fails.
    max_checkpoint_bytes: usize,
    max_calls: usize,
    max_parallel: usize,
    deadline: Instant,
    /// Queued `callAsync` work; drained with bounded host-side parallelism.
    pending: Rc<RefCell<VecDeque<PendingCall>>>,
}

/// A checkpoint is a resume marker, not a payload. Keep it bounded so even a
/// failure response can surface it without becoming an unbounded escape hatch.
pub(crate) const MAX_CHECKPOINT_BYTES: usize = 4096;

/// Space reserved for the failure prefix, shaping marker, and MCP result
/// envelope. The remainder of the active result budget is available to the
/// checkpoint itself.
const CHECKPOINT_RESPONSE_RESERVE_BYTES: usize = 1024;

fn checkpoint_limit_for_result_budget(result_budget: usize) -> usize {
    if result_budget == 0 {
        MAX_CHECKPOINT_BYTES
    } else {
        MAX_CHECKPOINT_BYTES.min(result_budget.saturating_sub(CHECKPOINT_RESPONSE_RESERVE_BYTES))
    }
}

fn store_checkpoint(
    checkpoint: &RefCell<Option<Value>>,
    raw: &str,
    max_bytes: usize,
) -> Result<(), JsError> {
    if raw.len() > max_bytes {
        return Err(JsError::from_native(JsNativeError::error().with_message(
            format!(
                "toolport.checkpoint value exceeds {max_bytes} bytes for the active result budget"
            ),
        )));
    }
    let parsed: Value = serde_json::from_str(raw).map_err(|error| {
        JsError::from_native(JsNativeError::error().with_message(format!(
            "toolport.checkpoint received invalid JSON: {error}"
        )))
    })?;
    *checkpoint.borrow_mut() = Some(parsed);
    Ok(())
}

/// Capture for `__toolport_fetch_result` (no GC refs). Shares the same call
/// budget and wall-clock deadline as `toolport.call` (WS2-2).
struct FetchHost {
    fetch: Option<FetchBinding>,
    calls_made: Rc<Cell<usize>>,
    max_calls: usize,
    deadline: Instant,
}

impl Finalize for FetchHost {}
// SAFETY: only Arc/Option of host closures and Rc counters — no boa heap pointers.
unsafe impl Trace for FetchHost {
    unsafe fn trace(&self, _tracer: &mut boa_gc::Tracer) {}
    unsafe fn trace_non_roots(&self) {}
    fn run_finalizer(&self) {}
}

impl Clone for HostState {
    fn clone(&self) -> Self {
        Self {
            call: Arc::clone(&self.call),
            calls_made: Rc::clone(&self.calls_made),
            executed: Rc::clone(&self.executed),
            checkpoint: Rc::clone(&self.checkpoint),
            checkpoint_binding: self.checkpoint_binding.clone(),
            max_checkpoint_bytes: self.max_checkpoint_bytes,
            max_calls: self.max_calls,
            max_parallel: self.max_parallel,
            deadline: self.deadline,
            pending: Rc::clone(&self.pending),
        }
    }
}

impl Finalize for HostState {
    fn finalize(&self) {
        if let Ok(pending) = self.pending.try_borrow() {
            for item in pending.iter() {
                item.finalize();
            }
        }
    }
}

// SAFETY: only the `ResolvingFunctions` inside `pending` point into the boa heap. The
// `call` Arc, counters, the `executed` ledger (plain Rust strings/bools), and the
// deadline are ordinary Rust-owned data, so tracing skips them. While a native call
// holds `pending` mutably, GC is not expected to re-enter; `try_borrow` fails closed by
// skipping the queue for that mark pass (queue entries stay reachable via the promise
// resolvers already rooted as live JS objects).
unsafe impl Trace for HostState {
    unsafe fn trace(&self, tracer: &mut boa_gc::Tracer) {
        if let Ok(pending) = self.pending.try_borrow() {
            for item in pending.iter() {
                // SAFETY: each PendingCall only traces its resolvers.
                unsafe { item.trace(tracer) };
            }
        }
    }
    unsafe fn trace_non_roots(&self) {
        if let Ok(pending) = self.pending.try_borrow() {
            for item in pending.iter() {
                // SAFETY: same as `trace`.
                unsafe { item.trace_non_roots() };
            }
        }
    }
    fn run_finalizer(&self) {
        self.finalize();
    }
}

/// The JS prelude installed before the user script.
const PRELUDE: &str = r#"
globalThis.toolport = {
    call: function (name, args) {
        var payload = (args === undefined || args === null) ? {} : args;
        return JSON.parse(__toolport_call(String(name), JSON.stringify(payload)));
    },
    checkpoint: function (value) {
        __toolport_checkpoint(JSON.stringify(value === undefined ? null : value));
    },
    callAsync: function (name, args) {
        var payload = (args === undefined || args === null) ? {} : args;
        return __toolport_call_async(String(name), JSON.stringify(payload)).then(function (raw) {
            return JSON.parse(raw);
        });
    },
    callAll: function (items) {
        if (!Array.isArray(items)) {
            return Promise.reject(new TypeError("toolport.callAll expects an array of {name, args}"));
        }
        return Promise.all(items.map(function (item) {
            var name = item && item.name;
            var args = item && item.args;
            return toolport.callAsync(name, args);
        }));
    },
    // Page a shaped result by cursor (same stash as toolport_fetch_result). Prefer
    // projecting / filtering full intermediate tool results in-script instead; this
    // is for cursors handed in via `data` or left from a prior shaped agent turn.
    fetchResult: function (opts) {
        opts = (opts === undefined || opts === null) ? {} : opts;
        return JSON.parse(__toolport_fetch_result(JSON.stringify({
            cursor: opts.cursor,
            offset: opts.offset,
            len: opts.len,
            projection: opts.projection
        })));
    },
    listTools: function () { return []; },
    listServers: function () { return []; },
};
"#;

/// Build the `globalThis.servers` injection from exposed catalog tool names
/// (`server__tool`). Safe to eval after [`PRELUDE`]: stubs call through `toolport.call` /
/// `callAsync`, so gates stay intact. Empty catalog yields an empty `servers` object.
///
/// Property names use the sanitized tool segment; when a camelCase form differs and does
/// not collide with another tool on the same server, both names are registered.
pub fn build_servers_prelude(catalog: &[String]) -> String {
    // server -> (tool_prop -> full exposed name), BTree for stable output in tests.
    let mut by_server: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for exposed in catalog {
        let Some((server, tool)) = split_exposed_name(exposed) else {
            continue;
        };
        if server.is_empty() || tool.is_empty() {
            continue;
        }
        by_server
            .entry(server.to_string())
            .or_default()
            .entry(tool.to_string())
            .or_insert_with(|| exposed.clone());
    }

    let mut out = String::with_capacity(256 + catalog.len() * 80);
    out.push_str("(function () {\n");
    out.push_str("  var servers = Object.create(null);\n");
    out.push_str("  function stub(fullName) {\n");
    out.push_str("    var f = function (args) {\n");
    out.push_str(
        "      return toolport.call(fullName, args === undefined || args === null ? {} : args);\n",
    );
    out.push_str("    };\n");
    out.push_str("    f.async = function (args) {\n");
    out.push_str("      return toolport.callAsync(fullName, args === undefined || args === null ? {} : args);\n");
    out.push_str("    };\n");
    out.push_str("    f.toolName = fullName;\n");
    out.push_str("    return f;\n");
    out.push_str("  }\n");
    out.push_str("  function ensure(server) {\n");
    out.push_str("    if (!servers[server]) servers[server] = Object.create(null);\n");
    out.push_str("    return servers[server];\n");
    out.push_str("  }\n");

    let mut all_tools: Vec<String> = Vec::new();
    for (server, tools) in &by_server {
        let server_lit = js_string_literal(server);
        out.push_str("  {\n");
        out.push_str("    var s = ensure(");
        out.push_str(&server_lit);
        out.push_str(");\n");

        // Track props claimed on this server so camelCase aliases don't clobber peers.
        let claimed: BTreeSet<&str> = tools.keys().map(String::as_str).collect();
        for (tool, exposed) in tools {
            let exposed_lit = js_string_literal(exposed);
            let tool_lit = js_string_literal(tool);
            out.push_str("    s[");
            out.push_str(&tool_lit);
            out.push_str("] = stub(");
            out.push_str(&exposed_lit);
            out.push_str(");\n");
            all_tools.push(exposed.clone());

            let camel = snake_to_camel(tool);
            if camel != *tool && is_js_ident_start(&camel) && !claimed.contains(camel.as_str()) {
                let camel_lit = js_string_literal(&camel);
                out.push_str("    if (s[");
                out.push_str(&camel_lit);
                out.push_str("] === undefined) s[");
                out.push_str(&camel_lit);
                out.push_str("] = s[");
                out.push_str(&tool_lit);
                out.push_str("];\n");
            }
        }
        out.push_str("  }\n");
    }

    out.push_str("  globalThis.servers = servers;\n");
    out.push_str("  var __toolport_catalog = [");
    for (i, name) in all_tools.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&js_string_literal(name));
    }
    out.push_str("];\n");
    out.push_str("  toolport.listTools = function () { return __toolport_catalog.slice(); };\n");
    out.push_str("  toolport.listServers = function () { return Object.keys(servers); };\n");
    out.push_str("})();\n");
    out
}

/// Split an exposed `server__tool` name on the first `__` (matches how the router
/// allocates names). Returns `None` when the separator is missing.
pub fn split_exposed_name(exposed: &str) -> Option<(&str, &str)> {
    exposed.split_once("__")
}

/// True when `name` is a gateway meta-tool that should not appear on `servers.*`.
pub fn is_code_mode_meta_tool(name: &str) -> bool {
    name.starts_with("toolport_") || name.starts_with("help_")
}

fn js_string_literal(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c => out.push(c),
        }
    }
    out.push('\'');
    out
}

fn snake_to_camel(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut up = false;
    for c in s.chars() {
        if c == '_' {
            up = true;
            continue;
        }
        if up {
            for u in c.to_uppercase() {
                out.push(u);
            }
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

fn is_js_ident_start(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}

/// Run `script` with `data` available as a global `data` object, giving it `toolport.call`
/// / `callAsync` / `callAll` / `fetchResult` bound to host closures, plus `servers.*`
/// stubs from `catalog`. Returns one aggregated [`ScriptOutcome`]; intermediate call
/// results never surface to the model.
///
/// Scripts are wrapped in an async IIFE so top-level `await` and returned Promises work.
/// Independent `callAsync` work is flushed with up to [`Limits::max_parallel`] host calls
/// in flight at once.
///
/// `fetch` wires `toolport.fetchResult` (cursor paging / projection). Pass `None` to
/// leave fetchResult as a fail-closed stub (tests that only exercise tool calls).
///
/// `catalog` is the list of exposed tool names (`server__tool`) the script may stub;
/// pass the client-scoped cache (meta tools filtered). Empty is fine: string-form
/// `toolport.call` still works.
///
/// `call` must be `'static` (the gateway builds it from `Arc`-cloned handles). It is
/// invoked once per host tool call; whatever it returns becomes that call's JS result.
pub fn run_script(
    script: &str,
    data: Value,
    call: CallBinding,
    fetch: Option<FetchBinding>,
    limits: Limits,
    catalog: &[String],
) -> ScriptOutcome {
    run_script_with_input(
        script,
        ScriptInput::Data(data),
        call,
        fetch,
        limits,
        catalog,
    )
}

/// Run a script with an explicitly selected input surface. This is separate from
/// [`run_script`] so existing callers keep the writable `data` contract unchanged.
pub fn run_script_with_input(
    script: &str,
    input: ScriptInput,
    call: CallBinding,
    fetch: Option<FetchBinding>,
    limits: Limits,
    catalog: &[String],
) -> ScriptOutcome {
    run_script_indexed(
        script,
        input,
        Arc::new(move |_, name, args| call(name, args)),
        fetch,
        limits,
        catalog,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn run_script_indexed(
    script: &str,
    input: ScriptInput,
    call: IndexedCallBinding,
    fetch: Option<FetchBinding>,
    limits: Limits,
    catalog: &[String],
    checkpoint_binding: Option<CheckpointBinding>,
) -> ScriptOutcome {
    let calls_made = Rc::new(Cell::new(0usize));
    let executed = Rc::new(RefCell::new(Vec::new()));
    let checkpoint = Rc::new(RefCell::new(None::<Value>));
    let (result_budget, _warning) = crate::shaping::budget();
    let max_checkpoint_bytes = checkpoint_limit_for_result_budget(result_budget);
    let pending = Rc::new(RefCell::new(VecDeque::new()));
    let deadline = Instant::now() + limits.wall_clock;
    let executor = Rc::new(BoundedJobExecutor::new(deadline, limits.max_promise_jobs));
    let mut context = match Context::builder().job_executor(executor).build() {
        Ok(ctx) => ctx,
        Err(e) => {
            return ScriptOutcome {
                value: json!(null),
                calls: 0,
                progress: Vec::new(),
                final_result_bytes: 0,
                checkpoint: None,
                error: Some(format!(
                    "toolport code mode: failed to create JS context: {e}"
                )),
            };
        }
    };

    // Pure-JS runaway guards (a script that loops/recurses forever without calling a tool).
    context
        .runtime_limits_mut()
        .set_loop_iteration_limit(limits.loop_iteration_limit);
    context
        .runtime_limits_mut()
        .set_recursion_limit(limits.recursion_limit);

    let state = HostState {
        call,
        calls_made: calls_made.clone(),
        executed: executed.clone(),
        checkpoint: checkpoint.clone(),
        checkpoint_binding,
        max_checkpoint_bytes,
        max_calls: limits.max_calls,
        max_parallel: limits.max_parallel.max(1),
        deadline,
        pending,
    };

    let sync_native = NativeFunction::from_copy_closure_with_captures(
        |_this: &JsValue, args: &[JsValue], state: &HostState, _ctx: &mut Context| {
            reserve_call_slot(state)?;
            let (name, parsed) = parse_call_args(args);
            state.calls_made.set(state.calls_made.get() + 1);
            let index = state.executed.borrow().len();
            let result = (state.call)(index, &name, parsed);
            // After the binding returns: the side effect has committed, so the
            // ledger reflects work actually done (#646).
            {
                let mut executed = state.executed.borrow_mut();
                let index = executed.len();
                executed.push(CallRecord {
                    index,
                    name,
                    ok: result_ok(&result),
                    result_bytes: serialized_len(&result),
                });
            }
            let result_str = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string());
            Ok(JsValue::from(js_string!(result_str)))
        },
        state.clone(),
    );

    let async_native = NativeFunction::from_copy_closure_with_captures(
        |_this: &JsValue, args: &[JsValue], state: &HostState, ctx: &mut Context| {
            reserve_call_slot(state)?;
            let (name, parsed) = parse_call_args(args);
            state.calls_made.set(state.calls_made.get() + 1);
            let (promise, resolvers) = JsPromise::new_pending(ctx);
            state.pending.borrow_mut().push_back(PendingCall {
                name,
                args: parsed,
                resolvers,
            });
            Ok(promise.into())
        },
        state.clone(),
    );

    let checkpoint_native = NativeFunction::from_copy_closure_with_captures(
        |_this: &JsValue, args: &[JsValue], state: &HostState, _ctx: &mut Context| {
            // No reserve_call_slot: this makes no downstream call, so it costs
            // nothing against max_calls or the wall clock (#663).
            let raw = args
                .first()
                .and_then(JsValue::as_string)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "null".to_string());
            store_checkpoint(&state.checkpoint, &raw, state.max_checkpoint_bytes)?;
            if let Some(binding) = &state.checkpoint_binding {
                if let Some(value) = state.checkpoint.borrow().as_ref() {
                    binding(value).map_err(|error| JsNativeError::error().with_message(error))?;
                }
            }
            Ok(JsValue::undefined())
        },
        state.clone(),
    );

    if let Err(e) = context.register_global_callable(js_string!("__toolport_call"), 2, sync_native)
    {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }
    if let Err(e) =
        context.register_global_callable(js_string!("__toolport_call_async"), 2, async_native)
    {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }
    if let Err(e) =
        context.register_global_callable(js_string!("__toolport_checkpoint"), 1, checkpoint_native)
    {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }

    // Fetch binding: pages shaped results by cursor. Absent binding fails closed.
    // Count against the same call budget / wall-clock as toolport.call (WS2-2).
    let fetch_host = FetchHost {
        fetch,
        calls_made: calls_made.clone(),
        max_calls: limits.max_calls,
        deadline,
    };
    let fetch_native = NativeFunction::from_copy_closure_with_captures(
        |_this: &JsValue, args: &[JsValue], host: &FetchHost, _ctx: &mut Context| {
            // Availability first: an exhausted budget must not mask the real reason
            // a script cannot page results here.
            let Some(fetch) = host.fetch.as_ref() else {
                return Err(JsError::from_native(JsNativeError::error().with_message(
                    "toolport.fetchResult is unavailable in this context",
                )));
            };
            // Budget/deadline next, still before argument parsing, so a script that
            // loops on invalid specs cannot spin past its wall clock unchecked.
            reserve_budget(host.calls_made.get(), host.max_calls, host.deadline)?;
            let raw = args
                .first()
                .and_then(JsValue::as_string)
                .map(|s| s.to_std_string_escaped())
                .unwrap_or_else(|| "{}".to_string());
            let spec: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let cursor = spec
                .get("cursor")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if cursor.is_empty() {
                return Err(JsError::from_native(
                    JsNativeError::error()
                        .with_message("toolport.fetchResult requires a non-empty cursor"),
                ));
            }
            let offset = spec.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let len = spec.get("len").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            let projection = spec
                .get("projection")
                .and_then(|v| v.as_str())
                .map(str::to_string);
            host.calls_made.set(host.calls_made.get() + 1);
            let result = (fetch)(FetchArgs {
                cursor,
                offset,
                len,
                projection,
            });
            let result_str = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string());
            Ok(JsValue::from(js_string!(result_str)))
        },
        fetch_host,
    );
    if let Err(e) =
        context.register_global_callable(js_string!("__toolport_fetch_result"), 1, fetch_native)
    {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }

    let (global_name, value, attributes, freeze) = match input {
        ScriptInput::Data(value) => ("data", value, Attribute::all(), false),
        ScriptInput::ImmutableInput(value) => ("input", value, Attribute::empty(), true),
    };
    match JsValue::from_json(&value, &mut context) {
        Ok(v) => {
            if let Err(e) = context.register_global_property(
                boa_engine::JsString::from(global_name),
                v,
                attributes,
            ) {
                return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
            }
        }
        Err(e) => return fail(calls_made.get(), executed.take(), checkpoint.take(), e),
    }

    if freeze {
        const DEEP_FREEZE_INPUT: &str = r#"
            (function (root) {
                const seen = new WeakSet();
                function freeze(value) {
                    if (value === null || typeof value !== "object" || seen.has(value)) return value;
                    seen.add(value);
                    for (const key of Object.keys(value)) freeze(value[key]);
                    return Object.freeze(value);
                }
                freeze(root);
            })(input);
        "#;
        if let Err(e) = context.eval(Source::from_bytes(DEEP_FREEZE_INPUT)) {
            return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
        }
    }

    if let Err(e) = context.eval(Source::from_bytes(PRELUDE)) {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }

    // Typed `servers.*` surface from the scoped catalog (after toolport bindings exist).
    let servers_js = build_servers_prelude(catalog);
    if let Err(e) = context.eval(Source::from_bytes(servers_js.as_bytes())) {
        return fail(calls_made.get(), executed.take(), checkpoint.take(), e);
    }

    // Async IIFE: top-level `return` and `await` both work; the result is always a Promise.
    let wrapped = format!("(async function () {{\n{script}\n}})()");
    let top = match context.eval(Source::from_bytes(wrapped.as_bytes())) {
        Ok(v) => v,
        Err(e) => return fail(calls_made.get(), executed.take(), checkpoint.take(), e),
    };

    match drive_to_completion(&mut context, &state, top) {
        Ok(value) => ScriptOutcome {
            final_result_bytes: serialized_len(&value),
            value,
            calls: calls_made.get(),
            progress: executed.take(),
            checkpoint: checkpoint.take(),
            error: None,
        },
        Err(e) => fail(calls_made.get(), executed.take(), checkpoint.take(), e),
    }
}

fn reserve_call_slot(state: &HostState) -> Result<(), JsError> {
    reserve_budget(state.calls_made.get(), state.max_calls, state.deadline)
}

/// Shared budget check for `toolport.call`, `callAsync`, and `fetchResult` (WS2-2).
fn reserve_budget(calls_made: usize, max_calls: usize, deadline: Instant) -> Result<(), JsError> {
    if calls_made >= max_calls {
        return Err(JsError::from_native(JsNativeError::error().with_message(
            format!("toolport.call budget exceeded ({max_calls} calls)"),
        )));
    }
    if Instant::now() >= deadline {
        return Err(JsError::from_native(
            JsNativeError::error().with_message("toolport script wall-clock deadline exceeded"),
        ));
    }
    Ok(())
}

fn parse_call_args(args: &[JsValue]) -> (String, Value) {
    let name = args
        .first()
        .and_then(JsValue::as_string)
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_default();
    let args_json = args
        .get(1)
        .and_then(JsValue::as_string)
        .map(|s| s.to_std_string_escaped())
        .unwrap_or_else(|| "{}".to_string());
    let parsed: Value = serde_json::from_str(&args_json).unwrap_or(Value::Null);
    (name, parsed)
}

/// Flush pending host work and promise jobs until the top-level async IIFE settles.
fn drive_to_completion(
    context: &mut Context,
    state: &HostState,
    top: JsValue,
) -> Result<Value, JsError> {
    // Bound the drive loop so a pure-JS pending Promise can't spin forever.
    const MAX_DRIVE_ITERS: usize = 1_000_000;

    for _ in 0..MAX_DRIVE_ITERS {
        flush_pending_host_calls(context, state)?;

        if let Err(e) = context.run_jobs() {
            return Err(e);
        }

        // Host work may have been enqueued from a microtask after run_jobs.
        if !state.pending.borrow().is_empty() {
            continue;
        }

        let Some(obj) = top.as_object() else {
            return json_from_js(context, &top);
        };
        let promise = match JsPromise::from_object(obj.clone()) {
            Ok(p) => p,
            Err(_) => {
                return json_from_js(context, &top);
            }
        };

        match promise.state() {
            PromiseState::Pending => {
                // No host work left and jobs drained: the script is stuck on a Promise
                // that nothing will settle.
                return Err(JsError::from_native(JsNativeError::error().with_message(
                    "toolport script hung on an unresolved Promise (no pending tool calls)",
                )));
            }
            PromiseState::Fulfilled(value) => {
                return json_from_js(context, &value);
            }
            PromiseState::Rejected(reason) => {
                let msg = reason
                    .to_string(context)
                    .map(|s| s.to_std_string_escaped())
                    .unwrap_or_else(|_| reason.display().to_string());
                return Err(JsError::from_native(
                    JsNativeError::error().with_message(format!("Uncaught {msg}")),
                ));
            }
        }
    }

    Err(JsError::from_native(JsNativeError::error().with_message(
        "toolport script exceeded internal async drive budget",
    )))
}

/// Convert a script's return value to JSON through JS `JSON.stringify`, the same boundary
/// the prelude already uses for tool arguments and results.
///
/// Not `JsValue::to_json`: that is a host-side walk of internal property slots, so it never
/// runs `toJSON()` and never sees accessors. A `Date` has no own enumerable properties and
/// came back as `{}`; a `BigInt` produced an `Err` that the old call sites discarded with
/// `.ok().flatten().unwrap_or(Value::Null)`. Either way the script reported success with
/// the data gone, which the agent cannot distinguish from a real `null` return.
///
/// Going through `JSON.stringify` gives `Date` its ISO-8601 string and turns values that
/// genuinely cannot be represented (`BigInt`, cyclic structures) into a thrown `TypeError`
/// we surface as a script error. `undefined` — a script that returned nothing — stays
/// `null`, matching [`ScriptOutcome::value`]'s contract.
fn json_from_js(context: &mut Context, value: &JsValue) -> Result<Value, JsError> {
    let json = context.global_object().get(js_string!("JSON"), context)?;
    let stringify = json
        .as_object()
        .ok_or_else(|| type_error("JSON is not an object"))?
        .get(js_string!("stringify"), context)?
        .as_callable()
        .ok_or_else(|| type_error("JSON.stringify is not callable"))?;

    let encoded = stringify.call(&JsValue::undefined(), &[value.clone()], context)?;
    let Some(text) = encoded.as_string() else {
        // `JSON.stringify(undefined)` is `undefined`: the script returned nothing.
        return Ok(Value::Null);
    };

    serde_json::from_str(&text.to_std_string_escaped()).map_err(|e| {
        JsError::from_native(JsNativeError::typ().with_message(format!(
            "script return value could not be encoded as JSON: {e}"
        )))
    })
}

fn type_error(message: &str) -> JsError {
    JsError::from_native(JsNativeError::typ().with_message(message.to_string()))
}

/// Take queued `callAsync` work, run it with bounded host-side parallelism, resolve each
/// Promise with the JSON-stringified tool result (same wire shape as sync `call`).
fn flush_pending_host_calls(context: &mut Context, state: &HostState) -> Result<(), JsError> {
    loop {
        if Instant::now() >= state.deadline {
            return Err(JsError::from_native(
                JsNativeError::error().with_message("toolport script wall-clock deadline exceeded"),
            ));
        }

        let batch: Vec<PendingCall> = {
            let mut pending = state.pending.borrow_mut();
            if pending.is_empty() {
                return Ok(());
            }
            let take = pending.len().min(state.max_parallel);
            pending.drain(..take).collect()
        };

        let names_args: Vec<(String, Value)> = batch
            .iter()
            .map(|p| (p.name.clone(), p.args.clone()))
            .collect();
        let results = run_calls_parallel(&state.call, state.executed.borrow().len(), names_args);

        // Record before resolving the promises: these calls have already run, and
        // a resolver that throws must not lose the fact that they did (#646).
        // `run_calls_parallel` preserves input order, so the ledger stays in batch
        // order rather than completion order.
        {
            let mut executed = state.executed.borrow_mut();
            for (pending_call, result) in batch.iter().zip(results.iter()) {
                let index = executed.len();
                executed.push(CallRecord {
                    index,
                    name: pending_call.name.clone(),
                    ok: result_ok(result),
                    result_bytes: serialized_len(result),
                });
            }
        }

        for (pending_call, result) in batch.into_iter().zip(results.into_iter()) {
            let result_str = serde_json::to_string(&result).unwrap_or_else(|_| "null".to_string());
            let js_result = JsValue::from(js_string!(result_str));
            pending_call
                .resolvers
                .resolve
                .call(&JsValue::undefined(), &[js_result], context)?;
        }

        // More may still be queued; keep draining this wave before returning to the
        // outer drive loop (which also runs promise jobs).
        if state.pending.borrow().is_empty() {
            return Ok(());
        }
    }
}

/// Run independent host tool calls, using a short-lived thread scope when more than one
/// is ready so wall-clock tracks the slowest call in the batch rather than the sum.
fn run_calls_parallel(
    call: &IndexedCallBinding,
    start_index: usize,
    items: Vec<(String, Value)>,
) -> Vec<Value> {
    if items.is_empty() {
        return Vec::new();
    }
    if items.len() == 1 {
        let (name, args) = &items[0];
        return vec![call(start_index, name, args.clone())];
    }

    let n = items.len();
    let mut results: Vec<Option<Value>> = (0..n).map(|_| None).collect();
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(n);
        for (i, (name, args)) in items.into_iter().enumerate() {
            let call = call;
            handles.push(scope.spawn(move || (i, call(start_index + i, &name, args))));
        }
        for handle in handles {
            match handle.join() {
                Ok((i, value)) => results[i] = Some(value),
                Err(_) => {
                    // Worker panicked; leave a slot error in place so order is preserved.
                    // Index is unknown if join payload was lost — fill first empty slot.
                    if let Some(slot) = results.iter_mut().find(|s| s.is_none()) {
                        *slot = Some(json!({
                            "content": [{ "type": "text", "text": "Toolport: callAsync worker panicked" }],
                            "isError": true
                        }));
                    }
                }
            }
        }
    });
    results
        .into_iter()
        .map(|v| {
            v.unwrap_or_else(|| {
                json!({
                    "content": [{ "type": "text", "text": "Toolport: callAsync worker missing result" }],
                    "isError": true
                })
            })
        })
        .collect()
}

/// Build a fail-closed outcome from a boa error, rendering it to a readable message.
/// Uses the error's `Display` rather than `to_opaque` on purpose: boa's uncatchable
/// runtime-limit errors (loop/recursion caps) panic when converted to an opaque JS value,
/// and `Display` yields a usable message (`Uncaught Error: ...`, `RuntimeLimit: ...`) for
/// every error kind.
fn fail(
    calls: usize,
    progress: Vec<CallRecord>,
    checkpoint: Option<Value>,
    err: JsError,
) -> ScriptOutcome {
    ScriptOutcome {
        value: json!(null),
        calls,
        progress,
        final_result_bytes: 0,
        checkpoint,
        error: Some(err.to_string()),
    }
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration as StdDuration;

    /// A call binding that records the calls it saw and echoes a canned reply per tool.
    fn recording_call(log: Arc<Mutex<Vec<(String, Value)>>>) -> CallBinding {
        Arc::new(move |name: &str, args: Value| {
            log.lock().unwrap().push((name.to_string(), args.clone()));
            json!({ "echo": name, "args": args })
        })
    }

    fn run(script: &str, data: Value, call: CallBinding, limits: Limits) -> ScriptOutcome {
        run_script(script, data, call, None, limits, &[])
    }

    /// Names in `outcome.progress`, for terse assertions.
    fn progress_names(out: &ScriptOutcome) -> Vec<&str> {
        out.progress.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn a_failed_script_still_reports_the_calls_that_already_ran() {
        // The point of #646: dying on call 3 must not erase calls 1 and 2, whose
        // side effects have already committed downstream.
        let log = Arc::new(Mutex::new(Vec::new()));
        let script = r#"
            toolport.call("first", {});
            toolport.call("second", {});
            throw new Error("boom");
        "#;
        let out = run(script, json!({}), recording_call(log), Limits::default());

        assert!(out.error.is_some(), "script was supposed to throw");
        assert_eq!(progress_names(&out), vec!["first", "second"]);
        assert!(out.progress.iter().all(|c| c.ok));
        assert_eq!(out.calls, 2);
    }

    /// A binding no return-value test needs, since none of them call a tool.
    fn no_calls() -> CallBinding {
        Arc::new(|_name: &str, _args: Value| json!({}))
    }

    fn returns(script: &str) -> ScriptOutcome {
        run(script, json!({}), no_calls(), Limits::default())
    }

    fn returns_with_immutable_input(script: &str, input: Value) -> ScriptOutcome {
        run_script_with_input(
            script,
            ScriptInput::ImmutableInput(input),
            no_calls(),
            None,
            Limits::default(),
            &[],
        )
    }

    #[test]
    fn routine_input_is_deeply_immutable_and_has_no_data_alias() {
        let out = returns_with_immutable_input(
            r#"
                try { input.owner = "changed"; } catch (_) {}
                try { input.nested.value = 2; } catch (_) {}
                try { input.items.push("new"); } catch (_) {}
                return {
                    owner: input.owner,
                    nested: input.nested.value,
                    items: input.items,
                    inputFrozen: Object.isFrozen(input),
                    nestedFrozen: Object.isFrozen(input.nested),
                    arrayFrozen: Object.isFrozen(input.items),
                    dataType: typeof data,
                };
            "#,
            json!({ "owner": "original", "nested": { "value": 1 }, "items": ["old"] }),
        );

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(
            out.value,
            json!({
                "owner": "original",
                "nested": 1,
                "items": ["old"],
                "inputFrozen": true,
                "nestedFrozen": true,
                "arrayFrozen": true,
                "dataType": "undefined",
            })
        );
    }

    #[test]
    fn ordinary_code_mode_data_remains_mutable() {
        let out = run(
            "data.value = 2; return data.value;",
            json!({ "value": 1 }),
            no_calls(),
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!(2));
    }

    #[test]
    fn a_returned_date_survives_as_its_instant() {
        // SBS-631: boa's to_json walks internal slots, so it never ran Date's toJSON()
        // and the instant arrived as {} under a successful outcome.
        let out = returns("return new Date(0);");

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!("1970-01-01T00:00:00.000Z"));
    }

    #[test]
    fn a_returned_bigint_fails_closed_instead_of_reporting_null() {
        // The old path produced `Err` here and then dropped it on the floor with
        // `.ok().flatten().unwrap_or(Value::Null)`, so the agent saw a successful
        // `null` id. A false success is worse than an error it can recover from.
        let out = returns("return 9007199254740993n;");

        let err = out.error.expect("BigInt cannot be represented in JSON");
        assert!(
            err.to_lowercase().contains("bigint"),
            "error should name the unrepresentable type, got: {err}"
        );
    }

    #[test]
    fn dates_nested_in_a_returned_structure_survive_too() {
        // Aggregation output is where this actually bit: the timestamp is a field on
        // a row, not the whole return value.
        let out = returns(r#"return { ranAt: new Date(0), rows: [{ at: new Date(0) }] };"#);

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(
            out.value,
            json!({
                "ranAt": "1970-01-01T00:00:00.000Z",
                "rows": [{ "at": "1970-01-01T00:00:00.000Z" }],
            })
        );
    }

    #[test]
    fn a_cyclic_return_value_is_an_error_not_an_empty_success() {
        let out = returns("const a = {}; a.self = a; return a;");

        let err = out.error.expect("a cycle cannot be encoded as JSON");
        assert!(
            err.to_lowercase().contains("circular") || err.to_lowercase().contains("cyclic"),
            "error should explain the cycle, got: {err}"
        );
    }

    #[test]
    fn returning_nothing_is_still_a_successful_null() {
        // `JSON.stringify(undefined)` is `undefined`, not a string. That has to stay a
        // successful null rather than falling into the encode-failure branch.
        let out = returns("return;");

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!(null));
    }

    #[test]
    fn ordinary_return_values_are_unchanged() {
        // The conversion swap must not disturb the shapes scripts actually return.
        let out = returns(r#"return { n: 1, s: "x", b: true, nil: null, arr: [1, 2] };"#);

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(
            out.value,
            json!({ "n": 1, "s": "x", "b": true, "nil": null, "arr": [1, 2] })
        );
    }

    #[test]
    fn repeated_tool_names_stay_distinguishable_by_index() {
        // The ledger carries no args (they routinely hold credentials and personal
        // data), so the same tool called twice yields two same-named entries. Index
        // is what makes them separable — an agent that deduplicated by NAME would
        // skip the third call, which never ran. Guard the ordinal contract.
        let log = Arc::new(Mutex::new(Vec::new()));
        let script = r#"
            toolport.call("create_row", { id: 1 });
            toolport.call("create_row", { id: 2 });
            throw new Error("died before the third row");
        "#;
        let out = run(script, json!({}), recording_call(log), Limits::default());

        assert!(out.error.is_some());
        assert_eq!(progress_names(&out), vec!["create_row", "create_row"]);
        assert_eq!(
            out.progress.iter().map(|c| c.index).collect::<Vec<_>>(),
            vec![0, 1],
            "indexes must be dense and ordered so resume-by-position is unambiguous"
        );
    }

    #[test]
    fn progress_indexes_stay_dense_across_sync_and_async_calls() {
        // Sync and flushed-async calls append to one ledger, so the index sequence
        // has to stay contiguous across both recording sites.
        let log = Arc::new(Mutex::new(Vec::new()));
        let script = r#"
            toolport.call("sync_one", {});
            await Promise.all([toolport.callAsync("fan_a", {}), toolport.callAsync("fan_b", {})]);
            toolport.call("sync_two", {});
            return "done";
        "#;
        let out = run(script, json!({}), recording_call(log), Limits::default());

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(
            out.progress.iter().map(|c| c.index).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            progress_names(&out),
            vec!["sync_one", "fan_a", "fan_b", "sync_two"]
        );
    }

    #[test]
    fn progress_marks_a_downstream_error_without_dropping_the_call() {
        // `ok: false` means the call RAN and failed — it must still be listed,
        // because a failed downstream call can still have committed a side effect.
        let call: CallBinding = Arc::new(|name: &str, _: Value| {
            if name == "bad" {
                json!({ "content": [], "isError": true })
            } else {
                json!({ "content": [], "isError": false })
            }
        });
        let script = r#"
            toolport.call("good", {});
            toolport.call("bad", {});
            toolport.call("good", {});
            return "done";
        "#;
        let out = run(script, json!({}), call, Limits::default());

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(progress_names(&out), vec!["good", "bad", "good"]);
        assert_eq!(
            out.progress.iter().map(|c| c.ok).collect::<Vec<_>>(),
            vec![true, false, true]
        );
    }

    #[test]
    fn progress_records_parallel_call_async_work_in_batch_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let script = r#"
            var ps = [];
            for (var i = 0; i < 4; i++) { ps.push(toolport.callAsync("fan" + i, {})); }
            await Promise.all(ps);
            throw new Error("after the fan-out");
        "#;
        let out = run(script, json!({}), recording_call(log), Limits::default());

        assert!(out.error.is_some());
        // run_calls_parallel preserves input order, so the ledger is deterministic
        // even though the calls ran concurrently.
        assert_eq!(
            progress_names(&out),
            vec!["fan0", "fan1", "fan2", "fan3"],
            "parallel work is recorded in batch order"
        );
    }

    #[test]
    fn fetch_result_counts_against_the_budget_but_is_not_a_downstream_call() {
        // fetchResult pages a cached result: it commits nothing downstream, so it
        // must not appear in a ledger whose purpose is "what side effects landed".
        let call = recording_call(Arc::new(Mutex::new(Vec::new())));
        let fetch: FetchBinding = Arc::new(|_: FetchArgs| json!({ "page": 1 }));
        let script = r#"
            toolport.call("real", {});
            toolport.fetchResult({ cursor: "c1", offset: 0, len: 1 });
            return "done";
        "#;
        let out = run_script(script, json!({}), call, Some(fetch), Limits::default(), &[]);

        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(progress_names(&out), vec!["real"]);
        assert_eq!(out.calls, 2, "fetchResult still counts against max_calls");
    }

    #[test]
    fn a_script_that_never_compiles_reports_no_progress() {
        let call = recording_call(Arc::new(Mutex::new(Vec::new())));
        let out = run(
            "this is not ( valid javascript",
            json!({}),
            call,
            Limits::default(),
        );
        assert!(out.error.is_some());
        assert!(out.progress.is_empty());
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn progress_is_populated_on_the_success_path_too() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let out = run(
            "toolport.call('one', {}); return 'ok';",
            json!({}),
            recording_call(log),
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(progress_names(&out), vec!["one"]);
    }

    #[test]
    fn a_budget_exhausted_script_reports_the_calls_it_got_through() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let limits = Limits {
            max_calls: 2,
            ..Limits::default()
        };
        let out = run(
            "for (var i = 0; i < 10; i++) { toolport.call('t' + i, {}); } return 'done';",
            json!({}),
            recording_call(log),
            limits,
        );
        assert!(out.error.is_some(), "budget should have aborted the script");
        assert_eq!(
            progress_names(&out),
            vec!["t0", "t1"],
            "the two calls that ran before the budget tripped are still reported"
        );
    }

    #[test]
    fn runs_a_plain_script_and_returns_its_value() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run("return 1 + 2;", json!({}), call, Limits::default());
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!(3));
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn toolport_call_reaches_the_binding_and_data_is_injected() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let script = r#"
            var out = [];
            for (var i = 0; i < data.ids.length; i++) {
                var r = toolport.call("lookup", { id: data.ids[i] });
                out.push(r.args.id);
            }
            return out;
        "#;
        let out = run(
            script,
            json!({ "ids": [10, 20, 30] }),
            call,
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!([10, 20, 30]));
        assert_eq!(out.calls, 3);
        let log = log.lock().unwrap();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0].0, "lookup");
        assert_eq!(log[1].1, json!({ "id": 20 }));
    }

    #[test]
    fn call_budget_is_enforced() {
        let call = Arc::new(|_: &str, _: Value| json!({}));
        let limits = Limits {
            max_calls: 2,
            ..Limits::default()
        };
        let out = run(
            "for (var i = 0; i < 10; i++) { toolport.call('t', {}); } return 'done';",
            json!({}),
            call,
            limits,
        );
        // Fail-closed: it made exactly the budgeted calls, then errored instead of finishing.
        assert_eq!(out.calls, 2);
        assert_ne!(out.error, None);
        assert!(out.error.unwrap().contains("budget"));
    }

    #[test]
    fn loop_limit_stops_pure_js_runaway() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            loop_iteration_limit: 1000,
            ..Limits::default()
        };
        let out = run("while (true) {} return 1;", json!({}), call, limits);
        assert_ne!(out.error, None, "an infinite loop must be stopped");
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn nested_loops_share_one_iteration_budget() {
        // SBS-430: the cap is total iterations, not per-loop, so nesting cannot multiply
        // its way past it. Without this a script could sit under the limit in every
        // individual loop and still run unbounded work.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            loop_iteration_limit: 1_000,
            ..Limits::default()
        };
        let out = run(
            "let n = 0; for (let i = 0; i < 1000; i++) { for (let j = 0; j < 1000; j++) { n++; } } return n;",
            json!({}),
            call,
            limits,
        );

        let err = out.error.expect("nested loops must hit the shared budget");
        assert!(err.contains("loop iteration limit"), "got: {err}");
    }

    #[test]
    fn unbounded_recursion_is_stopped_without_a_host_call() {
        // The other half of the pure-JS bound. Depth-limited, and it trips long before
        // the loop budget would.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            "function f(n) { return n <= 0 ? 0 : f(n - 1) + 1; } return f(10000000);",
            json!({}),
            call,
            Limits::default(),
        );

        let err = out.error.expect("unbounded recursion must be stopped");
        assert!(err.contains("recursive calls"), "got: {err}");
        assert_eq!(out.calls, 0, "it never reached a host call");
    }

    #[test]
    fn pure_js_runaways_are_bounded_by_count_not_wall_clock() {
        // Documents the real contract (SBS-430): a CPU-bound script that never calls a
        // tool and never awaits is stopped by boa's iteration counter, NOT by
        // Limits::wall_clock, which nothing consults on that path. A wall_clock of zero
        // therefore does not stop it -- only the loop budget does.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            wall_clock: StdDuration::from_secs(0),
            loop_iteration_limit: 5_000,
            ..Limits::default()
        };
        let out = run("while (true) {} return 1;", json!({}), call, limits);

        let err = out.error.expect("the loop budget must still stop it");
        assert!(
            err.contains("loop iteration limit"),
            "an expired wall clock is not what stops a pure-JS loop; got: {err}"
        );
    }

    #[test]
    fn a_thrown_error_is_reported_not_panicked() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            "throw new Error('boom');",
            json!({}),
            call,
            Limits::default(),
        );
        assert!(out.error.unwrap().contains("boom"));
    }

    #[test]
    fn syntax_error_fails_closed() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run("this is not valid )(", json!({}), call, Limits::default());
        assert_ne!(out.error, None);
        assert_eq!(out.calls, 0);
    }

    #[test]
    fn call_async_with_await_returns_result() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let script = r#"
            const a = await toolport.callAsync("lookup", { id: 7 });
            return a.args.id;
        "#;
        let out = run(script, json!({}), call, Limits::default());
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!(7));
        assert_eq!(out.calls, 1);
    }

    #[test]
    fn promise_all_fans_out_and_preserves_order() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let script = r#"
            const results = await Promise.all([
                toolport.callAsync("a", { n: 1 }),
                toolport.callAsync("b", { n: 2 }),
                toolport.callAsync("c", { n: 3 }),
            ]);
            return results.map(function (r) { return r.echo + ":" + r.args.n; });
        "#;
        let out = run(script, json!({}), call, Limits::default());
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!(["a:1", "b:2", "c:3"]));
        assert_eq!(out.calls, 3);
        let names: Vec<String> = log.lock().unwrap().iter().map(|(n, _)| n.clone()).collect();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"a".to_string()));
        assert!(names.contains(&"b".to_string()));
        assert!(names.contains(&"c".to_string()));
    }

    #[test]
    fn call_all_sugar_matches_promise_all() {
        let call = Arc::new(|name: &str, args: Value| json!({ "echo": name, "args": args }));
        let script = r#"
            const results = await toolport.callAll([
                { name: "x", args: { i: 1 } },
                { name: "y", args: { i: 2 } },
            ]);
            return results.map(function (r) { return r.echo + r.args.i; }).join(",");
        "#;
        let out = run(script, json!({}), call, Limits::default());
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value, json!("x1,y2"));
        assert_eq!(out.calls, 2);
    }

    #[test]
    fn call_async_budget_is_enforced() {
        let call = Arc::new(|_: &str, _: Value| json!({}));
        let limits = Limits {
            max_calls: 2,
            ..Limits::default()
        };
        let out = run(
            r#"
                await Promise.all([
                    toolport.callAsync("a", {}),
                    toolport.callAsync("b", {}),
                    toolport.callAsync("c", {}),
                ]);
                return "done";
            "#,
            json!({}),
            call,
            limits,
        );
        assert_eq!(out.calls, 2);
        assert_ne!(out.error, None);
        assert!(out.error.unwrap().contains("budget"));
    }

    #[test]
    fn parallel_host_calls_overlap() {
        // Measure overlap directly instead of inferring it from wall-clock timing. The
        // latter flakes on loaded runners even when all three workers are concurrent.
        let in_flight = Arc::new(Mutex::new(0usize));
        let peak = Arc::new(Mutex::new(0usize));
        let in_flight2 = in_flight.clone();
        let peak2 = peak.clone();
        let call: CallBinding = Arc::new(move |name: &str, _: Value| {
            {
                let mut current = in_flight2.lock().unwrap();
                *current += 1;
                let mut observed_peak = peak2.lock().unwrap();
                *observed_peak = (*observed_peak).max(*current);
            }
            thread::sleep(StdDuration::from_millis(80));
            *in_flight2.lock().unwrap() -= 1;
            json!({ "echo": name })
        });
        let limits = Limits {
            max_parallel: 8,
            wall_clock: StdDuration::from_secs(10),
            ..Limits::default()
        };
        let out = run(
            r#"
                return await Promise.all([
                    toolport.callAsync("a", {}),
                    toolport.callAsync("b", {}),
                    toolport.callAsync("c", {}),
                ]);
            "#,
            json!({}),
            call,
            limits,
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.calls, 3);
        assert_eq!(*peak.lock().unwrap(), 3, "all host calls should overlap");
    }

    #[test]
    fn max_parallel_caps_concurrent_host_work() {
        let in_flight = Arc::new(Mutex::new(0usize));
        let peak = Arc::new(Mutex::new(0usize));
        let in_flight2 = in_flight.clone();
        let peak2 = peak.clone();
        let call: CallBinding = Arc::new(move |_name: &str, _: Value| {
            {
                let mut n = in_flight2.lock().unwrap();
                *n += 1;
                let mut p = peak2.lock().unwrap();
                if *n > *p {
                    *p = *n;
                }
            }
            thread::sleep(StdDuration::from_millis(30));
            {
                let mut n = in_flight2.lock().unwrap();
                *n -= 1;
            }
            json!({ "ok": true })
        });
        let limits = Limits {
            max_parallel: 2,
            wall_clock: StdDuration::from_secs(10),
            ..Limits::default()
        };
        let out = run(
            r#"
                return await Promise.all([
                    toolport.callAsync("a", {}),
                    toolport.callAsync("b", {}),
                    toolport.callAsync("c", {}),
                    toolport.callAsync("d", {}),
                ]);
            "#,
            json!({}),
            call,
            limits,
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.calls, 4);
        let peak = *peak.lock().unwrap();
        assert!(peak <= 2, "peak concurrency {peak} exceeded max_parallel 2");
        assert!(peak >= 2, "expected to reach max_parallel, peak={peak}");
    }

    #[test]
    fn servers_stub_calls_through_with_snake_and_camel() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let catalog = vec![
            "stripe__create_refund".to_string(),
            "github__create_pull_request".to_string(),
        ];
        let script = r#"
            const a = servers.stripe.create_refund({ id: "ch_1" });
            const b = servers.stripe.createRefund({ id: "ch_2" });
            const c = servers.github.createPullRequest({ title: "t" });
            return {
                tools: toolport.listTools().sort(),
                servers: toolport.listServers().sort(),
                names: [a.echo, b.echo, c.echo],
                ids: [a.args.id, b.args.id],
                title: c.args.title,
            };
        "#;
        let out = run_script(script, json!({}), call, None, Limits::default(), &catalog);
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.calls, 3);
        assert_eq!(
            out.value["names"],
            json!([
                "stripe__create_refund",
                "stripe__create_refund",
                "github__create_pull_request"
            ])
        );
        assert_eq!(out.value["ids"], json!(["ch_1", "ch_2"]));
        assert_eq!(out.value["title"], json!("t"));
        assert_eq!(
            out.value["tools"],
            json!(["github__create_pull_request", "stripe__create_refund"])
        );
        assert_eq!(out.value["servers"], json!(["github", "stripe"]));
        let log = log.lock().unwrap();
        assert_eq!(log[0].0, "stripe__create_refund");
        assert_eq!(log[2].0, "github__create_pull_request");
    }

    #[test]
    fn servers_stub_async_fans_out() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let catalog = vec![
            "stripe__create_refund".to_string(),
            "resend__send_email".to_string(),
        ];
        let script = r#"
            const results = await Promise.all([
                servers.stripe.createRefund.async({ id: 1 }),
                servers.resend.send_email.async({ to: "a@b.c" }),
            ]);
            return results.map(function (r) { return r.echo; }).sort();
        "#;
        let out = run_script(script, json!({}), call, None, Limits::default(), &catalog);
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.calls, 2);
        assert_eq!(
            out.value,
            json!(["resend__send_email", "stripe__create_refund"])
        );
    }

    #[test]
    fn empty_catalog_still_exposes_empty_servers() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            "return { tools: toolport.listTools(), servers: toolport.listServers(), has: typeof servers };",
            json!({}),
            call,
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value["tools"], json!([]));
        assert_eq!(out.value["servers"], json!([]));
        assert_eq!(out.value["has"], json!("object"));
    }

    #[test]
    fn js_string_literal_escapes_quotes_and_newlines() {
        assert_eq!(js_string_literal("a'b\\c\nd"), "'a\\'b\\\\c\\nd'");
    }

    #[test]
    fn snake_to_camel_basic() {
        assert_eq!(snake_to_camel("create_refund"), "createRefund");
        assert_eq!(snake_to_camel("alreadyCamel"), "alreadyCamel");
        assert_eq!(snake_to_camel("a_b_c"), "aBC");
    }

    #[test]
    fn split_exposed_name_uses_first_separator() {
        assert_eq!(
            split_exposed_name("stripe__create_refund"),
            Some(("stripe", "create_refund"))
        );
        assert_eq!(
            split_exposed_name("s__tool__extra"),
            Some(("s", "tool__extra"))
        );
        assert_eq!(split_exposed_name("nosep"), None);
    }

    #[test]
    fn camel_alias_does_not_clobber_sibling_tool() {
        // If both create_refund and createRefund exist as distinct tools, keep both.
        let log = Arc::new(Mutex::new(Vec::new()));
        let call = recording_call(log.clone());
        let catalog = vec![
            "s__create_refund".to_string(),
            "s__createRefund".to_string(),
        ];
        let script = r#"
            return {
                a: servers.s.create_refund({}).echo,
                b: servers.s.createRefund({}).echo,
            };
        "#;
        let out = run_script(script, json!({}), call, None, Limits::default(), &catalog);
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value["a"], json!("s__create_refund"));
        assert_eq!(out.value["b"], json!("s__createRefund"));
    }

    #[test]
    fn fetch_result_binding_pages_shaped_cursor() {
        // Simulate a shaped stash entry via the fetch binding (gateway wires shaping::fetch_result).
        let full = "abcdefghijklmnopqrstuvwxyz";
        let fetch: FetchBinding = Arc::new(move |args: FetchArgs| {
            assert_eq!(args.cursor, "r1");
            let start = args.offset.min(full.len());
            let end = if args.len == 0 {
                full.len()
            } else {
                start.saturating_add(args.len).min(full.len())
            };
            json!({
                "content": [{ "type": "text", "text": &full[start..end] }],
                "isError": false
            })
        });
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run_script(
            r#"
                const a = toolport.fetchResult({ cursor: "r1", offset: 0, len: 5 });
                const b = toolport.fetchResult({ cursor: "r1", offset: 5, len: 5 });
                return { a: a.content[0].text, b: b.content[0].text };
            "#,
            json!({}),
            call,
            Some(fetch),
            Limits::default(),
            &[],
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.value["a"], json!("abcde"));
        assert_eq!(out.value["b"], json!("fghij"));
    }

    #[test]
    fn fetch_result_unavailable_without_binding() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"return toolport.fetchResult({ cursor: "r1" });"#,
            json!({}),
            call,
            Limits::default(),
        );
        assert_ne!(out.error, None);
        assert!(out.error.unwrap().contains("unavailable"));
    }

    /// An exhausted budget must not mask the real reason a script cannot page
    /// results: with no binding AND no budget left, the error still says
    /// "unavailable", not "budget exceeded".
    #[test]
    fn fetch_result_unavailable_wins_over_an_exhausted_budget() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"return toolport.fetchResult({ cursor: "r1" });"#,
            json!({}),
            call,
            Limits {
                max_calls: 0,
                ..Limits::default()
            },
        );
        let err = out.error.expect("no binding must still be an error");
        assert!(
            err.contains("unavailable"),
            "availability must be reported ahead of the budget: {err}"
        );
        assert!(!err.contains("budget"), "misleading budget error: {err}");
    }

    /// The deadline check still runs before argument parsing, so a script looping on
    /// invalid specs against a live binding cannot spin past its wall clock.
    #[test]
    fn fetch_result_charges_the_budget_before_validating_the_spec() {
        let fetch: FetchBinding = Arc::new(
            |_: FetchArgs| json!({ "content": [{ "type": "text", "text": "x" }], "isError": false }),
        );
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run_script(
            // Empty cursor is invalid; the budget must be refused first.
            r#"return toolport.fetchResult({ cursor: "" });"#,
            json!({}),
            call,
            Some(fetch),
            Limits {
                max_calls: 0,
                ..Limits::default()
            },
            &[],
        );
        let err = out.error.expect("exhausted budget must be an error");
        assert!(
            err.contains("budget"),
            "budget must be checked before spec validation: {err}"
        );
    }

    /// WS2-2: fetchResult must share the call budget with toolport.call.
    #[test]
    fn fetch_result_counts_against_call_budget() {
        let fetch: FetchBinding = Arc::new(
            |_: FetchArgs| json!({ "content": [{ "type": "text", "text": "x" }], "isError": false }),
        );
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            max_calls: 2,
            ..Limits::default()
        };
        let out = run_script(
            r#"
                toolport.fetchResult({ cursor: "r1" });
                toolport.fetchResult({ cursor: "r1" });
                toolport.fetchResult({ cursor: "r1" });
                return 1;
            "#,
            json!({}),
            call,
            Some(fetch),
            limits,
            &[],
        );
        assert_ne!(out.error, None, "third fetchResult must hit budget");
        assert!(
            out.error.as_ref().unwrap().contains("budget"),
            "got: {:?}",
            out.error
        );
        assert_eq!(out.calls, 2);
    }

    #[test]
    fn self_requeuing_promise_jobs_hit_budget() {
        // CodeRabbit #480: unbounded Promise microtask chains must not pin run_jobs forever.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            max_promise_jobs: 50,
            wall_clock: StdDuration::from_secs(5),
            ..Limits::default()
        };
        let out = run(
            r#"
                let n = 0;
                function loop() {
                    n += 1;
                    return Promise.resolve().then(loop);
                }
                loop();
                return new Promise(function () {}); // never settles
            "#,
            json!({}),
            call,
            limits,
        );
        assert_ne!(out.error, None, "expected promise-job budget error");
        let err = out.error.unwrap();
        assert!(
            err.contains("promise-job budget") || err.contains("wall-clock"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn checkpoint_is_last_write_wins() {
        // #663: repeated calls overwrite, they don't accumulate a history.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"
                toolport.checkpoint({ step: 1 });
                toolport.checkpoint({ step: 2 });
                toolport.checkpoint({ step: 3 });
                return 'done';
            "#,
            json!({}),
            call,
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.checkpoint, Some(json!({ "step": 3 })));
    }

    #[test]
    fn checkpoint_survives_on_the_error_path() {
        // The whole point of #663: a script that records progress and then dies
        // must still report where it got to.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"
                toolport.checkpoint({ lastInsertedId: 41 });
                throw new Error('boom');
            "#,
            json!({}),
            call,
            Limits::default(),
        );
        assert!(out.error.is_some(), "script was supposed to throw");
        assert_eq!(out.checkpoint, Some(json!({ "lastInsertedId": 41 })));
    }

    #[test]
    fn checkpoint_is_none_when_the_script_never_calls_it() {
        let out = returns("return 'ok';");
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.checkpoint, None);
    }

    #[test]
    fn checkpoint_is_none_on_a_script_that_never_compiles() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            "this is not ( valid javascript",
            json!({}),
            call,
            Limits::default(),
        );
        assert!(out.error.is_some());
        assert_eq!(out.checkpoint, None);
    }

    #[test]
    fn checkpoint_oversized_value_is_rejected_without_dropping_the_prior_one() {
        // A checkpoint is a resume marker, not a payload: a script cannot smuggle a
        // large blob out through the one path (the failure text) that isn't subject
        // to max_calls.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"
                toolport.checkpoint({ ok: true });
                toolport.checkpoint({ blob: 'x'.repeat(5000) });
            "#,
            json!({}),
            call,
            Limits::default(),
        );
        let err = out.error.expect("an oversized checkpoint must fail closed");
        assert!(
            err.contains("4096"),
            "error should name the byte cap: {err}"
        );
        // The prior good checkpoint is untouched by the rejected call.
        assert_eq!(out.checkpoint, Some(json!({ "ok": true })));
    }

    #[test]
    fn malformed_checkpoint_json_is_rejected_without_dropping_the_prior_one() {
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let out = run(
            r#"
                toolport.checkpoint({ safe: true });
                try {
                    __toolport_checkpoint('{not-json');
                } catch (_) {}
                return 'done';
            "#,
            json!({}),
            call,
            Limits::default(),
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(
            out.checkpoint,
            Some(json!({ "safe": true })),
            "malformed direct-binding input must not replace the last good checkpoint"
        );
    }

    #[test]
    fn checkpoint_costs_nothing_against_the_call_budget() {
        // Per #663: checkpoint makes no downstream call, so it must not be gated by
        // reserve_call_slot / max_calls, unlike toolport.call.
        let call = Arc::new(|_: &str, _: Value| Value::Null);
        let limits = Limits {
            max_calls: 0,
            ..Limits::default()
        };
        let out = run(
            r#"
                toolport.checkpoint({ a: 1 });
                toolport.checkpoint({ a: 2 });
                return 'done';
            "#,
            json!({}),
            call,
            limits,
        );
        assert_eq!(out.error, None, "unexpected error: {:?}", out.error);
        assert_eq!(out.calls, 0, "checkpoint must not count against max_calls");
        assert_eq!(out.checkpoint, Some(json!({ "a": 2 })));
    }
}
