//! #759: exercise the shipped gateway/worker boundary, not an in-process Boa harness.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::{Duration, Instant};

use conduit_lib::registry::{self, Registry};
use serde_json::{json, Value};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Gateway {
    child: Child,
    stdin: ChildStdin,
    replies: mpsc::Receiver<Value>,
    reader: Option<std::thread::JoinHandle<()>>,
    dir: PathBuf,
    next_id: u64,
    http_port: Option<u16>,
}

impl Gateway {
    fn start() -> Self {
        Self::configured(|_, _| {}, false)
    }

    fn configured(configure: impl FnOnce(&mut Registry, &Path), http: bool) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "toolport-759-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let mut reg = Registry::default();
        configure(&mut reg, &dir);
        registry::save_to(&dir.join("registry.json"), &reg).unwrap();
        let executable = dir.join(format!("toolport-gateway{}", std::env::consts::EXE_SUFFIX));
        // Allow a cross-compiled harness to run in a VM whose paths differ from
        // the build host. Native cargo test keeps using Cargo's exact binary.
        let gateway_binary = std::env::var_os("TOOLPORT_TEST_GATEWAY")
            .unwrap_or_else(|| env!("CARGO_BIN_EXE_toolport-gateway").into());
        std::fs::copy(gateway_binary, &executable).unwrap();
        let mut command = Command::new(executable);
        command
            .env("TOOLPORT_REGISTRY", dir.join("registry.json"))
            .env("TOOLPORT_DATA_DIR", &dir)
            .env("TOOLPORT_CLIENT_ID", "code-mode-isolation-test")
            .env("TOOLPORT_CODE_MODE", "1")
            .env("TOOLPORT_RESULT_BUDGET", "49152")
            .env_remove("TOOLPORT_HTTP")
            .env_remove("CONDUIT_HTTP")
            .env_remove("TOOLPORT_HTTP_TOKEN")
            .env_remove("CONDUIT_HTTP_TOKEN")
            .env_remove("TOOLPORT_PROFILE")
            .env_remove("CONDUIT_PROFILE")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let http_port = http.then(|| {
            let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            socket.local_addr().unwrap().port()
        });
        if let Some(port) = http_port {
            command
                .arg("--http")
                .arg(port.to_string())
                .env("TOOLPORT_HTTP_HOST", "127.0.0.1");
        }
        let mut child = command.spawn().expect("start gateway");
        let stdin = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, replies) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if tx.send(value).is_err() {
                    break;
                }
            }
        });
        let mut gateway = Self {
            child,
            stdin,
            replies,
            reader: Some(reader),
            dir,
            next_id: 0,
            http_port,
        };
        if let Some(port) = http_port {
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                assert!(
                    gateway.child.try_wait().unwrap().is_none(),
                    "HTTP gateway exited"
                );
                if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                    return gateway;
                }
                assert!(Instant::now() < deadline, "HTTP gateway failed to listen");
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        let initialized = gateway.request(
            "initialize",
            json!({
                "protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": { "name": "isolation-test", "version": "1" }
            }),
        );
        assert!(
            initialized.get("result").is_some(),
            "initialize: {initialized}"
        );
        gateway
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        serde_json::to_writer(&mut self.stdin, &request).unwrap();
        writeln!(&mut self.stdin).unwrap();
        self.stdin.flush().unwrap();
        let deadline = Instant::now() + Duration::from_secs(75);
        loop {
            let reply = self
                .replies
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .expect("gateway must answer without exiting or hanging");
            if reply["id"] == id {
                return reply;
            }
        }
    }

    fn run(&mut self, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": "toolport_run_script", "arguments": arguments }),
        )["result"]
            .clone()
    }

    fn assert_alive(&mut self) {
        assert!(
            self.child.try_wait().unwrap().is_none(),
            "parent gateway exited"
        );
        let response = self.request(
            "tools/call",
            json!({ "name": "toolport_status", "arguments": {} }),
        );
        assert_ne!(
            response["result"]["isError"], true,
            "status failed: {response}"
        );
        assert!(
            response["result"].is_object(),
            "missing status response: {response}"
        );
    }

    fn http_call(&self, token: &str, name: &str, args: Value) -> Value {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(75))
            .build();
        let response = agent
            .post(&format!(
                "http://127.0.0.1:{}/{name}",
                self.http_port.unwrap()
            ))
            .set("Authorization", &format!("Bearer {token}"))
            .send_json(args);
        let response = match response {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(error) => panic!("HTTP gateway failed: {error}"),
        };
        response.into_json().expect("JSON HTTP result")
    }

    fn audit(&self) -> Vec<Value> {
        std::fs::read_to_string(self.dir.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn allocating_scripts_fail_without_killing_stdio_gateway() {
    let mut gateway = Gateway::start();
    let normal = gateway.run(json!({
        "script": "const buffer = new ArrayBuffer(32 * 1024 * 1024); return { answer: data.value + 1, bytes: buffer.byteLength };",
        "data": { "value": 41 }
    }));
    assert_eq!(normal["isError"], false, "normal script failed: {normal}");
    assert_eq!(normal["structuredContent"]["result"]["answer"], 42);
    assert_eq!(
        normal["structuredContent"]["result"]["bytes"],
        32 * 1024 * 1024
    );

    for validate in [false, true] {
        let failure = gateway.run(json!({
            "script": "const buffers = []; for (let i = 0; i < 32; i++) buffers.push(new ArrayBuffer(32 * 1024 * 1024)); return buffers.length;",
            "validate": validate
        }));
        assert_eq!(
            failure["isError"], true,
            "allocating script succeeded: {failure}"
        );
        let field = if validate {
            "toolportValidate"
        } else {
            "toolportScript"
        };
        let error = failure["structuredContent"][field]["error"]
            .as_str()
            .unwrap_or_default();
        assert!(error.contains("memory budget"), "wrong failure: {failure}");
        gateway.assert_alive();
        let recovery = gateway.run(json!({ "script": "return 7;" }));
        assert_eq!(recovery["isError"], false, "next worker failed: {recovery}");
    }
    assert_eq!(
        gateway
            .audit()
            .iter()
            .filter(|entry| entry["server"] == "toolport"
                && entry["tool"] == "run_script"
                && entry["error"] == "code_mode_memory_budget")
            .count(),
        2
    );
}

#[test]
fn script_error_text_cannot_impersonate_memory_exhaustion() {
    let mut gateway = Gateway::start();
    for (constructor, message) in [
        ("Error", "out of memory from a downstream service"),
        ("Error", "memory allocation failed in the remote tool"),
        (
            "RangeError",
            "invalid layout Layout { size: 33554432, align: 64 (1 << 6) } while allocating data block",
        ),
        ("Error", "code mode script exceeded its memory budget (512 MiB)"),
    ] {
        let failure = gateway.run(json!({
            "script": format!("toolport.checkpoint({{step:1}}); throw new {constructor}(data.message);"),
            "data": { "message": message }
        }));
        assert_eq!(failure["isError"], true, "{failure}");
        let metadata = &failure["structuredContent"]["toolportScript"];
        let error = metadata["error"].as_str().unwrap();
        assert!(error.ends_with(message), "script error was replaced: {failure}");
        assert!(
            !error.starts_with("code mode script exceeded its memory budget"),
            "script error was classified as an allocation failure: {failure}"
        );
        assert_eq!(metadata["checkpoint"]["step"], 1, "{failure}");
    }
    let failures: Vec<Value> = gateway
        .audit()
        .into_iter()
        .filter(|entry| entry["server"] == "toolport" && entry["tool"] == "run_script")
        .collect();
    assert_eq!(failures.len(), 4, "{failures:?}");
    assert!(
        failures
            .iter()
            .all(|entry| entry["error"] == "code_mode_failed"),
        "script text changed the audit category: {failures:?}"
    );
    gateway.assert_alive();
}

#[test]
fn stdio_rejects_oversized_source_data_input_and_schema() {
    use conduit_lib::codemode_worker::{MAX_SCHEMA_BYTES, MAX_SCRIPT_BYTES, MAX_VALUE_BYTES};
    let mut gateway = Gateway::start();
    for (arguments, expected) in [
        (
            json!({ "script": "x".repeat(MAX_SCRIPT_BYTES + 1) }),
            "source limit",
        ),
        (
            json!({ "script": "return 1;", "data": "x".repeat(MAX_VALUE_BYTES) }),
            "value limit",
        ),
        (
            json!({ "script": "return 1;", "input": { "x": "x".repeat(MAX_VALUE_BYTES) }, "inputSchema": { "type": "object" } }),
            "value limit",
        ),
        (
            json!({ "script": "return 1;", "input": {}, "inputSchema": { "description": "x".repeat(MAX_SCHEMA_BYTES) } }),
            "schema limit",
        ),
    ] {
        let result = gateway.run(arguments);
        assert_eq!(result["isError"], true, "payload was accepted: {result}");
        assert!(
            result.to_string().contains(expected),
            "wrong error: {result}"
        );
    }
    gateway.assert_alive();
}

fn mock_registry(reg: &mut Registry, dir: &Path) {
    let mock = dir.join(format!("mock-mcp-server{}", std::env::consts::EXE_SUFFIX));
    let mock_binary = std::env::var_os("TOOLPORT_TEST_MOCK")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mock-mcp-server").into());
    std::fs::copy(mock_binary, &mock).unwrap();
    reg.servers.push(serde_json::from_value(json!({
        "id": "s", "name": "Fixture", "transport": "stdio", "command": mock,
        "env": [{ "key": "MOCK_MCP_TRANSCRIPT", "value": dir.join("downstream.jsonl"), "secret": false }]
    })).unwrap());
    reg.profiles[0].enabled_server_ids.push("s".into());
    reg.tool_overrides.entry("s".into()).or_default().insert(
        "add".into(),
        registry::ToolOverride {
            name: Some("s__delete_item".into()),
            description: None,
        },
    );
}

#[test]
fn host_calls_remain_ordered_and_completed_work_survives_worker_failure() {
    let mut gateway = Gateway::configured(mock_registry, false);
    let normal = gateway.run(json!({
        "script": "const r = await toolport.callAll(Array.from({ length: 8 }, (_, i) => ({ name: 's__echo', args: { text: String(i) } }))); toolport.checkpoint({ page: 8 }); throw new Error('stop');"
    }));
    assert_eq!(normal["isError"], true, "{normal}");
    let metadata = &normal["structuredContent"]["toolportScript"];
    assert_eq!(metadata["calls"], 8);
    assert_eq!(metadata["checkpoint"]["page"], 8);
    for (index, entry) in metadata["progress"].as_array().unwrap().iter().enumerate() {
        assert_eq!(entry["index"], index);
        assert_eq!(entry["name"], "s__echo");
        assert_eq!(entry["ok"], true);
    }
    assert_eq!(metadata["progress"].as_array().unwrap().len(), 8);
    let failure = gateway.run(json!({
        "script": "toolport.call('s__echo', {text: 'committed'}); toolport.checkpoint({ page: 1 }); const buffers = []; for (let i = 0; i < 32; i++) buffers.push(new ArrayBuffer(32 * 1024 * 1024)); return 1;"
    }));
    let metadata = &failure["structuredContent"]["toolportScript"];
    assert_eq!(failure["isError"], true, "{failure}");
    assert!(metadata["error"]
        .as_str()
        .unwrap()
        .contains("memory budget"));
    assert_eq!(metadata["progress"][0]["name"], "s__echo");
    assert_eq!(metadata["progress"][0]["ok"], true);
    assert_eq!(metadata["checkpoint"]["page"], 1);
    gateway.assert_alive();
}

#[test]
fn isolated_host_calls_preserve_confirmation_pii_and_rate_limits() {
    let mut gateway = Gateway::configured(
        |reg, dir| {
            mock_registry(reg, dir);
            reg.confirm_destructive = true;
            reg.pii_redaction = true;
            reg.team = Some(serde_json::from_value(json!({
            "serverUrl": "https://example.invalid", "teamId": "test", "role": "member",
            "rateLimits": [{ "id": "echo-cap", "window": "day", "maxCalls": 1, "tool": "s/echo" }]
        })).unwrap());
        },
        false,
    );
    let result = gateway.run(json!({ "script": "const a = toolport.call('s__echo', {text: 'ada@example.com'}); const b = toolport.call('s__echo', {text: 'second'}); const c = toolport.call('s__delete_item', {a:1,b:2}); return {a,b,c};" }));
    assert_eq!(result["isError"], false, "{result}");
    let values = &result["structuredContent"]["result"];
    assert_eq!(values["a"]["isError"], false, "{result}");
    assert!(
        !values["a"].to_string().contains("ada@example.com"),
        "{result}"
    );
    assert_eq!(values["b"]["isError"], true, "{result}");
    assert!(
        values["b"].to_string().to_lowercase().contains("limit"),
        "{result}"
    );
    assert_eq!(values["c"]["isError"], true, "{result}");
    assert!(
        values["c"]
            .to_string()
            .contains("requires per-call confirmation"),
        "{result}"
    );
    let transcript = std::fs::read_to_string(gateway.dir.join("downstream.jsonl")).unwrap();
    let executed: Vec<Value> = transcript
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|req| req["method"] == "tools/call")
        .collect();
    assert_eq!(executed.len(), 1, "{executed:?}");
    assert_eq!(executed[0]["params"]["name"], "echo");
}

#[test]
fn isolated_host_call_cannot_skip_human_approval() {
    let mut gateway = Gateway::configured(
        |reg, dir| {
            mock_registry(reg, dir);
            reg.human_approval = true;
        },
        false,
    );
    let result =
        gateway.run(json!({ "script": "return toolport.call('s__delete_item', {a:1,b:2});" }));
    let value = &result["structuredContent"]["result"];
    assert_eq!(value["isError"], true, "{result}");
    assert!(value.to_string().contains("unreachable"), "{result}");
    let transcript = std::fs::read_to_string(gateway.dir.join("downstream.jsonl")).unwrap();
    assert!(!transcript
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .any(|req| req["method"] == "tools/call"));
    assert!(gateway
        .audit()
        .iter()
        .any(|entry| entry["server"] == "s" && entry["decision"] == "unreachable"));
}

#[test]
fn isolated_fetch_reads_parent_cache_and_oversized_output_fails_cleanly() {
    let mut gateway = Gateway::start();
    let shaped = gateway.run(json!({ "script": "return 'x'.repeat(100000);" }));
    let text = shaped["content"][0]["text"].as_str().unwrap();
    let cursor = text
        .split("\"cursor\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let fetched = gateway.run(json!({
        "script": "return toolport.fetchResult({cursor:data.cursor, offset:0, len:16});",
        "data": { "cursor": cursor }
    }));
    assert_eq!(fetched["isError"], false, "{fetched}");
    assert_eq!(
        fetched["structuredContent"]["result"]["isError"], false,
        "{fetched}"
    );
    assert!(fetched["structuredContent"]["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("xxxxxxxx"));

    let result = gateway.run(
        json!({ "script": "toolport.checkpoint({page:2}); return 'x'.repeat(17 * 1024 * 1024);" }),
    );
    assert_eq!(result["isError"], true, "{result}");
    assert!(result.to_string().contains("IPC limit"), "{result}");
    assert!(!result.to_string().contains("memory budget"), "{result}");
    assert_eq!(
        result["structuredContent"]["toolportScript"]["checkpoint"]["page"],
        2
    );
    gateway.assert_alive();
}

#[test]
fn parent_enforces_saved_routine_deadline_during_pure_js() {
    use conduit_lib::{integrity, routines};
    let wall_clock = Duration::from_secs(5);
    let mut routine_id = String::new();
    let mut gateway = Gateway::configured(
        |reg, dir| {
            mock_registry(reg, dir);
            let fingerprint = integrity::fingerprint(&json!({
                "name": "s__echo", "description": "Echo back the text argument.",
                "inputSchema": { "type": "object", "properties": { "text": { "type": "string" } } }
            }));
            let evidence = routines::PromotionEvidence::new(
                format!("run_{}", "1".repeat(32)),
                1,
                1,
                vec![
                    routines::ObservedDependency::new("s__echo".into(), Some(fingerprint)).unwrap(),
                ],
                routines::RoutineRiskClass::Low,
            )
            .unwrap();
            let definition = routines::new_promoted_definition(
            "Deadline test".into(), None,
            "const result = toolport.call('s__echo', {text:'before'}); if (result.content.length) { toolport.checkpoint({step:1}); while (true) { Math.sin(1); } } return 1;".into(),
            json!({ "type": "object" }),
            routines::RoutineLimits { wall_clock_ms: wall_clock.as_millis() as u64, ..Default::default() },
            evidence,
        ).unwrap();
            routine_id = definition.id().into();
            std::fs::write(
                dir.join("routines.json"),
                serde_json::to_vec(&json!({
                    "schemaVersion": routines::STORE_SCHEMA_VERSION, "routines": [definition]
                }))
                .unwrap(),
            )
            .unwrap();
        },
        false,
    );
    // Cold executable loading and fixture discovery can exceed a short routine
    // budget under Windows ARM's x64 emulation. Warm those paths before timing
    // the pure-JS deadline; each invocation still starts its own worker.
    let warmup = gateway.run(json!({
        "script": "return toolport.call('s__echo', {text:'warmup'});"
    }));
    assert_eq!(warmup["isError"], false, "{warmup}");
    assert_eq!(
        warmup["structuredContent"]["result"]["isError"], false,
        "{warmup}"
    );
    let started = Instant::now();
    let reply = gateway.request(
        "tools/call",
        json!({
            "name": "toolport_run_routine", "arguments": { "id": routine_id, "arguments": {} }
        }),
    );
    let result = &reply["result"];
    assert_eq!(result["isError"], true, "{result}");
    assert_eq!(
        result["structuredContent"]["toolportRoutine"]["error"],
        "code mode worker exceeded its wall-clock deadline",
        "{result}"
    );
    assert_eq!(
        result["structuredContent"]["toolportRoutine"]["checkpoint"]["step"], 1,
        "{result}"
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= wall_clock,
        "deadline fired early after {elapsed:?}"
    );
    assert!(
        elapsed < wall_clock + Duration::from_secs(5),
        "deadline took {elapsed:?}"
    );
    gateway.assert_alive();
}

#[test]
fn http_client_memory_failure_does_not_stop_other_clients_and_scope_stays_enforced() {
    let mut gateway = Gateway::configured(
        |reg, dir| {
            mock_registry(reg, dir);
            reg.profiles.push(
                serde_json::from_value(
                    json!({ "id": "empty", "name": "Empty", "enabledServerIds": [] }),
                )
                .unwrap(),
            );
            for (id, profile) in [("client-a", "Empty"), ("client-b", "Default")] {
                reg.http_clients.push(registry::HttpClient {
                    id: id.into(),
                    label: id.into(),
                    token_sha256: registry::sha256_hex(id),
                    profile: profile.into(),
                });
            }
        },
        true,
    );
    let failure = gateway.http_call("client-a", "toolport_run_script", json!({
        "script": "const buffers = []; for (let i = 0; i < 32; i++) buffers.push(new ArrayBuffer(32 * 1024 * 1024)); return 1;"
    }));
    assert!(failure.to_string().contains("memory budget"), "{failure}");
    assert!(gateway.child.try_wait().unwrap().is_none());
    let status = gateway.http_call("client-b", "toolport_status", json!({}));
    assert!(status.is_string(), "status failed: {status}");
    let scoped = gateway.http_call(
        "client-a",
        "toolport_run_script",
        json!({
            "script": "return toolport.call('s__echo', { text: 'denied' });"
        }),
    );
    assert!(
        scoped.to_string().contains("not available to this client"),
        "{scoped}"
    );
    let normal = gateway.http_call(
        "client-b",
        "toolport_run_script",
        json!({
            "script": "return toolport.call('s__echo', { text: 'allowed' });"
        }),
    );
    assert!(normal.to_string().contains("allowed"), "{normal}");
}
