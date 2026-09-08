# Configuration

Lazy discovery, the destructive-tool block, and agent control are global settings,
stored in the registry and toggled in the app's Settings view, so they apply to every
client (lazy discovery is on by default). Per-client behavior is set via env vars on the
gateway entry, written for you when you connect a client:

- `TOOLPORT_CLIENT_ID=<id>` - identifies this client for live profile resolution
  (written automatically when you Connect a client).
- `TOOLPORT_PROFILE=<name>` - initial profile scope for a scoped install. Unset =
  follow the active profile (resolved live via `TOOLPORT_CLIENT_ID`).
- `TOOLPORT_DISCOVERY=lazy|full|grouped` - optional per-client override of the global
  discovery setting. Rarely needed; the gateway reads the registry default otherwise.
- `TOOLPORT_REGISTRY=<path>` - override the registry file location. Defaults to a
  stable per-user path so packaged and unpackaged clients agree.
- `TOOLPORT_DATA_DIR=<path>` - override the full Toolport data directory.
- `TOOLPORT_RESULT_BUDGET=<bytes>` - cap oversized tool results at this many bytes
  (0 disables it). Optional; default budget applies when unset.
- `TOOLPORT_HTTP=<port>` (with optional `TOOLPORT_HTTP_HOST`, default `127.0.0.1`,
  and `TOOLPORT_HTTP_TOKEN` for the required bearer token) - run the gateway in
  HTTP/OpenAPI mode instead of stdio, for Open WebUI and other OpenAPI clients (see [Open WebUI](openwebui.md)). The in-app Settings -> Integrations toggle sets these for you, and the
  gateway refuses to bind without a token or registered HTTP client. For isolated
  local development only, `--insecure-loopback` explicitly permits an unauthenticated
  loopback listener; it never permits an open non-loopback bind.
- `TOOLPORT_METRICS=1` - opt-in Prometheus `GET /metrics` on the HTTP surface.
- `TOOLPORT_DEBUG=1` - per-request gateway trace logging.
- `TOOLPORT_CODE_MODE=1` - force-enable code mode (`toolport_run_script`) even if Settings
  has it off. Code mode is **on by default** (Settings kill switch turns it off). Each
  in-script tool call still respects profile scope and human approval; code mode is not a
  security boundary.

Every `TOOLPORT_*` name still accepts the pre-rename `CONDUIT_*` alias (for example
`CONDUIT_HTTP_TOKEN` continues to work). Prefer `TOOLPORT_*` in new configs.

**Code mode limits.** Execution, validation, and saved routines run Boa in a separate
worker process. The parent enforces the 60-second wall-clock budget even during pure
JavaScript and permits at most four simultaneous runs. Saved routines can set lower
execution limits. Each worker has a 512 MiB allocation budget: Linux uses `RLIMIT_AS`
before exec, Windows assigns the suspended child to a memory-limited Job Object, and
macOS uses a worker-only Rust allocator cap because Darwin's `RLIMIT_AS` is advisory.
The macOS cap covers Boa's Rust heap, not the process's total resident memory. Allocation
refusal terminates the worker and returns a script error; the gateway stays available.
On all supported platforms, a worker allocation guard uses a dedicated exit code even
for fallible buffer allocations. Memory-budget audit attribution comes from the
worker's exit status, not error text thrown by JavaScript.

Source is capped at 256 KiB, `data` or `input` at 4 MiB of JSON, and `inputSchema` at
64 KiB on both stdio and HTTP. HTTP's 4 MiB whole-request cap still applies. Worker
messages, including host results and the final aggregate, are capped at 16 MiB per
frame. Oversized messages fail explicitly. Host calls still run through the parent's
scope, approval, content-defense, and rate-limit checks. On failure, completed calls
and the last checkpoint remain available; calls already in flight are cancelled where
supported and must not be automatically retried.

**Semantic search (optional).** Lazy discovery ranks tools lexically by default. Point it
at any `/v1/embeddings` endpoint (LM Studio, Ollama, or a cloud provider) to blend in
embedding similarity for paraphrased queries: `TOOLPORT_SEMANTIC=on`,
`TOOLPORT_EMBED_ENDPOINT`, `TOOLPORT_EMBED_MODEL`, plus optional `TOOLPORT_EMBED_KEY`
(endpoint auth) and `TOOLPORT_EMBED_BLEND`.

**Multiple accounts for the same service.** Credentials belong to a server, not a
profile. To use, say, a work and a personal GitHub, add GitHub twice as two
servers ("GitHub (work)", "GitHub (personal)"), authenticate each with its own
account, and enable one in each profile. A client scoped to the work profile
(`TOOLPORT_PROFILE`) then only ever sees the work account. Tool names are
namespaced per server, so the two never collide even in the same profile.
