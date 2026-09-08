use std::collections::HashMap;
use std::io::{BufReader, BufWriter};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::{memory, FetchFrameArgs, Frame};
use crate::codemode::{
    self, CallBinding, CallRecord, FetchBinding, Limits, ScriptInput, ScriptOutcome,
};
use crate::downstream::CancelContext;

const MAX_WORKERS: usize = 4;
static WORKERS: AtomicUsize = AtomicUsize::new(0);

struct RunPermit;

impl RunPermit {
    fn acquire() -> Option<Arc<Self>> {
        WORKERS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < MAX_WORKERS).then_some(count + 1)
            })
            .ok()
            .map(|_| Arc::new(Self))
    }
}

impl Drop for RunPermit {
    fn drop(&mut self) {
        WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

enum Event {
    Frame(Frame),
    PipeClosed(String),
    Failure(String),
    HostReply(Frame),
}

fn pipe_error(error: super::FrameError) -> Event {
    match error {
        super::FrameError::Io(_) => Event::PipeClosed(error.to_string()),
        _ => Event::Failure(error.to_string()),
    }
}

fn exit_reason(child: &mut Child) -> String {
    // Windows can close the pipes hundreds of milliseconds before signaling
    // the process handle. Give the dedicated memory exit code time to become
    // observable, while keeping even a broken worker's cleanup bounded.
    let grace = if cfg!(windows) {
        Duration::from_secs(1)
    } else {
        Duration::from_millis(25)
    };
    let until = Instant::now() + grace;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if memory::is_memory_termination(&status) => {
                return format!(
                    "code mode script exceeded its memory budget ({} MiB)",
                    super::MEMORY_LIMIT_BYTES / (1024 * 1024)
                );
            }
            Ok(Some(status)) => {
                return format!("code mode worker terminated before returning a result ({status})")
            }
            _ if Instant::now() >= until => {
                return "code mode worker pipe closed before returning a result".into()
            }
            _ => std::thread::sleep(Duration::from_millis(1)),
        }
    }
}

fn error_result(error: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": error }], "isError": true })
}

/// Only the parent owns host bindings. Every script, including dry runs and
/// routines, uses the same process boundary and bounded pipe queues.
#[allow(clippy::too_many_arguments)]
pub fn run_script(
    script: &str,
    input: ScriptInput,
    call: CallBinding,
    fetch: Option<FetchBinding>,
    limits: Limits,
    catalog: &[String],
    cancel: Option<CancelContext>,
    host_calls: super::HostCalls,
) -> ScriptOutcome {
    let fail = |error| super::terminated_outcome(0, Vec::new(), error);
    if let Err(error) = super::check_input(script, &input) {
        return fail(error);
    }
    let Some(permit) = RunPermit::acquire() else {
        return fail(format!("code mode concurrent worker limit reached ({MAX_WORKERS}); retry after a running script finishes"));
    };
    let deadline = Instant::now() + limits.wall_clock;
    let (value, immutable_input) = match input {
        ScriptInput::Data(value) => (value, false),
        ScriptInput::ImmutableInput(value) => (value, true),
    };
    let start = Frame::Start {
        script: script.to_string(),
        input: value,
        immutable_input,
        limits,
        catalog: catalog.to_vec(),
    };
    if super::json_size(&start, super::MAX_FRAME_BYTES).is_none() {
        return fail("code mode start payload exceeds the IPC frame limit".into());
    }
    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return fail(format!("code mode worker executable unavailable: {error}")),
    };
    let mut command = Command::new(executable);
    command
        .arg(super::WORKER_ARG)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Err(error) = memory::configure(&mut command) {
        return fail(format!("code mode memory limit setup failed: {error}"));
    }
    let mut child = match command.spawn() {
        Ok(child) => ChildGuard(child),
        Err(error) => {
            return fail(format!(
                "code mode worker could not start with its memory budget: {error}"
            ))
        }
    };
    let _job = match memory::Job::attach(&child.0) {
        Ok(job) => job,
        Err(error) => {
            return fail(format!(
                "code mode worker memory limit setup failed: {error}"
            ))
        }
    };
    let stdin = child.0.stdin.take().expect("piped worker stdin");
    let stdout = child.0.stdout.take().expect("piped worker stdout");
    // One received frame at a time; host fan-out and outgoing responses are
    // separately bounded. No pipe operation runs on the deadline supervisor.
    let (events, incoming) = mpsc::sync_channel(1);
    let (outgoing, responses) = mpsc::sync_channel(limits.max_parallel.max(1) + 1);
    let read_events = events.clone();
    let reader = match std::thread::Builder::new()
        .name("code-mode-read".into())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let event = match super::read_frame(&mut reader) {
                    Ok(Some(frame)) => Event::Frame(frame),
                    Ok(None) => Event::PipeClosed("worker pipe closed without an outcome".into()),
                    Err(error) => pipe_error(error),
                };
                let failed = matches!(event, Event::Failure(_) | Event::PipeClosed(_));
                if read_events.send(event).is_err() || failed {
                    break;
                }
            }
        }) {
        Ok(thread) => thread,
        Err(error) => return fail(format!("code mode reader could not start: {error}")),
    };
    let write_events = events.clone();
    let writer = match std::thread::Builder::new()
        .name("code-mode-write".into())
        .spawn(move || {
            let mut writer = BufWriter::new(stdin);
            for frame in std::iter::once(start).chain(responses) {
                if let Err(error) = super::write_frame(&mut writer, &frame) {
                    let _ = write_events.send(pipe_error(error));
                    break;
                }
            }
        }) {
        Ok(thread) => thread,
        Err(error) => return fail(format!("code mode writer could not start: {error}")),
    };

    let progress = Arc::new(Mutex::new(Vec::<CallRecord>::new()));
    let mut calls = 0;
    let mut inflight = 0;
    let mut seen_ids = std::collections::HashSet::new();
    let mut seen_indices = std::collections::HashSet::new();
    let mut checkpoint = None;
    let result = loop {
        if cancel.as_ref().is_some_and(CancelContext::is_cancelled) {
            break Err("code mode script was cancelled".to_string());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err("code mode worker exceeded its wall-clock deadline".to_string());
        }
        let event = match incoming.recv_timeout(remaining.min(Duration::from_millis(25))) {
            Ok(event) => event,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err("code mode worker IPC disconnected".to_string())
            }
        };
        match event {
            Event::PipeClosed(error) => {
                break Err(format!("{}: {error}", exit_reason(&mut child.0)));
            }
            Event::Failure(error) => break Err(error),
            Event::HostReply(frame) => {
                inflight -= 1;
                if outgoing.try_send(frame).is_err() {
                    break Err(
                        "code mode response pipe exceeded its queue limit or disconnected"
                            .to_string(),
                    );
                }
            }
            Event::Frame(Frame::Outcome { outcome }) => {
                if inflight != 0 {
                    break Err(
                        "code mode worker returned with host calls still pending".to_string()
                    );
                }
                break Ok(outcome);
            }
            Event::Frame(Frame::Checkpoint { value }) => {
                if super::json_size(&value, codemode::MAX_CHECKPOINT_BYTES).is_none() {
                    break Err("code mode checkpoint exceeded its byte limit".to_string());
                }
                checkpoint = Some(value);
            }
            Event::Frame(frame @ (Frame::Call { .. } | Frame::Fetch { .. })) => {
                let id = match &frame {
                    Frame::Call { id, .. } | Frame::Fetch { id, .. } => *id,
                    _ => unreachable!(),
                };
                if calls >= limits.max_calls || !seen_ids.insert(id) {
                    break Err(
                        "code mode worker exceeded its call budget or reused a request id"
                            .to_string(),
                    );
                }
                if inflight >= limits.max_parallel.max(1) {
                    break Err(
                        "code mode worker exceeded its host-call parallelism limit".to_string()
                    );
                }
                if super::json_size(&frame, super::MAX_VALUE_BYTES).is_none() {
                    break Err("code mode host arguments exceed the value limit".to_string());
                }
                calls += 1;
                inflight += 1;
                if let Frame::Call { index, .. } = &frame {
                    if *index >= limits.max_calls || !seen_indices.insert(*index) {
                        break Err("code mode worker sent an invalid call position".to_string());
                    }
                }
                let call = Arc::clone(&call);
                let fetch = fetch.clone();
                let progress = Arc::clone(&progress);
                let events = events.clone();
                let permit = Arc::clone(&permit);
                let spawned = std::thread::Builder::new()
                    .name("code-mode-host".into())
                    .spawn(move || {
                        // A timed-out binding retains its permit until it drains, so
                        // repeated failures cannot accumulate unlimited host threads.
                        let _permit = permit;
                        let (name, result) = match frame {
                            Frame::Call {
                                index, name, args, ..
                            } => {
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                        call(&name, args)
                                    }))
                                    .unwrap_or_else(|_| {
                                        error_result("code mode host call panicked")
                                    });
                                (Some((index, name)), result)
                            }
                            Frame::Fetch { args, .. } => {
                                let run = || match fetch {
                                    Some(fetch) => fetch(codemode::FetchArgs {
                                        cursor: args.cursor,
                                        offset: args.offset,
                                        len: args.len,
                                        projection: args.projection,
                                    }),
                                    None => error_result(
                                        "toolport.fetchResult is unavailable in this context",
                                    ),
                                };
                                let result =
                                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(run))
                                        .unwrap_or_else(|_| {
                                            error_result("code mode fetchResult panicked")
                                        });
                                (None, result)
                            }
                            _ => unreachable!(),
                        };
                        let result_bytes = super::json_size(&result, super::MAX_FRAME_BYTES);
                        let is_call = name.is_some();
                        if let Some((index, name)) = name {
                            progress
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .push(CallRecord {
                                    index,
                                    name,
                                    ok: !result
                                        .get("isError")
                                        .and_then(Value::as_bool)
                                        .unwrap_or(false),
                                    result_bytes: result_bytes
                                        .unwrap_or(super::MAX_FRAME_BYTES + 1),
                                });
                        }
                        let reply = if is_call {
                            Frame::CallResult { id, result }
                        } else {
                            Frame::FetchResult { id, result }
                        };
                        let event = if result_bytes.is_none()
                            || super::json_size(&reply, super::MAX_FRAME_BYTES).is_none()
                        {
                            Event::Failure(
                                "host result exceeded the code mode IPC frame limit".into(),
                            )
                        } else {
                            Event::HostReply(reply)
                        };
                        let _ = events.send(event);
                    });
                if let Err(error) = spawned {
                    break Err(format!("code mode host worker could not start: {error}"));
                }
            }
            Event::Frame(_) => break Err("code mode worker sent an unexpected frame".to_string()),
        }
    };

    host_calls.stop();
    // Closing the bounded queues first releases senders, then killing the child
    // releases blocked pipe I/O. Already dispatched host bindings retain their
    // permit until they drain, and are never joined without a deadline.
    drop(incoming);
    drop(outgoing);
    let _ = child.0.kill();
    let _ = child.0.wait();
    let _ = reader.join();
    let _ = writer.join();
    let mut records = progress
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    records.sort_by_key(|record| record.index);
    match result {
        Ok(mut outcome) => {
            // Boa also counts callAsync entries queued before an early JS error.
            outcome.calls = outcome.calls.max(calls).min(limits.max_calls);
            outcome.progress = records;
            outcome.checkpoint = checkpoint;
            outcome
        }
        Err(mut error) => {
            if inflight != 0 {
                error.push_str("; host calls may still be in flight, cancellation requested; do not automatically retry them");
            }
            let mut outcome = super::terminated_outcome(calls, records, error);
            outcome.checkpoint = checkpoint;
            outcome
        }
    }
}

#[derive(Default)]
struct Pending {
    senders: HashMap<u64, mpsc::Sender<Result<Value, String>>>,
    error: Option<String>,
}

#[derive(Clone)]
struct WorkerClient {
    writer: Arc<Mutex<BufWriter<std::io::Stdout>>>,
    pending: Arc<Mutex<Pending>>,
    next_id: Arc<AtomicU64>,
    deadline: Instant,
}

impl WorkerClient {
    fn new(mut reader: BufReader<std::io::Stdin>, deadline: Instant) -> Self {
        let pending = Arc::new(Mutex::new(Pending::default()));
        let replies = Arc::clone(&pending);
        std::thread::spawn(move || {
            let error = loop {
                match super::read_frame(&mut reader) {
                    Ok(Some(
                        Frame::CallResult { id, result } | Frame::FetchResult { id, result },
                    )) => {
                        let sender = replies
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .senders
                            .remove(&id);
                        if let Some(sender) = sender {
                            let _ = sender.send(Ok(result));
                        } else {
                            break "code mode parent returned an unknown request id".to_string();
                        }
                    }
                    Ok(None) => {
                        // The parent disappeared. Pure JS must not outlive it.
                        std::process::exit(0);
                    }
                    Ok(Some(_)) => {
                        break "code mode parent sent an unexpected response".to_string()
                    }
                    Err(error) => break format!("code mode parent response was invalid: {error}"),
                }
            };
            let mut pending = replies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.error = Some(error.clone());
            for (_, sender) in pending.senders.drain() {
                let _ = sender.send(Err(error.clone()));
            }
        });
        Self {
            writer: Arc::new(Mutex::new(BufWriter::new(std::io::stdout()))),
            pending,
            next_id: Arc::new(AtomicU64::new(0)),
            deadline,
        }
    }

    fn request(&self, frame: Frame, id: u64) -> Value {
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(error) = &pending.error {
                return error_result(error);
            }
            pending.senders.insert(id, sender);
        }
        let sent = super::write_frame(
            &mut *self
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &frame,
        );
        let result = match sent {
            Ok(()) => receiver
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                .unwrap_or_else(|_| {
                    Err("code mode parent did not answer before the deadline".into())
                }),
            Err(error) => Err(format!("code mode host request failed: {error}")),
        };
        match result {
            Ok(value) => value,
            Err(error) => {
                let mut pending = self
                    .pending
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                pending.senders.remove(&id);
                pending.error = Some(error.clone());
                error_result(&error)
            }
        }
    }
}

/// Internal entry point, before registry, router, keychain, or listeners exist.
pub fn worker_main() -> ! {
    memory::enable_worker_limit();
    let mut reader = BufReader::new(std::io::stdin());
    let (script, input, immutable, limits, catalog) = match super::read_frame(&mut reader) {
        Ok(Some(Frame::Start {
            script,
            input,
            immutable_input,
            limits,
            catalog,
        })) => (script, input, immutable_input, limits, catalog),
        _ => std::process::exit(1),
    };
    let client = WorkerClient::new(reader, Instant::now() + limits.wall_clock);
    let call_client = client.clone();
    let call: codemode::IndexedCallBinding = Arc::new(move |index, name, args| {
        let id = call_client.next_id.fetch_add(1, Ordering::Relaxed);
        call_client.request(
            Frame::Call {
                id,
                index,
                name: name.into(),
                args,
            },
            id,
        )
    });
    let fetch_client = client.clone();
    let fetch: FetchBinding = Arc::new(move |args| {
        let id = fetch_client.next_id.fetch_add(1, Ordering::Relaxed);
        fetch_client.request(
            Frame::Fetch {
                id,
                args: FetchFrameArgs {
                    cursor: args.cursor,
                    offset: args.offset,
                    len: args.len,
                    projection: args.projection,
                },
            },
            id,
        )
    });
    let input = if immutable {
        ScriptInput::ImmutableInput(input)
    } else {
        ScriptInput::Data(input)
    };
    let checkpoint_client = client.clone();
    let checkpoint: codemode::CheckpointBinding = Arc::new(move |value| {
        super::write_frame(
            &mut *checkpoint_client
                .writer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            &Frame::Checkpoint {
                value: value.clone(),
            },
        )
        .map_err(|error| error.to_string())
    });
    let mut outcome = codemode::run_script_indexed(
        &script,
        input,
        call,
        Some(fetch),
        limits,
        &catalog,
        Some(checkpoint),
    );
    if let Some(error) = client
        .pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .error
        .clone()
    {
        outcome.error = Some(error);
    }
    let mut writer = client
        .writer
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Err(error) = super::write_frame(&mut *writer, &Frame::Outcome { outcome }) {
        let outcome = super::terminated_outcome(
            0,
            Vec::new(),
            format!("code mode final result exceeded the IPC limit or could not be sent: {error}"),
        );
        let _ = super::write_frame(&mut *writer, &Frame::Outcome { outcome });
    }
    std::process::exit(0);
}
