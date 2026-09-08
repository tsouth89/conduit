//! Framing and wire types for the isolated Code Mode worker.
//!
//! The gateway and the worker communicate over the worker's stdin/stdout. A
//! length-prefixed frame is used instead of newline-delimited JSON so the
//! receiver can reject an oversized payload before allocating its body.

use std::fmt;
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::codemode::{CallRecord, Limits, ScriptOutcome};

mod host_calls;
mod memory;
mod process;

pub use host_calls::HostCalls;
#[cfg(any(unix, windows))]
pub use memory::WorkerAllocator;
pub use process::{run_script, worker_main};

pub const WORKER_ARG: &str = "--code-mode-worker";
pub const MAX_SCRIPT_BYTES: usize = crate::routines::MAX_SOURCE_BYTES;
pub const MAX_VALUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SCHEMA_BYTES: usize = crate::routines::MAX_SCHEMA_BYTES;
pub const MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;

/// Maximum encoded JSON payload in one worker frame.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Frame {
    Start {
        script: String,
        input: Value,
        immutable_input: bool,
        limits: Limits,
        catalog: Vec<String>,
    },
    Call {
        id: u64,
        index: usize,
        name: String,
        args: Value,
    },
    CallResult {
        id: u64,
        result: Value,
    },
    Fetch {
        id: u64,
        args: FetchFrameArgs,
    },
    FetchResult {
        id: u64,
        result: Value,
    },
    Checkpoint {
        value: Value,
    },
    Outcome {
        outcome: ScriptOutcome,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FetchFrameArgs {
    pub cursor: String,
    pub offset: usize,
    pub len: usize,
    pub projection: Option<String>,
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    Oversized { size: usize },
    InvalidJson(serde_json::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "worker pipe I/O error: {error}"),
            Self::Oversized { size } => write!(
                f,
                "worker frame is {size} bytes, over the {MAX_FRAME_BYTES}-byte limit"
            ),
            Self::InvalidJson(error) => write!(f, "worker frame is not valid JSON: {error}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Write one frame as a 4-byte big-endian length followed by its JSON bytes.
pub fn write_frame<W: Write>(writer: &mut W, frame: &Frame) -> Result<(), FrameError> {
    let mut payload = Vec::new();
    let mut bounded = LimitedWriter::new(&mut payload, MAX_FRAME_BYTES);
    if let Err(error) = serde_json::to_writer(&mut bounded, frame) {
        return Err(if bounded.exceeded {
            FrameError::Oversized {
                size: MAX_FRAME_BYTES + 1,
            }
        } else {
            FrameError::InvalidJson(error)
        });
    }
    let size = u32::try_from(payload.len()).map_err(|_| FrameError::Oversized {
        size: payload.len(),
    })?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read one frame. The body allocation happens only after the checked length
/// prefix has been received. A clean EOF before a new prefix is represented by
/// `Ok(None)`; a truncated prefix/body is an error.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<Frame>, FrameError> {
    let mut header = [0u8; 4];
    let first = loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break 1,
            Ok(_) => unreachable!("a one-byte read cannot return more than one byte"),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(FrameError::Io(error)),
        }
    };
    reader.read_exact(&mut header[first..])?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > MAX_FRAME_BYTES {
        return Err(FrameError::Oversized { size });
    }
    let mut payload = vec![0u8; size];
    reader.read_exact(&mut payload)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(FrameError::InvalidJson)
}

/// Construct an outcome when the parent detects that the worker disappeared
/// before it could send a normal result.
pub fn terminated_outcome(
    calls: usize,
    progress: Vec<CallRecord>,
    reason: String,
) -> ScriptOutcome {
    ScriptOutcome {
        value: Value::Null,
        calls,
        progress,
        final_result_bytes: 0,
        checkpoint: None,
        error: Some(reason),
    }
}

struct LimitedWriter<W> {
    inner: W,
    limit: usize,
    written: usize,
    exceeded: bool,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: usize) -> Self {
        Self {
            inner,
            limit,
            written: 0,
            exceeded: false,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.written) {
            self.exceeded = true;
            return Err(io::Error::other("code mode byte limit exceeded"));
        }
        let count = self.inner.write(bytes)?;
        self.written += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Count encoded bytes without making an additional, potentially unbounded copy.
pub fn json_size(value: &impl Serialize, limit: usize) -> Option<usize> {
    let mut writer = LimitedWriter::new(io::sink(), limit);
    serde_json::to_writer(&mut writer, value).ok()?;
    Some(writer.written)
}

pub fn check_input(script: &str, input: &crate::codemode::ScriptInput) -> Result<(), String> {
    if script.len() > MAX_SCRIPT_BYTES {
        return Err(format!(
            "code mode script exceeds the {MAX_SCRIPT_BYTES}-byte source limit"
        ));
    }
    let (name, value) = match input {
        crate::codemode::ScriptInput::Data(value) => ("data", value),
        crate::codemode::ScriptInput::ImmutableInput(value) => ("input", value),
    };
    if json_size(value, MAX_VALUE_BYTES).is_none() {
        return Err(format!(
            "code mode {name} exceeds the {MAX_VALUE_BYTES}-byte value limit"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_round_trip() {
        let frame = Frame::Call {
            id: 7,
            index: 0,
            name: "server__tool".to_string(),
            args: serde_json::json!({ "value": 1 }),
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("write frame");
        let decoded = read_frame(&mut Cursor::new(bytes))
            .expect("read frame")
            .expect("frame");
        match decoded {
            Frame::Call { id, name, .. } => {
                assert_eq!(id, 7);
                assert_eq!(name, "server__tool");
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn oversized_prefix_is_rejected_before_body_read() {
        let size = (MAX_FRAME_BYTES as u32).saturating_add(1);
        let mut reader = Cursor::new(size.to_be_bytes().to_vec());
        let error = read_frame(&mut reader).expect_err("oversized frame must fail");
        assert!(matches!(error, FrameError::Oversized { .. }));
        assert_eq!(reader.position(), 4, "body must not be read or allocated");
    }

    #[test]
    fn truncated_body_is_an_error() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u32.to_be_bytes());
        bytes.extend_from_slice(b"{}");
        let error = read_frame(&mut Cursor::new(bytes)).expect_err("truncated frame");
        assert!(matches!(error, FrameError::Io(_)));
    }

    #[test]
    fn oversized_write_leaves_the_pipe_untouched() {
        let frame = Frame::CallResult {
            id: 1,
            result: Value::String("x".repeat(MAX_FRAME_BYTES)),
        };
        let mut bytes = Vec::new();
        assert!(matches!(
            write_frame(&mut bytes, &frame),
            Err(FrameError::Oversized { .. })
        ));
        assert!(
            bytes.is_empty(),
            "a rejected payload must not leave a partial frame"
        );
    }

    #[test]
    fn json_size_counts_encoded_bytes_and_stops_at_the_limit() {
        let value = serde_json::json!({ "text": "\"\\\n" });
        let size = serde_json::to_vec(&value).unwrap().len();
        assert_eq!(json_size(&value, size), Some(size));
        assert_eq!(json_size(&value, size - 1), None);
    }
}
