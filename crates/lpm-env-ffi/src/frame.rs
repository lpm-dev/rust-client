//! The binary frame functions that carry secrets use, in both directions:
//!
//! ```text
//! frame = "LPMF" ‖ u8 version=1 ‖ u32be count ‖ count × (u32be length ‖ bytes)
//! ```
//!
//! Field 0 is a UTF-8 JSON object of everything that isn't secret. The other
//! fields are blobs the JSON names by index from 1: stored records, values,
//! records to write. Secrets never appear in JSON, and every output buffer
//! is wiped when it's released.

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{ABI_VERSION, LPMEnvResult, bytes, failure, result};

pub(crate) const FRAME_MAGIC: [u8; 4] = *b"LPMF";
pub(crate) const FRAME_VERSION: u8 = 1;
const REFUSED: u32 = 5;

/// The most blobs a frame carries: every input names far fewer (a history
/// reading names the head, the key, the values and at most 16 parts).
const MAX_FRAME_BLOBS: usize = 64;

/// The codes and input limit of one family of functions.
pub(crate) struct Domain {
    pub(crate) invalid_input: &'static str,
    pub(crate) serialization: &'static str,
    pub(crate) panic: &'static str,
    pub(crate) input_limit: usize,
}

/// A decoded input frame: the request and its blobs.
pub(crate) struct Frame<'a> {
    pub(crate) request: &'a [u8],
    pub(crate) blobs: Vec<&'a [u8]>,
}

pub(crate) fn decode_frame(bytes: &[u8]) -> Option<Frame<'_>> {
    let rest = bytes.strip_prefix(&FRAME_MAGIC)?;
    let (&version, rest) = rest.split_first()?;
    if version != FRAME_VERSION {
        return None;
    }
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    if count == 0 || count > MAX_FRAME_BLOBS + 1 || count > rest.len() / 4 + 1 {
        return None;
    }
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let (length, after) = rest.split_first_chunk::<4>()?;
        let length = u32::from_be_bytes(*length) as usize;
        if length > after.len() {
            return None;
        }
        let (field, after) = after.split_at(length);
        fields.push(field);
        rest = after;
    }
    if !rest.is_empty() {
        return None;
    }
    let request = fields.remove(0);
    Some(Frame {
        request,
        blobs: fields,
    })
}

/// An output frame being built: the response and its blobs, which are
/// wiped when dropped.
pub(crate) struct Output {
    blobs: Vec<Zeroizing<Vec<u8>>>,
    serialization: &'static str,
}

impl Output {
    pub(crate) fn new(serialization: &'static str) -> Self {
        Self {
            blobs: Vec::new(),
            serialization,
        }
    }

    pub(crate) fn blob(&mut self, bytes: impl Into<Vec<u8>>) -> usize {
        self.blobs.push(Zeroizing::new(bytes.into()));
        self.blobs.len()
    }

    /// A secret value as a blob, moved out of the wiped buffer that held it.
    pub(crate) fn secret(&mut self, mut value: Zeroizing<String>) -> usize {
        self.blob(std::mem::take(&mut *value).into_bytes())
    }

    /// The output frame: `response` with the ABI version, serialized once,
    /// then every blob, in a buffer sized exactly.
    pub(crate) fn finish(self, response: &impl Serialize) -> LPMEnvResult {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Framed<'r, R> {
            #[serde(flatten)]
            response: &'r R,
            abi_version: u32,
        }
        /// Counts what a serialization writes, so the frame is sized once.
        struct Counted(usize);
        impl std::io::Write for Counted {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 += bytes.len();
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let framed = Framed {
            response,
            abi_version: ABI_VERSION,
        };
        // Serializing twice costs less than holding the JSON twice: the
        // frame is written once, at its exact size.
        let mut counted = Counted(0);
        if serde_json::to_writer(&mut counted, &framed).is_err() {
            return failure(3, self.serialization);
        }
        let request_len = counted.0;
        let total = 4
            + 1
            + 4
            + 4
            + request_len
            + self.blobs.iter().map(|blob| 4 + blob.len()).sum::<usize>();
        let mut frame = Vec::with_capacity(total);
        frame.extend_from_slice(&FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.extend_from_slice(&((self.blobs.len() + 1) as u32).to_be_bytes());
        frame.extend_from_slice(&(request_len as u32).to_be_bytes());
        if serde_json::to_writer(&mut frame, &framed).is_err() {
            return failure(3, self.serialization);
        }
        for blob in &self.blobs {
            frame.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            frame.extend_from_slice(blob);
        }
        debug_assert_eq!(frame.len(), total);
        result(0, frame, None)
    }
}

pub(crate) fn refused(code: &str, message: Option<String>) -> LPMEnvResult {
    let mut output = json!({ "abiVersion": ABI_VERSION, "code": code });
    if let Some(message) = message {
        output["message"] = json!(message);
    }
    result(
        REFUSED,
        serde_json::to_vec(&output).unwrap_or_default(),
        None,
    )
}

/// Run `handle` on a decoded frame and its parsed request, catching panics.
///
/// # Safety
/// `input` must reference `length` readable bytes during the call.
pub(crate) unsafe fn respond<R: for<'de> Deserialize<'de>>(
    domain: &Domain,
    input: *const u8,
    length: usize,
    handle: impl FnOnce(R, &[&[u8]]) -> LPMEnvResult,
) -> LPMEnvResult {
    if length > domain.input_limit {
        return failure(2, domain.invalid_input);
    }
    // SAFETY: Forwarded from this function's contract; the length is bounded above.
    let Some(raw) = (unsafe { bytes(input, length) }) else {
        return failure(2, domain.invalid_input);
    };
    catch_unwind(AssertUnwindSafe(|| {
        let Some(frame) = decode_frame(raw) else {
            return failure(2, domain.invalid_input);
        };
        let Ok(request) = serde_json::from_slice::<R>(frame.request) else {
            return failure(2, domain.invalid_input);
        };
        handle(request, &frame.blobs)
    }))
    .unwrap_or_else(|_| failure(3, domain.panic))
}

/// The blob `index` names, counted from 1 as requests name them.
pub(crate) fn blob<'a>(blobs: &[&'a [u8]], index: usize) -> Option<&'a [u8]> {
    index
        .checked_sub(1)
        .and_then(|index| blobs.get(index))
        .copied()
}
