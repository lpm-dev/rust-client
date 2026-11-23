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

/// The codes and input limits of one family of functions. An output frame
/// carries as many blobs as it needs.
pub(crate) struct Domain {
    pub(crate) invalid_input: &'static str,
    pub(crate) serialization: &'static str,
    pub(crate) panic: &'static str,
    pub(crate) input_limit: usize,
    /// The most blobs an input frame carries.
    pub(crate) input_blobs: usize,
}

/// A decoded input frame: the request and its blobs.
pub(crate) struct Frame<'a> {
    pub(crate) request: &'a [u8],
    pub(crate) blobs: Vec<&'a [u8]>,
}

/// The frame `bytes` hold, with at most `max_blobs` blobs.
pub(crate) fn decode_frame(bytes: &[u8], max_blobs: usize) -> Option<Frame<'_>> {
    let rest = bytes.strip_prefix(&FRAME_MAGIC)?;
    let (&version, rest) = rest.split_first()?;
    if version != FRAME_VERSION {
        return None;
    }
    let (count, mut rest) = rest.split_first_chunk::<4>()?;
    let count = u32::from_be_bytes(*count) as usize;
    if count == 0 || count - 1 > max_blobs || count > rest.len() / 4 + 1 {
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
    refused_with(code, message, serde_json::Map::new())
}

/// A refusal that also names what it's about, such as an edit and its key,
/// never a value.
pub(crate) fn refused_with(
    code: &str,
    message: Option<String>,
    details: serde_json::Map<String, serde_json::Value>,
) -> LPMEnvResult {
    let mut output = json!({ "abiVersion": ABI_VERSION, "code": code });
    if let Some(message) = message {
        output["message"] = json!(message);
    }
    if let Some(fields) = output.as_object_mut() {
        fields.extend(details);
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
        let Some(frame) = decode_frame(raw, domain.input_blobs) else {
            return failure(2, domain.invalid_input);
        };
        let Ok(request) = serde_json::from_slice::<R>(frame.request) else {
            return failure(2, domain.invalid_input);
        };
        handle(request, &frame.blobs)
    }))
    .unwrap_or_else(|_| failure(3, domain.panic))
}

/// A JSON object decoded as `T`, refusing the array that serde's derived
/// structs also take: an input's shapes are objects with named fields.
pub(crate) struct Object<T>(pub(crate) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Object<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Fields<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>> serde::de::Visitor<'de> for Fields<T> {
            type Value = T;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(serde::de::value::MapAccessDeserializer::new(map))
            }
        }

        deserializer
            .deserialize_map(Fields(std::marker::PhantomData))
            .map(Self)
    }
}

/// An optional field, which is left out when absent: given, it holds a
/// value, never `null`.
pub(crate) fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

/// The blob `index` names, counted from 1 as requests name them.
pub(crate) fn blob<'a>(blobs: &[&'a [u8]], index: usize) -> Option<&'a [u8]> {
    index
        .checked_sub(1)
        .and_then(|index| blobs.get(index))
        .copied()
}
