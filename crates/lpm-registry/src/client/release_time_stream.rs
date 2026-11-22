//! Streaming JSON extractor for [`ReleaseTimeMetadata`].
//!
//! Full npm packuments (`Accept: application/json`) routinely reach 5–20 MiB
//! uncompressed (`typescript` ~15 MiB, `react-dom` ~9 MiB), yet release-time
//! and platform policy checks only need top-level `name`, `time`, and sparse
//! `versions.<ver>.{os,cpu,libc}`. Scanning directly over `response.chunk()`
//! keeps peak memory near the size of the `time` map (~10–200 KiB) instead of
//! buffering the entire packument in RAM and walking thousands of ignored
//! version fields through serde.

use super::body::MetadataBodyTimings;
use crate::types::{ReleaseTimeMetadata, ReleaseTimeVersionMetadata};
use lpm_common::LpmError;
use std::collections::HashMap;

const MAX_KEY_CAPTURE_BYTES: usize = 64;
const MAX_NAME_CAPTURE_BYTES: usize = 8 * 1024;
const MAX_PLATFORM_FIELD_CAPTURE_BYTES: usize = 64 * 1024;

#[derive(serde::Deserialize)]
struct PlatformFieldValue(
    #[serde(deserialize_with = "crate::types::deserialize_string_or_string_list")] Vec<String>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TopField {
    Name,
    Time,
    Versions,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VersionField {
    Os,
    Cpu,
    Libc,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureTarget {
    TopName,
    TopTime,
    VersionOs,
    VersionCpu,
    VersionLibc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReturnLevel {
    TopAfterValue,
    VersionAfterValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyContext {
    Top,
    Versions,
    Version,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Start,
    TopExpectKeyOrEnd,
    TopExpectKey,
    TopAfterKey,
    TopExpectValue(TopField),
    TopAfterValue,
    VersionsExpectKeyOrEnd,
    VersionsExpectKey,
    VersionsAfterKey,
    VersionsExpectObjStart,
    VersionsAfterValue,
    VersionExpectKeyOrEnd,
    VersionExpectKey,
    VersionAfterKey,
    VersionExpectValue(VersionField),
    VersionAfterValue,
    ReadKey {
        ctx: KeyContext,
        in_escape: bool,
    },
    SkipNull {
        remaining: u8,
        ret: ReturnLevel,
    },
    SkipValueStart {
        ret: ReturnLevel,
    },
    SkipString {
        in_escape: bool,
        ret: ReturnLevel,
    },
    SkipContainer {
        depth: usize,
        in_string: bool,
        in_escape: bool,
        ret: ReturnLevel,
    },
    SkipPrimitive {
        ret: ReturnLevel,
    },
    CaptureValueStart {
        target: CaptureTarget,
        ret: ReturnLevel,
        cap: usize,
    },
    CaptureString {
        target: CaptureTarget,
        in_escape: bool,
        ret: ReturnLevel,
        cap: usize,
    },
    CaptureContainer {
        target: CaptureTarget,
        depth: usize,
        in_string: bool,
        in_escape: bool,
        ret: ReturnLevel,
        cap: usize,
    },
    CapturePrimitive {
        target: CaptureTarget,
        ret: ReturnLevel,
        cap: usize,
    },
    Done,
}

pub(super) struct ReleaseTimeStreamParser {
    state: State,
    bom_checked: bool,
    bom_buf: [u8; 3],
    bom_len: usize,
    key_buf: Vec<u8>,
    key_overflow: bool,
    version_key_buf: Vec<u8>,
    capture_buf: Vec<u8>,
    name: Option<String>,
    time: HashMap<String, String>,
    versions: Option<HashMap<String, ReleaseTimeVersionMetadata>>,
    cur_platform: ReleaseTimeVersionMetadata,
}

impl ReleaseTimeStreamParser {
    pub(super) fn new() -> Self {
        Self {
            state: State::Start,
            bom_checked: false,
            bom_buf: [0; 3],
            bom_len: 0,
            key_buf: Vec::with_capacity(64),
            key_overflow: false,
            version_key_buf: Vec::with_capacity(64),
            capture_buf: Vec::with_capacity(4096),
            name: None,
            time: HashMap::new(),
            versions: None,
            cur_platform: ReleaseTimeVersionMetadata::default(),
        }
    }

    pub(super) fn feed(&mut self, chunk: &[u8]) -> Result<(), String> {
        if chunk.is_empty() {
            return Ok(());
        }
        if !self.bom_checked {
            return self.feed_with_bom(chunk);
        }
        self.feed_bytes(chunk)
    }

    fn feed_with_bom(&mut self, chunk: &[u8]) -> Result<(), String> {
        let mut idx = 0;
        while !self.bom_checked && idx < chunk.len() {
            let b = chunk[idx];
            let expected = [0xEF, 0xBB, 0xBF][self.bom_len];
            if b == expected {
                self.bom_buf[self.bom_len] = b;
                self.bom_len += 1;
                idx += 1;
                if self.bom_len == 3 {
                    self.bom_checked = true;
                    self.bom_len = 0;
                }
            } else {
                self.bom_checked = true;
                let buffered_len = self.bom_len;
                let buffered = self.bom_buf;
                self.bom_len = 0;
                if buffered_len > 0 {
                    self.feed_bytes(&buffered[..buffered_len])?;
                }
            }
        }
        if self.bom_checked && idx < chunk.len() {
            self.feed_bytes(&chunk[idx..])?;
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<ReleaseTimeMetadata, String> {
        if !self.bom_checked {
            self.bom_checked = true;
            let buffered_len = self.bom_len;
            let buffered = self.bom_buf;
            self.bom_len = 0;
            if buffered_len > 0 {
                self.feed_bytes(&buffered[..buffered_len])?;
            }
        }
        if self.state != State::Done {
            return Err("unexpected EOF while parsing release-time JSON".to_string());
        }
        Ok(ReleaseTimeMetadata {
            name: self.name,
            time: self.time,
            versions: self.versions,
        })
    }

    #[inline]
    fn is_ws(b: u8) -> bool {
        matches!(b, b' ' | b'\t' | b'\r' | b'\n')
    }

    #[inline]
    fn is_delim(b: u8) -> bool {
        Self::is_ws(b) || matches!(b, b',' | b'}' | b']')
    }

    fn feed_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        let mut i = 0;
        let len = bytes.len();
        while i < len {
            match self.state {
                State::SkipString {
                    mut in_escape,
                    ret,
                } => {
                    while i < len {
                        if in_escape {
                            in_escape = false;
                            i += 1;
                            continue;
                        }
                        if let Some(rel) = bytes[i..].iter().position(|&b| b == b'"' || b == b'\\')
                        {
                            i += rel;
                            if bytes[i] == b'\\' {
                                in_escape = true;
                                i += 1;
                            } else {
                                i += 1;
                                self.state = Self::after_value_state(ret);
                                break;
                            }
                        } else {
                            i = len;
                            break;
                        }
                    }
                    if matches!(self.state, State::SkipString { .. }) {
                        self.state = State::SkipString { in_escape, ret };
                    }
                }
                State::SkipContainer {
                    mut depth,
                    mut in_string,
                    mut in_escape,
                    ret,
                } => {
                    while i < len {
                        if in_string {
                            if in_escape {
                                in_escape = false;
                                i += 1;
                                continue;
                            }
                            if let Some(rel) =
                                bytes[i..].iter().position(|&b| b == b'"' || b == b'\\')
                            {
                                i += rel;
                                if bytes[i] == b'\\' {
                                    in_escape = true;
                                } else {
                                    in_string = false;
                                }
                                i += 1;
                            } else {
                                i = len;
                                break;
                            }
                        } else if let Some(rel) = bytes[i..]
                            .iter()
                            .position(|&b| matches!(b, b'"' | b'{' | b'}' | b'[' | b']'))
                        {
                            i += rel;
                            let b = bytes[i];
                            i += 1;
                            match b {
                                b'"' => in_string = true,
                                b'{' | b'[' => depth += 1,
                                b'}' | b']' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        self.state = Self::after_value_state(ret);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            i = len;
                            break;
                        }
                    }
                    if matches!(self.state, State::SkipContainer { .. }) {
                        self.state = State::SkipContainer {
                            depth,
                            in_string,
                            in_escape,
                            ret,
                        };
                    }
                }
                State::SkipPrimitive { ret } => {
                    if let Some(rel) = bytes[i..].iter().position(|&b| Self::is_delim(b)) {
                        i += rel;
                        self.state = Self::after_value_state(ret);
                    } else {
                        i = len;
                    }
                }
                State::CaptureString {
                    target,
                    mut in_escape,
                    ret,
                    cap,
                } => {
                    let start = i;
                    let mut finished = false;
                    while i < len {
                        if in_escape {
                            in_escape = false;
                            i += 1;
                            continue;
                        }
                        if let Some(rel) = bytes[i..].iter().position(|&b| b == b'"' || b == b'\\')
                        {
                            i += rel;
                            if bytes[i] == b'\\' {
                                in_escape = true;
                                i += 1;
                            } else {
                                i += 1;
                                finished = true;
                                break;
                            }
                        } else {
                            i = len;
                            break;
                        }
                    }
                    self.push_capture(&bytes[start..i], cap)?;
                    if finished {
                        self.commit_capture(target)?;
                        self.state = Self::after_value_state(ret);
                    } else {
                        self.state = State::CaptureString {
                            target,
                            in_escape,
                            ret,
                            cap,
                        };
                    }
                }
                State::CaptureContainer {
                    target,
                    mut depth,
                    mut in_string,
                    mut in_escape,
                    ret,
                    cap,
                } => {
                    let start = i;
                    let mut finished = false;
                    while i < len {
                        if in_string {
                            if in_escape {
                                in_escape = false;
                                i += 1;
                                continue;
                            }
                            if let Some(rel) =
                                bytes[i..].iter().position(|&b| b == b'"' || b == b'\\')
                            {
                                i += rel;
                                if bytes[i] == b'\\' {
                                    in_escape = true;
                                } else {
                                    in_string = false;
                                }
                                i += 1;
                            } else {
                                i = len;
                                break;
                            }
                        } else if let Some(rel) = bytes[i..]
                            .iter()
                            .position(|&b| matches!(b, b'"' | b'{' | b'}' | b'[' | b']'))
                        {
                            i += rel;
                            let b = bytes[i];
                            i += 1;
                            match b {
                                b'"' => in_string = true,
                                b'{' | b'[' => depth += 1,
                                b'}' | b']' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        finished = true;
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        } else {
                            i = len;
                            break;
                        }
                    }
                    self.push_capture(&bytes[start..i], cap)?;
                    if finished {
                        self.commit_capture(target)?;
                        self.state = Self::after_value_state(ret);
                    } else {
                        self.state = State::CaptureContainer {
                            target,
                            depth,
                            in_string,
                            in_escape,
                            ret,
                            cap,
                        };
                    }
                }
                State::CapturePrimitive { target, ret, cap } => {
                    if let Some(rel) = bytes[i..].iter().position(|&b| Self::is_delim(b)) {
                        self.push_capture(&bytes[i..i + rel], cap)?;
                        i += rel;
                        self.commit_capture(target)?;
                        self.state = Self::after_value_state(ret);
                    } else {
                        self.push_capture(&bytes[i..], cap)?;
                        i = len;
                    }
                }
                State::ReadKey { ctx, mut in_escape } => {
                    let start = i;
                    let mut finished = false;
                    while i < len {
                        if in_escape {
                            in_escape = false;
                            i += 1;
                            continue;
                        }
                        if let Some(rel) = bytes[i..].iter().position(|&b| b == b'"' || b == b'\\')
                        {
                            i += rel;
                            if bytes[i] == b'\\' {
                                in_escape = true;
                                i += 1;
                            } else {
                                finished = true;
                                break;
                            }
                        } else {
                            i = len;
                            break;
                        }
                    }
                    let slice = &bytes[start..i];
                    match ctx {
                        KeyContext::Versions => {
                            if self.version_key_buf.len() + slice.len() > MAX_NAME_CAPTURE_BYTES {
                                return Err("version key exceeds length cap".to_string());
                            }
                            self.version_key_buf.extend_from_slice(slice);
                        }
                        KeyContext::Top | KeyContext::Version => {
                            if !self.key_overflow {
                                if self.key_buf.len() + slice.len() <= MAX_KEY_CAPTURE_BYTES {
                                    self.key_buf.extend_from_slice(slice);
                                } else {
                                    self.key_overflow = true;
                                }
                            }
                        }
                    }
                    if finished {
                        i += 1; // consume closing '"'
                        self.state = match ctx {
                            KeyContext::Top => State::TopAfterKey,
                            KeyContext::Versions => {
                                self.version_key_buf.push(b'"');
                                State::VersionsAfterKey
                            }
                            KeyContext::Version => State::VersionAfterKey,
                        };
                    } else {
                        self.state = State::ReadKey { ctx, in_escape };
                    }
                }
                State::Start => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b'{' {
                        self.state = State::TopExpectKeyOrEnd;
                    } else {
                        return Err(format!("expected top-level '{{', got byte 0x{b:02x}"));
                    }
                }
                State::TopExpectKeyOrEnd => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b'}' => self.state = State::Done,
                        b'"' => self.begin_key(KeyContext::Top),
                        _ => return Err(format!("expected key or '}}', got byte 0x{b:02x}")),
                    }
                }
                State::TopExpectKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b'"' {
                        self.begin_key(KeyContext::Top);
                    } else {
                        return Err(format!("expected top-level key, got byte 0x{b:02x}"));
                    }
                }
                State::TopAfterKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b':' {
                        let field = self.classify_top_key()?;
                        self.state = State::TopExpectValue(field);
                    } else {
                        return Err(format!("expected ':', got byte 0x{b:02x}"));
                    }
                }
                State::TopExpectValue(field) => {
                    let b = bytes[i];
                    if Self::is_ws(b) {
                        i += 1;
                        continue;
                    }
                    match field {
                        TopField::Name => {
                            self.capture_buf.clear();
                            self.state = State::CaptureValueStart {
                                target: CaptureTarget::TopName,
                                ret: ReturnLevel::TopAfterValue,
                                cap: MAX_NAME_CAPTURE_BYTES,
                            };
                        }
                        TopField::Time => {
                            self.capture_buf.clear();
                            self.state = State::CaptureValueStart {
                                target: CaptureTarget::TopTime,
                                ret: ReturnLevel::TopAfterValue,
                                cap: super::body::MAX_METADATA_BYTES,
                            };
                        }
                        TopField::Versions => {
                            i += 1;
                            match b {
                                b'{' => {
                                    self.versions.get_or_insert_with(HashMap::new);
                                    self.state = State::VersionsExpectKeyOrEnd;
                                }
                                b'n' => {
                                    self.state = State::SkipNull {
                                        remaining: 3,
                                        ret: ReturnLevel::TopAfterValue,
                                    };
                                }
                                _ => {
                                    return Err(format!(
                                        "expected object or null for 'versions', got byte 0x{b:02x}"
                                    ));
                                }
                            }
                        }
                        TopField::Ignore => {
                            self.state = State::SkipValueStart {
                                ret: ReturnLevel::TopAfterValue,
                            };
                        }
                    }
                }
                State::TopAfterValue => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b',' => self.state = State::TopExpectKey,
                        b'}' => self.state = State::Done,
                        _ => return Err(format!("expected ',' or '}}', got byte 0x{b:02x}")),
                    }
                }
                State::VersionsExpectKeyOrEnd => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b'}' => self.state = State::TopAfterValue,
                        b'"' => self.begin_key(KeyContext::Versions),
                        _ => {
                            return Err(format!(
                                "expected version key or '}}', got byte 0x{b:02x}"
                            ));
                        }
                    }
                }
                State::VersionsExpectKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b'"' {
                        self.begin_key(KeyContext::Versions);
                    } else {
                        return Err(format!("expected version key, got byte 0x{b:02x}"));
                    }
                }
                State::VersionsAfterKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b':' {
                        self.state = State::VersionsExpectObjStart;
                    } else {
                        return Err(format!(
                            "expected ':' after version key, got byte 0x{b:02x}"
                        ));
                    }
                }
                State::VersionsExpectObjStart => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b'{' {
                        self.cur_platform = ReleaseTimeVersionMetadata::default();
                        self.state = State::VersionExpectKeyOrEnd;
                    } else {
                        return Err(format!("expected version object '{{', got byte 0x{b:02x}"));
                    }
                }
                State::VersionsAfterValue => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b',' => self.state = State::VersionsExpectKey,
                        b'}' => self.state = State::TopAfterValue,
                        _ => {
                            return Err(format!(
                                "expected ',' or '}}' in versions map, got byte 0x{b:02x}"
                            ));
                        }
                    }
                }
                State::VersionExpectKeyOrEnd => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b'}' => {
                            self.commit_version_platform()?;
                            self.state = State::VersionsAfterValue;
                        }
                        b'"' => self.begin_key(KeyContext::Version),
                        _ => {
                            return Err(format!(
                                "expected version field key or '}}', got byte 0x{b:02x}"
                            ));
                        }
                    }
                }
                State::VersionExpectKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b'"' {
                        self.begin_key(KeyContext::Version);
                    } else {
                        return Err(format!("expected version field key, got byte 0x{b:02x}"));
                    }
                }
                State::VersionAfterKey => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    if b == b':' {
                        let field = self.classify_version_key()?;
                        self.state = State::VersionExpectValue(field);
                    } else {
                        return Err(format!(
                            "expected ':' after version field key, got byte 0x{b:02x}"
                        ));
                    }
                }
                State::VersionExpectValue(field) => {
                    let b = bytes[i];
                    if Self::is_ws(b) {
                        i += 1;
                        continue;
                    }
                    match field {
                        VersionField::Os => {
                            self.capture_buf.clear();
                            self.state = State::CaptureValueStart {
                                target: CaptureTarget::VersionOs,
                                ret: ReturnLevel::VersionAfterValue,
                                cap: MAX_PLATFORM_FIELD_CAPTURE_BYTES,
                            };
                        }
                        VersionField::Cpu => {
                            self.capture_buf.clear();
                            self.state = State::CaptureValueStart {
                                target: CaptureTarget::VersionCpu,
                                ret: ReturnLevel::VersionAfterValue,
                                cap: MAX_PLATFORM_FIELD_CAPTURE_BYTES,
                            };
                        }
                        VersionField::Libc => {
                            self.capture_buf.clear();
                            self.state = State::CaptureValueStart {
                                target: CaptureTarget::VersionLibc,
                                ret: ReturnLevel::VersionAfterValue,
                                cap: MAX_PLATFORM_FIELD_CAPTURE_BYTES,
                            };
                        }
                        VersionField::Ignore => {
                            self.state = State::SkipValueStart {
                                ret: ReturnLevel::VersionAfterValue,
                            };
                        }
                    }
                }
                State::VersionAfterValue => {
                    let b = bytes[i];
                    i += 1;
                    if Self::is_ws(b) {
                        continue;
                    }
                    match b {
                        b',' => self.state = State::VersionExpectKey,
                        b'}' => {
                            self.commit_version_platform()?;
                            self.state = State::VersionsAfterValue;
                        }
                        _ => {
                            return Err(format!(
                                "expected ',' or '}}' in version object, got byte 0x{b:02x}"
                            ));
                        }
                    }
                }
                State::SkipNull { remaining, ret } => {
                    let b = bytes[i];
                    i += 1;
                    let expected = match remaining {
                        3 => b'u',
                        2 | 1 => b'l',
                        _ => unreachable!(),
                    };
                    if b != expected {
                        return Err(format!("invalid 'null' literal byte 0x{b:02x}"));
                    }
                    if remaining == 1 {
                        self.state = Self::after_value_state(ret);
                    } else {
                        self.state = State::SkipNull {
                            remaining: remaining - 1,
                            ret,
                        };
                    }
                }
                State::SkipValueStart { ret } => {
                    let b = bytes[i];
                    if Self::is_ws(b) {
                        i += 1;
                        continue;
                    }
                    i += 1;
                    match b {
                        b'"' => {
                            self.state = State::SkipString {
                                in_escape: false,
                                ret,
                            };
                        }
                        b'{' | b'[' => {
                            self.state = State::SkipContainer {
                                depth: 1,
                                in_string: false,
                                in_escape: false,
                                ret,
                            };
                        }
                        b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                            self.state = State::SkipPrimitive { ret };
                        }
                        _ => {
                            return Err(format!("unexpected JSON value start byte 0x{b:02x}"));
                        }
                    }
                }
                State::CaptureValueStart { target, ret, cap } => {
                    let b = bytes[i];
                    if Self::is_ws(b) {
                        i += 1;
                        continue;
                    }
                    i += 1;
                    self.push_capture(&[b], cap)?;
                    match b {
                        b'"' => {
                            self.state = State::CaptureString {
                                target,
                                in_escape: false,
                                ret,
                                cap,
                            };
                        }
                        b'{' | b'[' => {
                            self.state = State::CaptureContainer {
                                target,
                                depth: 1,
                                in_string: false,
                                in_escape: false,
                                ret,
                                cap,
                            };
                        }
                        b't' | b'f' | b'n' | b'-' | b'0'..=b'9' => {
                            self.state = State::CapturePrimitive { target, ret, cap };
                        }
                        _ => {
                            return Err(format!(
                                "unexpected JSON value start byte 0x{b:02x} for captured field"
                            ));
                        }
                    }
                }
                State::Done => {
                    let b = bytes[i];
                    i += 1;
                    if !Self::is_ws(b) {
                        return Err(format!("trailing byte 0x{b:02x} after JSON object"));
                    }
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn after_value_state(ret: ReturnLevel) -> State {
        match ret {
            ReturnLevel::TopAfterValue => State::TopAfterValue,
            ReturnLevel::VersionAfterValue => State::VersionAfterValue,
        }
    }

    #[inline]
    fn begin_key(&mut self, ctx: KeyContext) {
        match ctx {
            KeyContext::Versions => {
                self.version_key_buf.clear();
                self.version_key_buf.push(b'"');
            }
            KeyContext::Top | KeyContext::Version => {
                self.key_buf.clear();
                self.key_overflow = false;
            }
        }
        self.state = State::ReadKey {
            ctx,
            in_escape: false,
        };
    }

    #[inline]
    fn push_capture(&mut self, slice: &[u8], cap: usize) -> Result<(), String> {
        if self.capture_buf.len().saturating_add(slice.len()) > cap {
            return Err(format!("captured JSON field exceeded {cap}-byte limit"));
        }
        self.capture_buf.extend_from_slice(slice);
        Ok(())
    }

    fn decode_small_key(&self) -> Result<std::borrow::Cow<'_, str>, String> {
        if self.key_buf.contains(&b'\\') {
            let mut quoted = Vec::with_capacity(self.key_buf.len() + 2);
            quoted.push(b'"');
            quoted.extend_from_slice(&self.key_buf);
            quoted.push(b'"');
            let s: String =
                serde_json::from_slice(&quoted).map_err(|e| format!("invalid key string: {e}"))?;
            Ok(std::borrow::Cow::Owned(s))
        } else {
            let s = std::str::from_utf8(&self.key_buf)
                .map_err(|e| format!("invalid UTF-8 key: {e}"))?;
            Ok(std::borrow::Cow::Borrowed(s))
        }
    }

    fn classify_top_key(&self) -> Result<TopField, String> {
        if self.key_overflow {
            return Ok(TopField::Ignore);
        }
        if !self.key_buf.contains(&b'\\') {
            return Ok(match self.key_buf.as_slice() {
                b"name" => TopField::Name,
                b"time" => TopField::Time,
                b"versions" => TopField::Versions,
                _ => TopField::Ignore,
            });
        }
        let decoded = self.decode_small_key()?;
        Ok(match decoded.as_ref() {
            "name" => TopField::Name,
            "time" => TopField::Time,
            "versions" => TopField::Versions,
            _ => TopField::Ignore,
        })
    }

    fn classify_version_key(&self) -> Result<VersionField, String> {
        if self.key_overflow {
            return Ok(VersionField::Ignore);
        }
        if !self.key_buf.contains(&b'\\') {
            return Ok(match self.key_buf.as_slice() {
                b"os" => VersionField::Os,
                b"cpu" => VersionField::Cpu,
                b"libc" => VersionField::Libc,
                _ => VersionField::Ignore,
            });
        }
        let decoded = self.decode_small_key()?;
        Ok(match decoded.as_ref() {
            "os" => VersionField::Os,
            "cpu" => VersionField::Cpu,
            "libc" => VersionField::Libc,
            _ => VersionField::Ignore,
        })
    }

    fn commit_capture(&mut self, target: CaptureTarget) -> Result<(), String> {
        match target {
            CaptureTarget::TopName => {
                self.name = serde_json::from_slice::<Option<String>>(&self.capture_buf)
                    .map_err(|e| format!("invalid 'name' field: {e}"))?;
            }
            CaptureTarget::TopTime => {
                let parsed =
                    serde_json::from_slice::<Option<HashMap<String, String>>>(&self.capture_buf)
                        .map_err(|e| format!("invalid 'time' field: {e}"))?;
                self.time = parsed.unwrap_or_default();
            }
            CaptureTarget::VersionOs => {
                self.cur_platform.os = serde_json::from_slice::<PlatformFieldValue>(
                    &self.capture_buf,
                )
                .map_err(|e| format!("invalid 'os' field: {e}"))?
                .0;
            }
            CaptureTarget::VersionCpu => {
                self.cur_platform.cpu = serde_json::from_slice::<PlatformFieldValue>(
                    &self.capture_buf,
                )
                .map_err(|e| format!("invalid 'cpu' field: {e}"))?
                .0;
            }
            CaptureTarget::VersionLibc => {
                self.cur_platform.libc = serde_json::from_slice::<PlatformFieldValue>(
                    &self.capture_buf,
                )
                .map_err(|e| format!("invalid 'libc' field: {e}"))?
                .0;
            }
        }
        Ok(())
    }

    fn commit_version_platform(&mut self) -> Result<(), String> {
        if self.cur_platform.os.is_empty()
            && self.cur_platform.cpu.is_empty()
            && self.cur_platform.libc.is_empty()
        {
            return Ok(());
        }
        let version = if !self.version_key_buf.contains(&b'\\') {
            std::str::from_utf8(&self.version_key_buf[1..self.version_key_buf.len() - 1])
                .map_err(|e| format!("invalid UTF-8 version key: {e}"))?
                .to_owned()
        } else {
            serde_json::from_slice::<String>(&self.version_key_buf)
                .map_err(|e| format!("invalid version key string: {e}"))?
        };
        if let Some(versions) = self.versions.as_mut() {
            versions.insert(version, std::mem::take(&mut self.cur_platform));
        }
        Ok(())
    }
}

pub(super) async fn parse_streaming_release_time_metadata_with_timing(
    mut response: reqwest::Response,
    cap: usize,
    context: &str,
) -> Result<(ReleaseTimeMetadata, MetadataBodyTimings), LpmError> {
    if let Some(declared) = response.content_length()
        && declared > cap as u64
    {
        return Err(LpmError::Registry(format!(
            "{context}: response body declared {declared} bytes exceeds {cap}-byte cap"
        )));
    }

    let body_start = std::time::Instant::now();
    let mut parser = ReleaseTimeStreamParser::new();
    let mut total_bytes: u64 = 0;
    let mut parse_ns: u128 = 0;

    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| LpmError::Registry(format!("{context}: failed reading body: {error}")))?
    {
        total_bytes = total_bytes.saturating_add(chunk.len() as u64);
        if total_bytes > cap as u64 {
            return Err(LpmError::Registry(format!(
                "{context}: response body exceeded {cap}-byte cap"
            )));
        }
        let parse_start = std::time::Instant::now();
        parser
            .feed(&chunk)
            .map_err(|error| LpmError::Registry(format!("{context}: failed to parse JSON: {error}")))?;
        parse_ns = parse_ns.saturating_add(parse_start.elapsed().as_nanos());
    }

    let finish_start = std::time::Instant::now();
    let metadata = parser
        .finish()
        .map_err(|error| LpmError::Registry(format!("{context}: failed to parse JSON: {error}")))?;
    parse_ns = parse_ns.saturating_add(finish_start.elapsed().as_nanos());

    let timings = MetadataBodyTimings {
        body_read_ms: body_start.elapsed().as_millis(),
        json_parse_ms: parse_ns / 1_000_000,
        body_bytes: total_bytes,
        cap_exceeded: false,
    };
    Ok((metadata, timings))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_chunked(input: &[u8], chunk_size: usize) -> Result<ReleaseTimeMetadata, String> {
        let mut parser = ReleaseTimeStreamParser::new();
        for chunk in input.chunks(chunk_size) {
            parser.feed(chunk)?;
        }
        parser.finish()
    }

    #[test]
    fn streaming_parser_matches_serde_across_chunk_sizes() {
        let doc = serde_json::json!({
            "_id": "@scope/demo",
            "name": "@scope/demo",
            "readme": "Lots of text with \"escaped quotes\", braces { \"time\": {} }, and \\\\ slashes",
            "dist-tags": { "latest": "2.0.0" },
            "versions": {
                "1.0.0": {
                    "name": "@scope/demo",
                    "version": "1.0.0",
                    "dependencies": { "a": "^1.0.0", "b": "*" },
                    "dist": { "tarball": "https://registry.npmjs.org/a.tgz" }
                },
                "2.0.0": {
                    "name": "@scope/demo",
                    "version": "2.0.0",
                    "os": ["linux", "!win32"],
                    "cpu": "x64",
                    "libc": ["glibc"],
                    "exports": { ".": { "import": "./index.mjs" } }
                },
                "2.0.1-alpha.1": {
                    "name": "@scope/demo",
                    "version": "2.0.1-alpha.1",
                    "os": [],
                    "cpu": null,
                    "libc": ["musl"]
                }
            },
            "time": {
                "created": "2024-01-01T00:00:00.000Z",
                "modified": "2026-11-20T00:00:00.000Z",
                "1.0.0": "2024-01-01T00:00:00.000Z",
                "2.0.0": "2026-11-19T00:00:00.000Z",
                "2.0.1-alpha.1": "2026-11-20T00:00:00.000Z"
            },
            "maintainers": [{ "name": "alice", "email": "alice@example.com" }]
        });
        let raw = serde_json::to_vec(&doc).unwrap();
        let expected: ReleaseTimeMetadata = serde_json::from_slice(&raw).unwrap();

        for chunk_size in [1, 2, 3, 7, 17, 64, raw.len()] {
            let actual = parse_chunked(&raw, chunk_size)
                .unwrap_or_else(|e| panic!("failed with chunk_size={chunk_size}: {e}"));
            assert_eq!(actual.name, expected.name);
            assert_eq!(actual.time, expected.time);
            assert_eq!(
                serde_json::to_value(&actual).unwrap(),
                serde_json::to_value(&expected).unwrap(),
                "mismatch for chunk_size={chunk_size}"
            );
        }
    }

    #[test]
    fn streaming_parser_preserves_versions_presence_distinction() {
        let time_only = br#"{"name":"a","time":{"1.0.0":"2025-01-01T00:00:00.000Z"}}"#;
        let parsed = parse_chunked(time_only, 5).unwrap();
        assert!(parsed.versions.is_none());

        let null_versions =
            br#"{"name":"a","versions":null,"time":{"1.0.0":"2025-01-01T00:00:00.000Z"}}"#;
        let parsed = parse_chunked(null_versions, 4).unwrap();
        assert!(parsed.versions.is_none());

        let empty_versions =
            br#"{"name":"a","versions":{},"time":{"1.0.0":"2025-01-01T00:00:00.000Z"}}"#;
        let parsed = parse_chunked(empty_versions, 4).unwrap();
        assert!(parsed.versions.is_some());
        assert!(parsed.versions.unwrap().is_empty());

        let no_platform_versions =
            br#"{"name":"a","versions":{"1.0.0":{"name":"a"}},"time":{"1.0.0":"2025-01-01T00:00:00.000Z"}}"#;
        let parsed = parse_chunked(no_platform_versions, 3).unwrap();
        assert!(parsed.versions.is_some());
        assert!(parsed.versions.unwrap().is_empty());
    }

    #[test]
    fn streaming_parser_strips_utf8_bom_across_chunks_and_rejects_malformed() {
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(br#"{"name":"bom-pkg","time":{"1.0.0":"2025-01-01T00:00:00.000Z"}}"#);
        let parsed = parse_chunked(&with_bom, 1).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("bom-pkg"));
        assert_eq!(
            parsed.time.get("1.0.0").map(String::as_str),
            Some("2025-01-01T00:00:00.000Z")
        );

        assert!(parse_chunked(br#"{"name":"truncated""#, 5).is_err());
        assert!(parse_chunked(br#"{"name":"trailing"} garbage"#, 5).is_err());
        assert!(parse_chunked(br#"[]"#, 1).is_err());
    }
}
