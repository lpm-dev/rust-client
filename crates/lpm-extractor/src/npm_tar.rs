//! A tar stream as npm's tar (node-tar 7) reads it, for a reader that must see the
//! entries an npm install unpacks: the same files, framed by the same sizes, ending
//! at the same place.
//!
//! The tar crate frames every header by its size field and reads GNU and PAX
//! records its own way. npm's tar differs on headers it rejects (a bad checksum,
//! an empty path, a link without a target or a file with one, a number it can't
//! decode), which it reads as a single block without a body; on directories, whose
//! body it always reads as empty; on records that set the next entry's size, path
//! or link target, where the last one wins and a global one applies to every entry
//! after it; and on where the archive ends. A payload one reader skips and the
//! other reads as headers can hold entries only one of them unpacks.
//!
//! [`NpmTarStream`] hands on, in place of the archive it reads, one the tar crate
//! frames exactly as npm's tar frames the original.

use std::io::{self, Read};

/// Payload bytes of a GNU or PAX record npm's tar applies; it skips a longer one
/// without applying it.
const MAX_META_BYTES: u64 = 1024 * 1024;

/// Payload and padding bytes [`NpmTarStream::with_every_name`] holds to hand
/// an entry on under more than one name.
const MAX_REPEATED_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

/// Names [`NpmTarStream::with_every_name`] hands one entry on under.
const MAX_ENTRY_NAMES: usize = 4;

/// The largest number JavaScript represents exactly, past which npm's tar refuses
/// a base-256 field.
const MAX_SAFE_INTEGER: u128 = (1 << 53) - 1;

/// A tar stream as npm's tar reads it:
/// - It ends where npm's tar ends one, at the second of two null blocks in a
///   row. A lone null block is read past, as npm reads on after one, and nothing
///   after the end is read, as npm ignores it. A partial block after the last
///   entry is dropped, as npm drops it.
/// - A header npm's tar rejects is dropped, without a body, so what follows it
///   is read as headers, as npm reads it.
/// - GNU long-name and long-link records and PAX records are applied as npm
///   applies them and dropped. An entry whose path or link target they changed
///   gets one PAX record that names them.
/// - Each entry's size field says the size npm reads (a directory's is 0, and a
///   file whose path ends in `/` is a directory), and its checksum is rewritten.
/// - An entry npm skips (a type it doesn't unpack) is dropped with its payload.
///
/// A PAX size only a non-canonical writer produces, which npm would read in a
/// way that can't be framed, and input that ends inside an entry, fail the read.
///
/// npm's tar decodes a PAX record piece by piece as its input arrives, so a
/// line holding a multi-byte character split between two pieces fails its
/// length check and is dropped, and the entry keeps the path it had without
/// it. Where pieces end depends on the network, so [`Self::new`] gives the
/// path the whole line gives, as an install should, and
/// [`Self::with_every_name`] hands such an entry on under each path npm may
/// give it, for a reader that must see every file npm may unpack.
pub struct NpmTarStream<R> {
    inner: R,
    every_name: bool,
    /// Bytes ready to hand on: a header, a PAX record, a null block.
    pending: Vec<u8>,
    pending_at: usize,
    /// Payload and padding bytes of the current entry still to pass on, or to
    /// skip when the entry was dropped.
    body_remaining: u64,
    emit_body: bool,
    /// What the records read so far set for the next entry, and for every entry.
    local: Extended,
    global: Extended,
    saw_null: bool,
    ended: bool,
}

/// The fields of npm's extended header state this reader needs: the overrides
/// that move an entry, and which numeric fields a record supplies, since npm
/// doesn't decode (or refuse) a header field a record supplies. npm's PAX state
/// keeps no mode, so a header's mode is always decoded.
#[derive(Clone, Default)]
struct Extended {
    path: Option<String>,
    /// The other paths npm may give the entry, when dropping a path line that
    /// holds a multi-byte character leaves an earlier one, or `None`, the
    /// header's.
    other_paths: Vec<Option<String>>,
    linkpath: Option<String>,
    size: Option<u64>,
    uid: bool,
    gid: bool,
    mtime: bool,
    atime: bool,
    ctime: bool,
}

impl Extended {
    /// `newer` applied over `self`, as npm merges a PAX record into the state.
    fn merged(self, newer: Extended) -> Extended {
        let other_paths = if newer.path.is_some() {
            let mut paths: Vec<Option<String>> = Vec::new();
            for other in newer.other_paths {
                let others = match other {
                    Some(path) => vec![Some(path)],
                    None => std::iter::once(self.path.clone())
                        .chain(self.other_paths.iter().cloned())
                        .collect(),
                };
                for path in others {
                    if path != newer.path && !paths.contains(&path) {
                        paths.push(path);
                    }
                }
            }
            paths
        } else {
            self.other_paths
        };
        Extended {
            path: newer.path.or(self.path),
            other_paths,
            linkpath: newer.linkpath.or(self.linkpath),
            size: newer.size.or(self.size),
            uid: newer.uid || self.uid,
            gid: newer.gid || self.gid,
            mtime: newer.mtime || self.mtime,
            atime: newer.atime || self.atime,
            ctime: newer.ctime || self.ctime,
        }
    }
}

impl<R> NpmTarStream<R> {
    pub fn new(inner: R) -> Self {
        Self::reading(inner, false)
    }

    /// A stream that hands an entry on under each path npm may give it, which
    /// fails when the paths would frame the archive differently or the entry
    /// is too large to repeat.
    pub fn with_every_name(inner: R) -> Self {
        Self::reading(inner, true)
    }

    fn reading(inner: R, every_name: bool) -> Self {
        Self {
            inner,
            every_name,
            pending: Vec::new(),
            pending_at: 0,
            body_remaining: 0,
            emit_body: false,
            local: Extended::default(),
            global: Extended::default(),
            saw_null: false,
            ended: false,
        }
    }

    /// The reader the archive came from, positioned after its end once the
    /// archive has been read to its end, so a caller can read what follows,
    /// such as a compression trailer.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for NpmTarStream<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.pending_at < self.pending.len() {
                let count = output.len().min(self.pending.len() - self.pending_at);
                output[..count]
                    .copy_from_slice(&self.pending[self.pending_at..self.pending_at + count]);
                self.pending_at += count;
                return Ok(count);
            }
            if self.body_remaining > 0 {
                if self.emit_body {
                    let room = (output.len() as u64).min(self.body_remaining) as usize;
                    let read = read_retrying(&mut self.inner, &mut output[..room])?;
                    if read == 0 {
                        return Err(truncated());
                    }
                    self.body_remaining -= read as u64;
                    return Ok(read);
                }
                skip(&mut self.inner, self.body_remaining)?;
                self.body_remaining = 0;
                continue;
            }
            if self.ended {
                return Ok(0);
            }
            let mut block = [0u8; 512];
            if !read_block(&mut self.inner, &mut block)? {
                self.ended = true;
                return Ok(0);
            }
            self.next_header(&block)?;
        }
    }
}

impl<R: Read> NpmTarStream<R> {
    fn next_header(&mut self, block: &[u8; 512]) -> io::Result<()> {
        self.pending.clear();
        self.pending_at = 0;
        let header = match decode(block, &self.local, &self.global) {
            // npm's tar warns and reads on without touching its null-block count.
            Decoded::Throws => return Ok(()),
            Decoded::Null => {
                self.pending.extend_from_slice(&[0; 512]);
                self.ended = self.saw_null;
                self.saw_null = true;
                return Ok(());
            }
            Decoded::Header(header) => header,
        };
        self.saw_null = false;
        if !header.accepted() {
            return Ok(());
        }
        let padded = header.size.div_ceil(512) * 512;
        match header.kind() {
            Kind::Meta(meta) => {
                // npm decides from the entry's size, which takes a global size,
                // then a local one, over the header's: past its limit the record
                // is skipped; at 0 its payload isn't read as a record at all, so
                // what follows its header is read as headers. Otherwise the
                // header's size frames the payload.
                let decided = self.global.size.or(self.local.size).unwrap_or(header.size);
                if decided > MAX_META_BYTES {
                    self.drop_body(padded);
                } else if decided > 0 {
                    let mut record = vec![0u8; padded as usize];
                    read_exact_or_truncated(&mut self.inner, &mut record)?;
                    record.truncate(header.size as usize);
                    self.apply(meta, &record)?;
                }
            }
            Kind::Skipped => {
                self.local = Extended::default();
                self.drop_body(padded);
            }
            Kind::Unpacked => {
                let local = std::mem::take(&mut self.local);
                if !(self.every_name && self.emit_every_name(block, &header, &local, padded)?) {
                    self.emit_entry(block, &header, &local)?;
                    self.body_remaining = padded;
                    self.emit_body = true;
                }
            }
        }
        Ok(())
    }

    /// Queues a GNU long-name or long-link record holding `value`.
    fn push_long_record(&mut self, kind: tar::EntryType, value: &str) {
        let mut record = tar::Header::new_gnu();
        record.as_mut_bytes()[..13].copy_from_slice(b"././@LongLink");
        record.set_entry_type(kind);
        record.set_size(value.len() as u64 + 1);
        record.set_mode(0o644);
        record.set_cksum();
        self.pending.extend_from_slice(record.as_bytes());
        self.pending.extend_from_slice(value.as_bytes());
        self.pending.push(0);
        self.pending
            .resize(self.pending.len().div_ceil(512) * 512, 0);
    }

    /// Queues the entry, with its payload, under each path npm may give it.
    /// `false` when it has just the one, which is left to queue.
    fn emit_every_name(
        &mut self,
        block: &[u8; 512],
        header: &Header,
        local: &Extended,
        padded: u64,
    ) -> io::Result<bool> {
        let primary = local.path.as_deref().unwrap_or(&header.path);
        let mut others: Vec<(Header, Extended)> = Vec::new();
        for path in &local.other_paths {
            let candidate = Extended {
                path: path.clone(),
                other_paths: Vec::new(),
                ..local.clone()
            };
            let Decoded::Header(other) = decode(block, &candidate, &self.global) else {
                return Err(differently_framed());
            };
            if !other.accepted()
                || !matches!(other.kind(), Kind::Unpacked)
                || other.code != header.code
                || other.size != header.size
            {
                return Err(differently_framed());
            }
            let name = candidate.path.as_deref().unwrap_or(&other.path);
            let known = others
                .iter()
                .any(|(seen, extended)| extended.path.as_deref().unwrap_or(&seen.path) == name);
            if name != primary && !known {
                others.push((other, candidate));
            }
        }
        if others.is_empty() {
            return Ok(false);
        }
        if others.len() >= MAX_ENTRY_NAMES || padded > MAX_REPEATED_ENTRY_BYTES {
            return Err(differently_framed());
        }
        let mut body = vec![0u8; padded as usize];
        read_exact_or_truncated(&mut self.inner, &mut body)?;
        self.emit_entry(block, header, local)?;
        self.pending.extend_from_slice(&body);
        for (other, candidate) in &others {
            self.emit_entry(block, other, candidate)?;
            self.pending.extend_from_slice(&body);
        }
        Ok(true)
    }

    fn drop_body(&mut self, padded: u64) {
        self.body_remaining = padded;
        self.emit_body = false;
    }

    fn apply(&mut self, meta: Meta, record: &[u8]) -> io::Result<()> {
        let text = String::from_utf8_lossy(record);
        match meta {
            Meta::Extended => {
                let parsed = parse_pax(&text)?;
                self.local = std::mem::take(&mut self.local).merged(parsed);
            }
            Meta::Global => {
                let parsed = parse_pax(&text)?;
                self.global = std::mem::take(&mut self.global).merged(parsed);
            }
            Meta::LongPath => {
                self.local.path = Some(js_strip_nul(&text));
                self.local.other_paths.clear();
            }
            Meta::LongLink => self.local.linkpath = Some(js_strip_nul(&text)),
        }
        Ok(())
    }

    /// Queues the header the tar crate reads for an entry npm unpacks: GNU records
    /// naming the path and link target npm gives it when the header alone doesn't,
    /// then the header with npm's type and size and a fresh checksum. GNU records
    /// are framed by their size, so a name holding a line break, which npm keeps,
    /// reads back whole; the tar crate splits PAX records at line breaks.
    ///
    /// What it queues reads the same through npm's rules again: a numeric field a
    /// record supplied, which npm never decoded, is zeroed, since the records
    /// aren't handed on. A name holding a NUL, which a second read would cut, or
    /// one past the record limit fails the read.
    fn emit_entry(
        &mut self,
        block: &[u8; 512],
        header: &Header,
        local: &Extended,
    ) -> io::Result<()> {
        let tar_crate_path = tar::Header::from_byte_slice(block)
            .path_bytes()
            .into_owned();
        let path = local.path.as_deref().unwrap_or(&header.path);
        let raw_link = (!header.linkpath.is_empty()).then_some(header.linkpath.as_str());
        // A global link target applies after the local one, as npm slurps it last.
        let link = self
            .global
            .linkpath
            .clone()
            .or_else(|| local.linkpath.clone())
            .or_else(|| raw_link.map(str::to_owned));
        for name in std::iter::once(path).chain(link.as_deref()) {
            if name.contains('\0') || name.len() as u64 >= MAX_META_BYTES {
                return Err(unrepeatable_name());
            }
        }
        if local.path.is_some() || tar_crate_path != path.as_bytes() {
            self.push_long_record(tar::EntryType::GNULongName, path);
        }
        if header.is_link() && link.as_deref() != raw_link {
            self.push_long_record(
                tar::EntryType::GNULongLink,
                link.as_deref().unwrap_or_default(),
            );
        }
        let mut rewritten = *block;
        if header.directory_from_file() {
            rewritten[156] = b'5';
        }
        let supplied = |field: fn(&Extended) -> bool| field(local) || field(&self.global);
        let mut zeroed: Vec<std::ops::Range<usize>> = Vec::with_capacity(5);
        if header.is_normal_type() {
            for (field, range) in [
                (supplied(|extended| extended.uid), 108..116),
                (supplied(|extended| extended.gid), 116..124),
                (supplied(|extended| extended.mtime), 136..148),
            ] {
                if field {
                    zeroed.push(range);
                }
            }
        }
        if &block[257..265] == b"ustar\x0000" && block[475] == 0 {
            for (field, range) in [
                (supplied(|extended| extended.atime), 476..488),
                (supplied(|extended| extended.ctime), 488..500),
            ] {
                if field {
                    zeroed.push(range);
                }
            }
        }
        for range in zeroed {
            write_octal_zero(&mut rewritten[range]);
        }
        write_size(&mut rewritten, header.size);
        let mut out = tar::Header::new_old();
        out.as_mut_bytes().copy_from_slice(&rewritten);
        out.set_cksum();
        self.pending.extend_from_slice(out.as_bytes());
        Ok(())
    }
}

/// Fills a numeric header field with an octal zero and its NUL terminator.
fn write_octal_zero(field: &mut [u8]) {
    let (last, digits) = field.split_last_mut().expect("header fields are not empty");
    digits.fill(b'0');
    *last = 0;
}

fn unrepeatable_name() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "an entry name npm keeps that can't be handed on: it holds a NUL or passes the record limit",
    )
}

/// A header block as npm's tar decodes it.
enum Decoded {
    /// Decoding refused a number; npm warns and reads on.
    Throws,
    /// A block npm reads as a null block.
    Null,
    Header(Header),
}

struct Header {
    /// The type code, `0` for an old file's empty one.
    code: Code,
    raw_code: u8,
    path: String,
    linkpath: String,
    size: u64,
    checksum_valid: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Code {
    Known(u8),
    Unsupported,
}

enum Kind {
    Meta(Meta),
    Unpacked,
    Skipped,
}

#[derive(Clone, Copy)]
enum Meta {
    Extended,
    Global,
    LongPath,
    LongLink,
}

impl Header {
    /// Whether npm's tar reads the fields records supply from its records: its
    /// type is a normal one, or the empty type of an old file.
    fn is_normal_type(&self) -> bool {
        self.raw_code == 0 || is_normal_type(self.raw_code)
    }

    fn is_link(&self) -> bool {
        matches!(self.code, Code::Known(b'1' | b'2'))
    }

    /// Whether npm's tar makes an entry of it.
    fn accepted(&self) -> bool {
        if !self.checksum_valid || self.path.is_empty() {
            return false;
        }
        let pax = matches!(self.code, Code::Known(b'g' | b'x'));
        if self.is_link() {
            !self.linkpath.is_empty()
        } else {
            pax || self.linkpath.is_empty()
        }
    }

    fn kind(&self) -> Kind {
        match self.code {
            Code::Known(b'x' | b'X') => Kind::Meta(Meta::Extended),
            Code::Known(b'g') => Kind::Meta(Meta::Global),
            Code::Known(b'L' | b'N') => Kind::Meta(Meta::LongPath),
            Code::Known(b'K') => Kind::Meta(Meta::LongLink),
            Code::Known(code) if is_normal_type(code) => Kind::Unpacked,
            _ => Kind::Skipped,
        }
    }

    /// A file header npm reads as a directory, because its path ends in `/`.
    fn directory_from_file(&self) -> bool {
        self.code == Code::Known(b'5') && self.raw_code != b'5'
    }
}

/// The types npm's tar unpacks, or parses and skips as devices, which records
/// can describe.
fn is_normal_type(code: u8) -> bool {
    matches!(code, b'0' | b'1'..=b'7' | b'D')
}

/// The type codes npm's tar knows; any other is `Unsupported`.
fn is_known_type(code: u8) -> bool {
    is_normal_type(code)
        || matches!(
            code,
            b'g' | b'x' | b'A' | b'I' | b'K' | b'L' | b'M' | b'N' | b'S' | b'V' | b'X'
        )
}

/// Decodes a header block as node-tar's `Header` does, with the extended
/// header state that applies to it.
fn decode(block: &[u8; 512], local: &Extended, global: &Extended) -> Decoded {
    let raw_code = block[156];
    let normal = raw_code == 0 || is_normal_type(raw_code);
    let supplied = |field: fn(&Extended) -> bool| normal && (field(local) || field(global));
    let mut numbers_valid = true;
    let mut number = |range: std::ops::Range<usize>| match decode_number(&block[range]) {
        Ok(value) => value,
        Err(Refused) => {
            numbers_valid = false;
            None
        }
    };
    number(100..108);
    if !supplied(|extended| extended.uid) {
        number(108..116);
    }
    if !supplied(|extended| extended.gid) {
        number(116..124);
    }
    let raw_size = if supplied(|extended| extended.size.is_some()) {
        None
    } else {
        Some(number(124..136))
    };
    if !supplied(|extended| extended.mtime) {
        number(136..148);
    }
    let checksum = number(148..160);
    let ustar = &block[257..265] == b"ustar\x0000";
    let long_prefix = block[475] != 0;
    if ustar {
        number(329..337);
        number(337..345);
        if !long_prefix {
            // npm reads these with the local and global records whatever the type.
            if !(local.atime || global.atime) {
                number(476..488);
            }
            if !(local.ctime || global.ctime) {
                number(488..500);
            }
        }
    }
    if !numbers_valid {
        return Decoded::Throws;
    }
    let sum = 8 * 0x20
        + block[..148]
            .iter()
            .map(|&byte| i64::from(byte))
            .sum::<i64>()
        + block[156..]
            .iter()
            .map(|&byte| i64::from(byte))
            .sum::<i64>();
    if checksum.is_none() && sum == 8 * 0x20 {
        return Decoded::Null;
    }

    let mut path = match (normal, &local.path) {
        (true, Some(path)) => path.clone(),
        _ => js_decode_string(&block[..100]),
    };
    // npm decides the type from the path before it joins the ustar prefix.
    let names_directory = path.ends_with('/');
    if ustar {
        if long_prefix {
            path = format!("{}/{path}", js_decode_string(&block[345..500]));
        } else {
            let prefix = js_decode_string(&block[345..475]);
            if !prefix.is_empty() {
                path = format!("{prefix}/{path}");
            }
        }
    }
    let mut code = match raw_code {
        0 => Code::Known(b'0'),
        code if is_known_type(code) => Code::Known(code),
        _ => Code::Unsupported,
    };
    if code == Code::Known(b'0') && names_directory {
        code = Code::Known(b'5');
    }
    let size = if code == Code::Known(b'5') {
        0
    } else {
        let value = match raw_size {
            Some(raw) => raw,
            None => local.size.or(global.size).map(|size| size as i128),
        };
        value.and_then(|size| u64::try_from(size).ok()).unwrap_or(0)
    };
    Decoded::Header(Header {
        code,
        raw_code,
        path,
        linkpath: js_decode_string(&block[157..257]),
        size,
        checksum_valid: checksum == Some(sum.into()),
    })
}

/// A numeric field npm's tar refuses to decode.
struct Refused;

/// A numeric field as node-tar decodes it: base-256 when its first byte has the
/// high bit, refused unless that byte is `0x80` or `0xff` and the value is a safe
/// integer; otherwise octal as JavaScript's `parseInt` reads it, `None` when it
/// reads no digits.
fn decode_number(field: &[u8]) -> Result<Option<i128>, Refused> {
    if field[0] & 0x80 == 0 {
        let text = String::from_utf8_lossy(field);
        let text = js_strip_nul_to_end(&text);
        return Ok(js_parse_int(js_trim(&text), 8));
    }
    match field[0] {
        0x80 => {
            let mut value: u128 = 0;
            for &byte in &field[1..] {
                value = (value << 8) | u128::from(byte);
            }
            if value > MAX_SAFE_INTEGER {
                return Err(Refused);
            }
            Ok(Some(value as i128))
        }
        0xff => {
            let mut value: u128 = 0;
            for &byte in field {
                value = (value << 8) | u128::from(byte);
            }
            let magnitude = (1u128 << (8 * field.len())) - value;
            if magnitude > MAX_SAFE_INTEGER {
                return Err(Refused);
            }
            Ok(Some(-(magnitude as i128)))
        }
        _ => Err(Refused),
    }
}

/// A PAX record's keys as node-tar's `parseKV` reads them. A size that isn't a
/// whole number written in decimal digits fails: npm would read it as a
/// JavaScript number (hexadecimal, an exponent, a fraction), which only a
/// non-canonical writer produces and which can't always be framed.
fn parse_pax(text: &str) -> io::Result<Extended> {
    let mut extended = Extended::default();
    // Each path line, and whether npm may drop it: it holds a multi-byte
    // character, which input pieces can split.
    let mut paths: Vec<(String, bool)> = Vec::new();
    let text = text.strip_suffix('\n').unwrap_or(text);
    for line in text.split('\n') {
        let Some(length) = js_parse_int(line, 10) else {
            continue;
        };
        if length != line.len() as i128 + 1 {
            continue;
        }
        let Some(rest) = slice_utf16(line, length.to_string().len() + 1) else {
            continue;
        };
        let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
        if key.is_empty() {
            continue;
        }
        let value = js_strip_nul(value);
        match key {
            "path" => paths.push((value, !line.is_ascii())),
            "linkpath" => extended.linkpath = Some(value),
            // `+value`, applied when it is not negative or NaN.
            "size" => match js_number(&value) {
                None => {}
                Some(size) if size < 0.0 => {}
                Some(size) if size.fract() == 0.0 && size <= MAX_SAFE_INTEGER as f64 => {
                    extended.size = Some(size as u64);
                }
                Some(_) => return Err(unframable_size(&value)),
            },
            "uid" => extended.uid = true,
            "gid" => extended.gid = true,
            "mtime" => extended.mtime = true,
            "atime" => extended.atime = true,
            "ctime" => extended.ctime = true,
            _ => {}
        }
    }
    let mut lines = paths.into_iter().rev();
    if let Some((primary, mut droppable)) = lines.next() {
        while droppable {
            let Some((path, earlier_droppable)) = lines.next() else {
                extended.other_paths.push(None);
                break;
            };
            if path != primary && !extended.other_paths.contains(&Some(path.clone())) {
                extended.other_paths.push(Some(path));
            }
            droppable = earlier_droppable;
        }
        extended.path = Some(primary);
    }
    Ok(extended)
}

fn differently_framed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "an entry npm may unpack under paths that frame the archive differently, or too large to hand on under each",
    )
}

fn unframable_size(value: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("a PAX size npm's tar would read as `{value}` can't be framed"),
    )
}

/// JavaScript's `Number(text)`, `None` for NaN: whitespace around a decimal
/// literal (with a sign, a fraction and an exponent), `Infinity`, or an unsigned
/// hexadecimal, octal or binary literal; empty text is 0.
fn js_number(text: &str) -> Option<f64> {
    let text = js_trim(text);
    if text.is_empty() {
        return Some(0.0);
    }
    for (prefix, radix) in [
        ("0x", 16),
        ("0X", 16),
        ("0o", 8),
        ("0O", 8),
        ("0b", 2),
        ("0B", 2),
    ] {
        if let Some(digits) = text.strip_prefix(prefix) {
            if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
                return None;
            }
            return Some(
                u128::from_str_radix(digits, radix).map_or(f64::INFINITY, |value| value as f64),
            );
        }
    }
    let (sign, unsigned) = match text.as_bytes()[0] {
        b'-' => (-1.0, &text[1..]),
        b'+' => (1.0, &text[1..]),
        _ => (1.0, text),
    };
    if unsigned == "Infinity" {
        return Some(sign * f64::INFINITY);
    }
    if !is_js_decimal(unsigned) {
        return None;
    }
    unsigned.parse::<f64>().ok().map(|value| sign * value)
}

/// JavaScript's StrUnsignedDecimalLiteral, without Infinity.
fn is_js_decimal(text: &str) -> bool {
    let (mantissa, exponent) = match text.find(['e', 'E']) {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let (whole, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    let mantissa_ok = digits(whole)
        && digits(fraction)
        && !(whole.is_empty() && fraction.is_empty())
        && (mantissa.contains('.') || !whole.is_empty());
    let exponent_ok = exponent.is_none_or(|exponent| {
        let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        !exponent.is_empty() && digits(exponent)
    });
    mantissa_ok && exponent_ok
}

/// Appends a PAX record, `<length> <key>=<value>\n`, whose length counts itself.
#[cfg(test)]
fn push_pax_record(records: &mut Vec<u8>, key: &str, value: &str) {
    let body = key.len() + value.len() + 3;
    let mut length = body + body.to_string().len();
    if length.to_string().len() > body.to_string().len() {
        length += 1;
    }
    records.extend_from_slice(format!("{length} {key}={value}\n").as_bytes());
}

/// Writes `size` into a header's size field: octal when it fits, base-256 when
/// it doesn't.
fn write_size(block: &mut [u8; 512], size: u64) {
    let field = &mut block[124..136];
    if size < 0o777_7777_7777 {
        field.copy_from_slice(format!("{size:011o}\0").as_bytes());
    } else {
        field.fill(0);
        field[0] = 0x80;
        field[4..].copy_from_slice(&size.to_be_bytes());
    }
}

/// JavaScript's `buffer.toString('utf8').replace(/\0.*/, '')`: the text up to its
/// first NUL, and after the line break that follows the NUL, if any, since `.`
/// stops at line breaks.
fn js_decode_string(bytes: &[u8]) -> String {
    js_strip_nul(&String::from_utf8_lossy(bytes))
}

fn js_strip_nul(text: &str) -> String {
    let Some(nul) = text.find('\0') else {
        return text.to_owned();
    };
    let rest = &text[nul..];
    let line_break = rest
        .char_indices()
        .find(|&(_, c)| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        .map_or(rest.len(), |(at, _)| at);
    format!("{}{}", &text[..nul], &rest[line_break..])
}

/// `text.replace(/\0.*$/, '')`: from the first NUL with no line break after it to
/// the end.
fn js_strip_nul_to_end(text: &str) -> std::borrow::Cow<'_, str> {
    for (at, c) in text.char_indices() {
        if c == '\0'
            && !text[at..]
                .chars()
                .any(|c| matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}'))
        {
            return std::borrow::Cow::Borrowed(&text[..at]);
        }
    }
    std::borrow::Cow::Borrowed(text)
}

fn is_js_whitespace(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{000B}' | '\u{000C}' | '\r' | ' ' | '\u{00A0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200A}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202F}'
                | '\u{205F}'
                | '\u{3000}'
                | '\u{FEFF}'
    )
}

fn js_trim(text: &str) -> &str {
    text.trim_matches(is_js_whitespace)
}

/// JavaScript's `parseInt(text, radix)` for radix 8 or 10: leading whitespace, an
/// optional sign, then the longest run of digits; `None` when there are none.
fn js_parse_int(text: &str, radix: u32) -> Option<i128> {
    let text = text.trim_start_matches(is_js_whitespace);
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let run = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    if run == 0 {
        return None;
    }
    // Beyond 30 digits the value no longer matters to any comparison made here.
    let value = i128::from_str_radix(&digits[..run.min(30)], radix).ok()?;
    Some(if negative { -value } else { value })
}

/// `text.slice(units)` counted in UTF-16 units, as JavaScript slices a string;
/// `None` when the cut would split a character.
fn slice_utf16(text: &str, units: usize) -> Option<&str> {
    let mut counted = 0;
    for (at, c) in text.char_indices() {
        if counted == units {
            return Some(&text[at..]);
        }
        counted += c.len_utf16();
        if counted > units {
            return None;
        }
    }
    (counted == units).then_some("")
}

fn read_retrying(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        match reader.read(buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// Reads a whole block; `false` at the end of the input, including inside a
/// block, which npm's tar drops after the last entry.
fn read_block(reader: &mut impl Read, block: &mut [u8; 512]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < block.len() {
        let read = read_retrying(reader, &mut block[filled..])?;
        if read == 0 {
            return Ok(false);
        }
        filled += read;
    }
    Ok(true)
}

fn read_exact_or_truncated(reader: &mut impl Read, buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = read_retrying(reader, &mut buffer[filled..])?;
        if read == 0 {
            return Err(truncated());
        }
        filled += read;
    }
    Ok(())
}

fn skip(reader: &mut impl Read, mut count: u64) -> io::Result<()> {
    let mut scratch = [0u8; 8192];
    while count > 0 {
        let room = (scratch.len() as u64).min(count) as usize;
        let read = read_retrying(reader, &mut scratch[..room])?;
        if read == 0 {
            return Err(truncated());
        }
        count -= read as u64;
    }
    Ok(())
}

fn truncated() -> io::Error {
    io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "tar stream ends inside an entry",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header with `name`, type `code`, `size` in its size field and
    /// `link` as its link target, checksummed.
    fn header(name: &str, code: u8, size: u64, link: &str) -> Vec<u8> {
        let mut header = tar::Header::new_ustar();
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.as_mut_bytes()[156] = code;
        header.as_mut_bytes()[157..157 + link.len()].copy_from_slice(link.as_bytes());
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    fn padded(body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        body.resize(body.len().div_ceil(512) * 512, 0);
        body
    }

    fn file(name: &str, body: &[u8]) -> Vec<u8> {
        let mut bytes = header(name, b'0', body.len() as u64, "");
        bytes.extend(padded(body));
        bytes
    }

    /// A meta record of type `code` holding `body`.
    fn record(code: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = header("././@LongLink", code, body.len() as u64, "");
        bytes.extend(padded(body));
        bytes
    }

    fn pax(records: &[(&str, &str)]) -> Vec<u8> {
        let mut body = Vec::new();
        for (key, value) in records {
            push_pax_record(&mut body, key, value);
        }
        body
    }

    fn end() -> Vec<u8> {
        vec![0; 1024]
    }

    /// An entry as the tar crate reads it: path, type, size, link target.
    type Listed = (String, u8, u64, Option<String>);

    /// The entries the tar crate reads from the stream.
    fn entries(stream: &[u8]) -> io::Result<Vec<Listed>> {
        let mut archive = tar::Archive::new(NpmTarStream::new(stream));
        archive.set_ignore_zeros(true);
        let mut found = Vec::new();
        for entry in archive.entries()? {
            let entry = entry?;
            found.push((
                String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
                entry.header().entry_type().as_byte(),
                entry.size(),
                matches!(entry.header().entry_type().as_byte(), b'1' | b'2')
                    .then(|| entry.link_name_bytes())
                    .flatten()
                    .map(|link| String::from_utf8_lossy(&link).into_owned()),
            ));
        }
        Ok(found)
    }

    fn names(stream: &[u8]) -> Vec<String> {
        entries(stream)
            .unwrap()
            .into_iter()
            .map(|(name, ..)| name)
            .collect()
    }

    #[test]
    fn the_stream_ends_after_two_null_blocks_and_reads_past_one() {
        let mut stream = file("package/a", &[0; 600]);
        stream.extend_from_slice(&[0; 512]);
        stream.extend(file("package/b", b"b"));
        stream.extend(end());
        let archive_end = stream.len();
        stream.extend_from_slice(b"trailing bytes npm ignores");
        let mut input = stream.as_slice();
        let mut read = Vec::new();
        NpmTarStream::new(&mut input)
            .read_to_end(&mut read)
            .unwrap();
        assert_eq!(read, stream[..archive_end]);
        assert_eq!(input, b"trailing bytes npm ignores");
    }

    #[test]
    fn a_directory_s_body_is_read_as_headers_as_npm_reads_it() {
        let hidden = file("package/hidden.js", b"payload");
        let mut stream = header("package/dir/", b'5', hidden.len() as u64, "");
        stream.extend(&hidden);
        stream.extend(file("package/after.js", b"x"));
        stream.extend(end());
        let found = entries(&stream).unwrap();
        assert_eq!(found[0], ("package/dir/".into(), b'5', 0, None));
        assert_eq!(
            names(&stream),
            ["package/dir/", "package/hidden.js", "package/after.js"]
        );

        // A file header whose path ends in `/` is a directory to npm.
        let mut stream = header("package/dir/", b'0', hidden.len() as u64, "");
        stream.extend(&hidden);
        stream.extend(end());
        let found = entries(&stream).unwrap();
        assert_eq!(found[0], ("package/dir/".into(), b'5', 0, None));
        assert_eq!(found[1].0, "package/hidden.js");
    }

    #[test]
    fn a_header_npm_rejects_is_dropped_and_what_follows_is_read_as_headers() {
        let hidden = file("package/hidden.js", b"payload");
        let size = hidden.len() as u64;
        let mut bad_checksum = header("package/a.js", b'0', size, "");
        bad_checksum[148] ^= 1;
        let cases = [
            bad_checksum,
            header("", b'0', size, ""),
            header("package/link", b'2', size, ""),
            header("package/a.js", b'0', size, "target"),
            header("package/l", b'L', size, "target"),
        ];
        for rejected in cases {
            let mut stream = rejected;
            stream.extend(&hidden);
            stream.extend(end());
            assert_eq!(names(&stream), ["package/hidden.js"]);
        }
    }

    #[test]
    fn a_number_npm_refuses_drops_its_header_without_ending_a_null_run() {
        let mut refused = header("package/a.js", b'0', 0, "");
        refused[100] = 0x81;
        let mut stream = file("package/first.js", b"1");
        stream.extend(&refused);
        stream.extend(file("package/second.js", b"2"));
        stream.extend_from_slice(&[0; 512]);
        stream.extend(&refused);
        stream.extend_from_slice(&[0; 512]);
        stream.extend(file("package/after-the-end.js", b"3"));
        assert_eq!(names(&stream), ["package/first.js", "package/second.js"]);
    }

    #[test]
    fn a_null_block_npm_reads_with_a_checksum_it_can_t_decode_counts_as_null() {
        let mut null = vec![0u8; 512];
        null[148..156].copy_from_slice(b"garbage!");
        let mut stream = file("package/a.js", b"a");
        stream.extend(&null);
        stream.extend(&null);
        stream.extend(file("package/after-the-end.js", b"b"));
        assert_eq!(names(&stream), ["package/a.js"]);
    }

    #[test]
    fn records_set_the_next_entry_s_size_path_and_link_as_npm_applies_them() {
        // The PAX size frames the entry, whatever the header says.
        let mut stream = record(b'x', &pax(&[("size", "7")]));
        stream.extend(header("package/a.js", b'0', 0, ""));
        stream.extend(padded(b"payload"));
        stream.extend(end());
        assert_eq!(
            entries(&stream).unwrap(),
            [("package/a.js".into(), b'0', 7, None)]
        );

        // A global size applies to every entry after it.
        let mut stream = record(b'g', &pax(&[("size", "1")]));
        stream.extend(header("package/a.js", b'0', 0, ""));
        stream.extend(padded(b"a"));
        stream.extend(header("package/b.js", b'0', 0, ""));
        stream.extend(padded(b"b"));
        stream.extend(end());
        let sizes: Vec<u64> = entries(&stream).unwrap().iter().map(|e| e.2).collect();
        assert_eq!(sizes, [1, 1]);

        // The last record for a path wins.
        let mut stream = record(b'L', b"package/long-name.js\0");
        stream.extend(record(b'x', &pax(&[("path", "package/pax-name.js")])));
        stream.extend(file("package/short.js", b"x"));
        stream.extend(record(b'x', &pax(&[("path", "package/pax-name.js")])));
        stream.extend(record(b'L', b"package/long-name.js\0"));
        stream.extend(file("package/short.js", b"y"));
        stream.extend(end());
        assert_eq!(
            names(&stream),
            ["package/pax-name.js", "package/long-name.js"]
        );

        // A global link target applies after a local one.
        let mut stream = record(b'g', &pax(&[("linkpath", "global-target")]));
        stream.extend(record(b'K', b"local-target\0"));
        stream.extend(header("package/link", b'2', 0, "raw-target"));
        stream.extend(end());
        assert_eq!(
            entries(&stream).unwrap(),
            [("package/link".into(), b'2', 0, Some("global-target".into()))]
        );
    }

    /// The entries, with their bodies, a stream naming each entry under every
    /// name npm may give it hands on.
    fn every_name(stream: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut archive = tar::Archive::new(NpmTarStream::with_every_name(stream));
        archive.set_ignore_zeros(true);
        let mut found = Vec::new();
        for entry in archive.entries()? {
            let mut entry = entry?;
            let mut body = Vec::new();
            entry.read_to_end(&mut body)?;
            found.push((
                String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
                body,
            ));
        }
        Ok(found)
    }

    #[test]
    fn a_path_npm_may_drop_at_a_split_character_names_the_entry_both_ways_when_scanning() {
        let long = format!("package/lib/{}\u{e9}.dat", "p".repeat(120));
        let mut stream = record(b'x', &pax(&[("path", &long)]));
        stream.extend(file("package/index.js", b"payload"));
        stream.extend(file("package/after.js", b"after"));
        stream.extend(end());
        // npm reads the path line whole, or drops it and keeps the header's name.
        assert_eq!(
            every_name(&stream).unwrap(),
            [
                (long.clone(), b"payload".to_vec()),
                ("package/index.js".into(), b"payload".to_vec()),
                ("package/after.js".into(), b"after".to_vec()),
            ]
        );
        // An install unpacks the name the whole line gives.
        assert_eq!(names(&stream), [long.as_str(), "package/after.js"]);

        // Dropping the last path line leaves the one before it.
        let mut stream = record(b'x', &pax(&[("path", "package/first.js"), ("path", &long)]));
        stream.extend(file("package/index.js", b"payload"));
        stream.extend(end());
        let named: Vec<String> = every_name(&stream)
            .unwrap()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(named, [long.as_str(), "package/first.js"]);

        // A path npm can't drop, or one the header spells too, is one name.
        for (path, name) in [
            ("package/lib/a.js", "package/index.js"),
            ("package/lib/\u{e9}.js", "package/lib/\u{e9}.js"),
        ] {
            let mut stream = record(b'x', &pax(&[("path", path)]));
            stream.extend(file(name, b"x"));
            stream.extend(end());
            assert_eq!(every_name(&stream).unwrap(), [(path.into(), b"x".to_vec())]);
        }
    }

    #[test]
    fn a_path_npm_may_drop_that_frames_the_archive_differently_fails_the_scan() {
        // Read whole, the path names a directory, whose body npm reads as
        // headers; dropped, the header's name is a file with a body.
        let mut stream = record(b'x', &pax(&[("path", "package/d\u{e9}/")]));
        stream.extend(file("package/index.js", b"payload"));
        stream.extend(end());
        assert_eq!(
            every_name(&stream).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        // Past the bytes held to hand an entry on twice.
        let large = vec![b'a'; MAX_REPEATED_ENTRY_BYTES as usize + 1];
        let mut stream = record(b'x', &pax(&[("path", "package/\u{e9}.dat")]));
        stream.extend(file("package/index.js", &large));
        stream.extend(end());
        assert_eq!(
            every_name(&stream).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    /// `header` with a base-256 value too large for JavaScript in `field`, which
    /// npm refuses to decode, checksummed again.
    fn with_refused_number(mut header: Vec<u8>, field: std::ops::Range<usize>) -> Vec<u8> {
        header[field.start] = 0x81;
        header[field.start + 1..field.end].fill(0xff);
        let mut block = tar::Header::new_old();
        block.as_mut_bytes().copy_from_slice(&header[..512]);
        block.set_cksum();
        block.as_bytes().to_vec()
    }

    #[test]
    fn what_the_stream_hands_on_reads_the_same_through_a_second_pass() {
        // Records supply these fields, so npm never decodes the header's.
        let mut stream = Vec::new();
        for (key, field) in [("uid", 108..116), ("gid", 116..124), ("mtime", 136..148)] {
            stream.extend(record(b'x', &pax(&[(key, "0")])));
            let name = format!("package/{key}.js");
            stream.extend(with_refused_number(header(&name, b'0', 1, ""), field));
            stream.extend(padded(b"a"));
        }
        stream.extend(record(b'g', &pax(&[("atime", "0"), ("ctime", "0")])));
        let refused = with_refused_number(header("package/times.js", b'0', 1, ""), 476..488);
        stream.extend(with_refused_number(refused, 488..500));
        stream.extend(padded(b"t"));
        stream.extend(file("package/after.js", b"b"));
        stream.extend(end());
        let once = entries(&stream).unwrap();
        assert_eq!(once.len(), 5);

        let mut handed_on = Vec::new();
        NpmTarStream::new(stream.as_slice())
            .read_to_end(&mut handed_on)
            .unwrap();
        assert_eq!(entries(&handed_on).unwrap(), once);
    }

    #[test]
    fn a_name_no_second_pass_reads_back_whole_fails_the_read() {
        // A NUL after a line break survives npm's strip, and invalid bytes npm
        // decodes as three-byte replacement characters can carry a name past the
        // record limit.
        let mut with_nul = record(b'L', b"package/a\0b\nc.js\0");
        with_nul.extend(file("package/short.js", b"x"));
        with_nul.extend(end());
        let mut invalid = b"package/".to_vec();
        invalid.extend(std::iter::repeat_n(0xff, 400_000));
        invalid.push(0);
        let mut too_long = record(b'L', &invalid);
        too_long.extend(file("package/short.js", b"x"));
        too_long.extend(end());
        for stream in [with_nul, too_long] {
            let mut sink = Vec::new();
            let error = NpmTarStream::new(stream.as_slice())
                .read_to_end(&mut sink)
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn a_record_past_npm_s_limit_is_skipped_without_being_applied() {
        let mut long_path = b"package/hidden.js".to_vec();
        long_path.resize(MAX_META_BYTES as usize + 1, b'a');
        let mut stream = record(b'L', &long_path);
        stream.extend(file("package/shown.js", b"x"));
        stream.extend(end());
        assert_eq!(names(&stream), ["package/shown.js"]);
    }

    #[test]
    fn an_entry_of_a_type_npm_skips_is_dropped_with_its_payload() {
        let mut stream = header("package/sparse", b'S', 512, "");
        stream.extend(file("package/inside.js", b"x"));
        stream.extend(file("package/after.js", b"y"));
        stream.extend(end());
        assert_eq!(names(&stream), ["package/after.js"]);
    }

    #[test]
    fn pax_sizes_npm_reads_as_javascript_numbers_frame_or_fail_as_npm_would() {
        let sized = |size: &str| {
            let mut stream = record(b'x', &pax(&[("size", size)]));
            stream.extend(header("package/a.js", b'0', 1, ""));
            stream.extend(padded(b"a"));
            stream.extend(end());
            entries(&stream).map(|found| found[0].2)
        };
        assert_eq!(sized("1").unwrap(), 1);
        assert_eq!(sized("-5").unwrap(), 1);
        assert_eq!(sized("not a number").unwrap(), 1);
        assert_eq!(sized("-0").unwrap(), 0);
        assert_eq!(sized(" 0x1 ").unwrap(), 1);
        assert!(sized("1.5").is_err());
        assert!(sized("Infinity").is_err());
        assert!(sized("9007199254740993").is_err());
    }

    /// Hands out its chunks, then counts the reads made after its end.
    struct EndCounting<'a> {
        chunks: std::collections::VecDeque<&'a [u8]>,
        reads_after_end: usize,
    }

    impl Read for EndCounting<'_> {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            let Some(chunk) = self.chunks.front_mut() else {
                self.reads_after_end += 1;
                return Ok(0);
            };
            let count = chunk.len().min(output.len());
            output[..count].copy_from_slice(&chunk[..count]);
            *chunk = &chunk[count..];
            if chunk.is_empty() {
                self.chunks.pop_front();
            }
            Ok(count)
        }
    }

    #[test]
    fn input_that_ends_inside_an_entry_fails_and_a_partial_last_block_is_dropped() {
        let whole = file("package/a", &[7; 600]);
        let mut input = EndCounting {
            chunks: [&whole[..1024]].into_iter().collect(),
            reads_after_end: 0,
        };
        let mut read = Vec::new();
        let error = NpmTarStream::new(&mut input)
            .read_to_end(&mut read)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);

        let mut with_partial = whole.clone();
        with_partial.extend_from_slice(&[1; 100]);
        let mut input = EndCounting {
            chunks: [with_partial.as_slice()].into_iter().collect(),
            reads_after_end: 0,
        };
        let mut archive = NpmTarStream::new(&mut input);
        let mut read = Vec::new();
        archive.read_to_end(&mut read).unwrap();
        let mut more = [0u8; 16];
        assert_eq!(archive.read(&mut more).unwrap(), 0);
        assert_eq!(read.len(), whole.len());
        assert_eq!(input.reads_after_end, 1);
    }
}
