//! The CPU architecture and C library a native executable was built for, read
//! from its header without running it.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::OnceLock;

/// The furthest into a file that a header field is read from.
const MAX_HEADER_OFFSET: u64 = 64 * 1024;
const MAX_INTERPRETER_BYTES: u64 = 256;
const PT_INTERP: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BinaryTarget {
    pub(crate) arch: &'static str,
    /// `glibc` or `musl` for a dynamically linked ELF executable.
    pub(crate) libc: Option<&'static str>,
}

/// The target of the native executable at `path`. `None` for a file that
/// isn't one, or a universal Mach-O binary, whose architecture is chosen when
/// it starts.
pub(crate) fn binary_target(path: &Path) -> Option<BinaryTarget> {
    let mut file = File::open(path).ok()?;
    let mut header = [0_u8; 64];
    let read = read_up_to(&mut file, &mut header)?;
    let header = &header[..read];
    match header.get(..4)? {
        [0x7f, b'E', b'L', b'F'] => elf_target(&mut file, header),
        [0xcf, 0xfa, 0xed, 0xfe] | [0xce, 0xfa, 0xed, 0xfe] => Some(BinaryTarget {
            arch: mach_o_arch(u32::from_le_bytes(header.get(4..8)?.try_into().ok()?))?,
            libc: None,
        }),
        [0xfe, 0xed, 0xfa, 0xcf] | [0xfe, 0xed, 0xfa, 0xce] => Some(BinaryTarget {
            arch: mach_o_arch(u32::from_be_bytes(header.get(4..8)?.try_into().ok()?))?,
            libc: None,
        }),
        [b'M', b'Z', _, _] => pe_target(&mut file, header),
        _ => None,
    }
}

/// The host's C library: the one its shell is linked against. A loader that is
/// merely installed, as `musl-tools` installs one on a glibc system, doesn't
/// count.
pub(crate) fn host_libc() -> Option<&'static str> {
    static HOST_LIBC: OnceLock<Option<&'static str>> = OnceLock::new();
    *HOST_LIBC.get_or_init(|| {
        if !cfg!(target_os = "linux") {
            return None;
        }
        binary_target(Path::new("/bin/sh"))
            .and_then(|target| target.libc)
            .or_else(lpm_common::platform::detect_libc)
    })
}

fn read_up_to(file: &mut File, buffer: &mut [u8]) -> Option<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]).ok()? {
            0 => break,
            read => filled += read,
        }
    }
    Some(filled)
}

fn read_at(file: &mut File, offset: u64, buffer: &mut [u8]) -> Option<()> {
    if offset > MAX_HEADER_OFFSET {
        return None;
    }
    file.seek(SeekFrom::Start(offset)).ok()?;
    file.read_exact(buffer).ok()
}

/// Reads integers in one byte order.
#[derive(Clone, Copy)]
struct Endian {
    little: bool,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> Option<u16> {
        let bytes = bytes.get(..2)?.try_into().ok()?;
        Some(if self.little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        })
    }

    fn u32(self, bytes: &[u8]) -> Option<u32> {
        let bytes = bytes.get(..4)?.try_into().ok()?;
        Some(if self.little {
            u32::from_le_bytes(bytes)
        } else {
            u32::from_be_bytes(bytes)
        })
    }

    fn u64(self, bytes: &[u8]) -> Option<u64> {
        let bytes = bytes.get(..8)?.try_into().ok()?;
        Some(if self.little {
            u64::from_le_bytes(bytes)
        } else {
            u64::from_be_bytes(bytes)
        })
    }
}

fn elf_target(file: &mut File, header: &[u8]) -> Option<BinaryTarget> {
    let wide = match header.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let endian = Endian {
        little: *header.get(5)? == 1,
    };
    let arch = match endian.u16(header.get(18..)?)? {
        0x03 => "x86",
        0x3e => "x86_64",
        0x28 => "arm",
        0xb7 => "aarch64",
        0xf3 => "riscv64",
        0x15 => "powerpc64",
        0x16 => "s390x",
        0x102 => "loongarch64",
        _ => return None,
    };
    Some(BinaryTarget {
        arch,
        libc: elf_interpreter(file, header, wide, endian).and_then(|interpreter| {
            if interpreter.contains("musl") {
                Some("musl")
            } else if interpreter.contains("ld-linux") || interpreter.contains("ld64.so") {
                Some("glibc")
            } else {
                None
            }
        }),
    })
}

/// The dynamic loader an ELF executable names, from its `PT_INTERP` segment.
fn elf_interpreter(file: &mut File, header: &[u8], wide: bool, endian: Endian) -> Option<String> {
    let (table, entry_size, entries) = if wide {
        (
            endian.u64(header.get(0x20..)?)?,
            endian.u16(header.get(0x36..)?)?,
            endian.u16(header.get(0x38..)?)?,
        )
    } else {
        (
            u64::from(endian.u32(header.get(0x1c..)?)?),
            endian.u16(header.get(0x2a..)?)?,
            endian.u16(header.get(0x2c..)?)?,
        )
    };
    let mut entry = [0_u8; 0x38];
    let entry = entry.get_mut(..usize::from(entry_size))?;
    for index in 0..u64::from(entries) {
        read_at(file, table + index * u64::from(entry_size), entry)?;
        if endian.u32(entry)? != PT_INTERP {
            continue;
        }
        let (offset, size) = if wide {
            (
                endian.u64(entry.get(0x08..)?)?,
                endian.u64(entry.get(0x20..)?)?,
            )
        } else {
            (
                u64::from(endian.u32(entry.get(0x04..)?)?),
                u64::from(endian.u32(entry.get(0x10..)?)?),
            )
        };
        let mut interpreter = vec![0_u8; usize::try_from(size.min(MAX_INTERPRETER_BYTES)).ok()?];
        read_at(file, offset, &mut interpreter)?;
        let end = interpreter
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(interpreter.len());
        return String::from_utf8(interpreter[..end].to_vec()).ok();
    }
    None
}

fn mach_o_arch(cpu_type: u32) -> Option<&'static str> {
    match cpu_type {
        0x0100_0007 => Some("x86_64"),
        0x0100_000c => Some("aarch64"),
        0x07 => Some("x86"),
        0x0c => Some("arm"),
        _ => None,
    }
}

fn pe_target(file: &mut File, header: &[u8]) -> Option<BinaryTarget> {
    let signature_offset = u64::from(u32::from_le_bytes(header.get(0x3c..0x40)?.try_into().ok()?));
    let mut signature = [0_u8; 6];
    read_at(file, signature_offset, &mut signature)?;
    if signature[..4] != *b"PE\0\0" {
        return None;
    }
    let arch = match u16::from_le_bytes([signature[4], signature[5]]) {
        0x8664 => "x86_64",
        0xaa64 => "aarch64",
        0x014c => "x86",
        _ => return None,
    };
    Some(BinaryTarget { arch, libc: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    }

    /// A 64-bit little-endian ELF header for `machine`, with one `PT_INTERP`
    /// segment naming `interpreter`.
    fn elf64(machine: u16, interpreter: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8; 0x40 + 0x38];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[0x20..0x28].copy_from_slice(&0x40_u64.to_le_bytes());
        bytes[0x36..0x38].copy_from_slice(&0x38_u16.to_le_bytes());
        bytes[0x38..0x3a].copy_from_slice(&1_u16.to_le_bytes());
        let segment = 0x40;
        let offset = bytes.len() as u64;
        bytes[segment..segment + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
        bytes[segment + 8..segment + 16].copy_from_slice(&offset.to_le_bytes());
        let size = interpreter.len() as u64 + 1;
        bytes[segment + 0x20..segment + 0x28].copy_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(interpreter.as_bytes());
        bytes.push(0);
        bytes
    }

    #[test]
    fn elf_names_its_architecture_and_c_library_from_its_loader() {
        let dir = tempfile::tempdir().unwrap();
        let glibc = write(
            dir.path(),
            "glibc",
            &elf64(0x3e, "/lib64/ld-linux-x86-64.so.2"),
        );
        let musl = write(
            dir.path(),
            "musl",
            &elf64(0xb7, "/lib/ld-musl-aarch64.so.1"),
        );
        assert_eq!(
            binary_target(&glibc),
            Some(BinaryTarget {
                arch: "x86_64",
                libc: Some("glibc")
            })
        );
        assert_eq!(
            binary_target(&musl),
            Some(BinaryTarget {
                arch: "aarch64",
                libc: Some("musl")
            })
        );
    }

    #[test]
    fn a_static_elf_has_no_c_library() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = elf64(0x3e, "");
        bytes[0x38..0x3a].copy_from_slice(&0_u16.to_le_bytes());
        let path = write(dir.path(), "static", &bytes);
        assert_eq!(
            binary_target(&path),
            Some(BinaryTarget {
                arch: "x86_64",
                libc: None
            })
        );
    }

    #[test]
    fn mach_o_names_its_architecture_and_a_universal_binary_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let mut arm = vec![0_u8; 32];
        arm[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        arm[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
        let mut intel = arm.clone();
        intel[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
        let mut universal = vec![0_u8; 32];
        universal[..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        assert_eq!(
            binary_target(&write(dir.path(), "arm", &arm)).map(|target| target.arch),
            Some("aarch64")
        );
        assert_eq!(
            binary_target(&write(dir.path(), "intel", &intel)).map(|target| target.arch),
            Some("x86_64")
        );
        assert_eq!(binary_target(&write(dir.path(), "fat", &universal)), None);
    }

    #[test]
    fn pe_names_its_architecture() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0_u8; 0x86];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0xaa64_u16.to_le_bytes());
        assert_eq!(
            binary_target(&write(dir.path(), "node.exe", &bytes)),
            Some(BinaryTarget {
                arch: "aarch64",
                libc: None
            })
        );
    }

    #[test]
    fn truncated_or_foreign_files_have_no_target() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(binary_target(&write(dir.path(), "empty", b"")), None);
        assert_eq!(
            binary_target(&write(dir.path(), "script", b"#!/bin/sh\n")),
            None
        );
        assert_eq!(
            binary_target(&write(dir.path(), "elf", b"\x7fELF\x02\x01")),
            None
        );
    }

    #[test]
    fn the_running_test_binary_matches_its_own_build_target() {
        let target = binary_target(&std::env::current_exe().unwrap());
        if cfg!(any(target_os = "linux", target_os = "macos", windows)) {
            assert_eq!(
                target.map(|target| target.arch),
                Some(std::env::consts::ARCH)
            );
        }
    }
}
