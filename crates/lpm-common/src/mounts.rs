//! The mounts a process sees, as Linux's mount table lists them, and where
//! an NFS mount's files are, which its source names.

use std::path::{Path, PathBuf};

/// One mount: the filesystem's device (`major:minor`), the directory of it
/// the mount shows, where it shows it, the filesystem's type, and the files
/// it shows (`shows`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub filesystem: String,
    /// The filesystem the mount shows, as a key, and the directory's path
    /// on it: the device and `root`, or for NFS the server and the path the
    /// mount's source names ([`nfs_location`]). `None` where the line
    /// doesn't tell.
    pub shows: Option<(String, PathBuf)>,
}

/// Where an NFS mount's files are, from its source (`server:/path`) and
/// its options: NFS writes `/` as every mount's root (its `show_path`), and
/// its mounts of one server filesystem share a device only when they share
/// a superblock, which any differing option prevents, while the source
/// names the server directory the mount shows, a bind's included. The
/// server is the `addr=` option where there is one, and NFS 4's paths are
/// another space than 2's and 3's, so the major version is part of the key.
pub fn nfs_location(source: &[u8], options: &[u8]) -> Option<(String, PathBuf)> {
    use std::os::unix::ffi::OsStringExt as _;
    let (server, path) = match source.strip_prefix(b"[") {
        Some(bracketed) => {
            let end = bracketed.iter().position(|byte| *byte == b']')?;
            (&bracketed[..end], bracketed[end + 1..].strip_prefix(b":")?)
        }
        None => {
            let colon = source.iter().position(|byte| *byte == b':')?;
            (&source[..colon], &source[colon + 1..])
        }
    };
    if server.is_empty() || !path.starts_with(b"/") {
        return None;
    }
    let option = |name: &[u8]| {
        options
            .split(|byte| *byte == b',')
            .find_map(|option| option.strip_prefix(name))
    };
    let server = option(b"addr=").unwrap_or(server);
    let version = option(b"vers=")
        .and_then(|version| version.split(|byte| *byte == b'.').next())
        .unwrap_or_default();
    Some((
        format!(
            "nfs {} {}",
            String::from_utf8_lossy(server),
            String::from_utf8_lossy(version)
        ),
        PathBuf::from(std::ffi::OsString::from_vec(path.to_vec())),
    ))
}

/// Room for a container's thousands of mounts.
#[cfg(target_os = "linux")]
const MOUNT_TABLE_CAP_BYTES: u64 = 16 * 1024 * 1024;

/// This process's mount table, in mount order: a later mount at a point
/// hides an earlier one there.
#[cfg(target_os = "linux")]
pub fn mount_table() -> std::io::Result<Vec<Mount>> {
    let table = crate::read_file_capped(Path::new("/proc/self/mountinfo"), MOUNT_TABLE_CAP_BYTES)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    parse_mount_table(&table)
}

/// The mounts a `/proc/<pid>/mountinfo` table lists, all of them: a line
/// that names no mount, or a table without one, is an error, as a mount
/// left out could be the one that matters.
pub fn parse_mount_table(table: &[u8]) -> std::io::Result<Vec<Mount>> {
    use std::os::unix::ffi::OsStringExt as _;
    let path = |field: &[u8]| PathBuf::from(std::ffi::OsString::from_vec(unescaped(field)));
    let mounts = table
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| {
            let malformed = || {
                std::io::Error::other(format!(
                    "a mount table line names no mount: {:?}",
                    String::from_utf8_lossy(line)
                ))
            };
            // ID, parent ID, device, root, mount point, the mount's options,
            // optional fields up to a `-`, then the filesystem's type, its
            // source, which can be empty (`mount -t tmpfs "" /x`), and its
            // options.
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
            let field = |index: usize| {
                fields
                    .get(index)
                    .copied()
                    .filter(|field| !field.is_empty())
                    .ok_or_else(malformed)
            };
            let device = String::from_utf8_lossy(field(2)?).into_owned();
            let root = path(field(3)?);
            let mount_point = path(field(4)?);
            field(5)?;
            let separator = (6..fields.len())
                .find(|index| fields[*index] == b"-")
                .ok_or_else(malformed)?;
            let filesystem = String::from_utf8_lossy(field(separator + 1)?).into_owned();
            let source = unescaped(fields.get(separator + 2).copied().unwrap_or_default());
            let options = fields.get(separator + 3).copied().unwrap_or_default();
            let shows = if matches!(filesystem.as_str(), "nfs" | "nfs4") {
                nfs_location(&source, options)
            } else {
                Some((device.clone(), root.clone()))
            };
            Ok(Mount {
                device,
                root,
                mount_point,
                filesystem,
                shows,
            })
        })
        .collect::<std::io::Result<Vec<Mount>>>()?;
    if mounts.is_empty() {
        return Err(std::io::Error::other("the mount table lists no mounts"));
    }
    Ok(mounts)
}

/// A mount table path, whose space, tab, line feed and backslash the kernel
/// writes as octal escapes (`\040`).
fn unescaped(field: &[u8]) -> Vec<u8> {
    let mut path = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, after)) = rest.split_first() {
        let octal = if byte == b'\\' {
            after
                .get(..3)
                .filter(|digits| digits.iter().all(|digit| (b'0'..=b'7').contains(digit)))
                .and_then(|digits| {
                    let value = digits
                        .iter()
                        .fold(0u16, |value, digit| value * 8 + u16::from(digit - b'0'));
                    u8::try_from(value).ok()
                })
        } else {
            None
        };
        match octal {
            Some(value) => {
                path.push(value);
                rest = &after[3..];
            }
            None => {
                path.push(byte);
                rest = after;
            }
        }
    }
    path
}

/// Where the files at `path`, absolute and without links, are: the key of
/// the filesystem the mount holding them shows and their path on it
/// ([`Mount::shows`]). `None` where no mount holds `path` or the one that
/// does doesn't tell.
pub fn filesystem_location<'table>(
    table: &'table [Mount],
    path: &Path,
) -> Option<(&'table str, PathBuf)> {
    let (_, mount) = table
        .iter()
        .enumerate()
        .filter(|(_, mount)| path.starts_with(&mount.mount_point))
        .max_by_key(|(index, mount)| (mount.mount_point.components().count(), *index))?;
    let (key, files) = mount.shows.as_ref()?;
    let below = path.strip_prefix(&mount.mount_point).ok()?;
    Some((key.as_str(), files.join(below)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TABLE: &[u8] = b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
        30 22 8:2 / /home rw - ext4 /dev/sda2 rw\n\
        31 30 8:2 /u/a\\040b /mnt/a\\040b rw - ext4 /dev/sda2 rw\n\
        32 22 8:3 / /home rw - ext4 /dev/sda3 rw\n";

    #[test]
    fn the_mount_table_reads_as_the_kernel_escapes_it() {
        let table = parse_mount_table(TABLE).unwrap();
        assert_eq!(table.len(), 4);
        assert_eq!(table[2].root, Path::new("/u/a b"));
        assert_eq!(table[2].mount_point, Path::new("/mnt/a b"));
        assert_eq!(
            unescaped(b"/mnt/a\\040b\\134c\\011\\777\\04"),
            b"/mnt/a b\\c\t\\777\\04"
        );
    }

    #[test]
    fn a_mount_table_that_leaves_a_mount_out_is_no_table() {
        for table in [
            &b""[..],
            b"\n",
            b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n30 22 8:2\n",
            b"22 1 8:1  / rw - ext4 /dev/sda1 rw\n",
            b"22 1 8:1 / / rw ext4 /dev/sda1 rw\n",
            b"22 1 8:1 / / rw shared:1 -\n",
        ] {
            assert!(
                parse_mount_table(table).is_err(),
                "{:?}",
                String::from_utf8_lossy(table)
            );
        }
    }

    /// `mount -t tmpfs "" /x` leaves the source empty, which the kernel
    /// writes as nothing between two spaces.
    #[test]
    fn a_mount_with_an_empty_source_is_still_a_mount() {
        let table = parse_mount_table(
            b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
              40 22 0:60 / /x rw - tmpfs  rw\n\
              41 22 0:61 / /n rw - nfs4  rw,vers=4.2,addr=10.0.0.5\n",
        )
        .unwrap();
        assert_eq!(table[1].mount_point, Path::new("/x"));
        assert_eq!(
            table[1].shows,
            Some(("0:60".to_string(), PathBuf::from("/")))
        );
        assert_eq!(table[2].shows, None);
    }

    #[test]
    fn a_mount_s_filesystem_follows_its_optional_fields() {
        let table = parse_mount_table(
            b"36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 shared:2 - ext3 /dev/root rw\n\
              37 35 0:52 / /home/u rw - nfs4 fs1:/export/home/u rw,vers=4.2,addr=10.0.0.5\n",
        )
        .unwrap();
        assert_eq!(table[0].filesystem, "ext3");
        assert_eq!(
            table[0].shows,
            Some(("98:0".to_string(), PathBuf::from("/mnt1")))
        );
        assert_eq!(table[1].filesystem, "nfs4");
        assert_eq!(
            table[1].shows,
            Some((
                "nfs 10.0.0.5 4".to_string(),
                PathBuf::from("/export/home/u")
            ))
        );
    }

    /// NFS writes `/` as the root of each of its mounts and gives a mount
    /// with other options its own device; its source names the server
    /// directory it shows, a bind's included.
    #[test]
    fn a_path_on_nfs_is_placed_by_its_server_and_the_directory_its_source_names() {
        let table = parse_mount_table(
            b"22 1 8:1 / / rw - ext4 /dev/sda1 rw\n\
              50 22 0:52 / /home/u rw - nfs4 fs1:/export/home/u rw,vers=4.2,addr=10.0.0.5\n\
              51 22 0:53 / /net/fs1 rw - nfs4 fs1:/ rw,vers=4.1,soft,addr=10.0.0.5\n\
              52 50 0:52 / /srv/certs rw - nfs4 fs1:/export/home/u/.lpm/certs rw,vers=4.2,addr=10.0.0.5\n\
              53 22 0:54 / /old rw - nfs fs1:/export rw,vers=3,addr=10.0.0.5\n",
        )
        .unwrap();
        let key = "nfs 10.0.0.5 4";
        assert_eq!(
            filesystem_location(&table, Path::new("/home/u/x")),
            Some((key, PathBuf::from("/export/home/u/x")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/net/fs1/export/home")),
            Some((key, PathBuf::from("/export/home")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/srv/certs/ca.pem")),
            Some((key, PathBuf::from("/export/home/u/.lpm/certs/ca.pem")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/old/home")),
            Some(("nfs 10.0.0.5 3", PathBuf::from("/export/home")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/etc")),
            Some(("8:1", PathBuf::from("/etc")))
        );
    }

    #[test]
    fn an_nfs_source_names_its_server_and_directory() {
        assert_eq!(
            nfs_location(b"[fd00::5]:/export", b"rw,vers=4.2"),
            Some(("nfs fd00::5 4".to_string(), PathBuf::from("/export")))
        );
        assert_eq!(
            nfs_location(b"fs1:/export", b""),
            Some(("nfs fs1 ".to_string(), PathBuf::from("/export")))
        );
        for source in [&b"fs1"[..], b"fs1:export", b":/export", b"[fd00::5]/export"] {
            assert_eq!(
                nfs_location(source, b""),
                None,
                "{:?}",
                String::from_utf8_lossy(source)
            );
        }
    }

    #[test]
    fn a_path_is_where_the_last_mount_holding_it_shows_it() {
        let table = parse_mount_table(TABLE).unwrap();
        assert_eq!(
            filesystem_location(&table, Path::new("/home/u/x")),
            Some(("8:3", PathBuf::from("/u/x")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/mnt/a b/c")),
            Some(("8:2", PathBuf::from("/u/a b/c")))
        );
        assert_eq!(
            filesystem_location(&table, Path::new("/etc")),
            Some(("8:1", PathBuf::from("/etc")))
        );
    }
}
