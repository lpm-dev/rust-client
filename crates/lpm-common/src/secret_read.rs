//! Reading text that may hold secrets, such as an env value or a .env file,
//! from a file, a pipe or standard input. Every buffer that held the bytes
//! is wiped: one that has to grow is copied into a larger one and wiped
//! rather than left in freed memory, and the caller's text is wiped when it's
//! dropped.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use zeroize::{Zeroize as _, Zeroizing};

/// Why text that may hold secrets couldn't be read.
#[derive(Debug)]
pub enum SecretReadError {
    NotFound,
    Directory,
    /// Neither a file nor a pipe, such as a terminal or another device, which
    /// could wait for input or never end.
    NotFileOrPipe,
    /// More bytes than the limit.
    TooLarge,
    /// Not UTF-8 text.
    NotText,
    Io(io::Error),
}

impl std::fmt::Display for SecretReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("it doesn't exist"),
            Self::Directory => formatter.write_str("it's a directory"),
            Self::NotFileOrPipe => formatter.write_str("it isn't a file or a pipe"),
            Self::TooLarge => formatter.write_str("it's larger than the limit"),
            Self::NotText => formatter.write_str("it isn't UTF-8 text"),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SecretReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

const INITIAL_CAPACITY: usize = 8 * 1024;

/// All of `reader`, at most `limit` bytes, as UTF-8 text.
pub fn read_secret_text<R: Read>(
    reader: R,
    limit: usize,
) -> Result<Zeroizing<String>, SecretReadError> {
    into_text(read_wiped(reader, limit, 0)?)
}

/// The file or pipe at `path`, at most `limit` bytes, as UTF-8 text, such as
/// a file or the `/dev/fd` path of a shell's process substitution. A named
/// pipe is read as any reader reads one, once a writer opens it; a directory
/// or a device, such as a terminal, which would show what's typed, is
/// refused.
pub fn read_secret_text_file(
    path: &Path,
    limit: usize,
) -> Result<Zeroizing<String>, SecretReadError> {
    let (file, size) = open_file_or_pipe(path, limit)?;
    #[cfg(unix)]
    let reader = WaitingForInput(&file);
    #[cfg(not(unix))]
    let reader = &file;
    into_text(read_wiped(reader, limit, size)?)
}

fn open_file_or_pipe(path: &Path, limit: usize) -> Result<(File, usize), SecretReadError> {
    // Windows opens no directory as a file, and says only that access is
    // denied.
    #[cfg(windows)]
    if std::fs::metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        return Err(SecretReadError::Directory);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // Opening a device can wait for it, so only a named pipe, which waits
    // for its writer, is opened in a way that can. Whatever the path names
    // once it's open decides.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};

        let named_pipe =
            std::fs::metadata(path).is_ok_and(|metadata| metadata.file_type().is_fifo());
        options.custom_flags(if named_pipe {
            libc::O_CLOEXEC
        } else {
            libc::O_CLOEXEC | libc::O_NONBLOCK
        });
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            SecretReadError::NotFound
        } else {
            SecretReadError::Io(error)
        }
    })?;
    // Windows gives no metadata for a pipe or a device, so its kind decides
    // first.
    #[cfg(windows)]
    match windows_kind(&file) {
        WindowsKind::Disk => {}
        WindowsKind::Pipe => return Ok((file, 0)),
        WindowsKind::Other => return Err(SecretReadError::NotFileOrPipe),
    }
    let metadata = file.metadata().map_err(SecretReadError::Io)?;
    if metadata.is_dir() {
        return Err(SecretReadError::Directory);
    }
    if metadata.is_file() {
        let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if size > limit {
            return Err(SecretReadError::TooLarge);
        }
        return Ok((file, size));
    }
    if is_pipe(&file, &metadata) {
        return Ok((file, 0));
    }
    Err(SecretReadError::NotFileOrPipe)
}

#[cfg(unix)]
fn is_pipe(_file: &File, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt as _;

    metadata.file_type().is_fifo()
}

#[cfg(not(unix))]
fn is_pipe(_file: &File, _metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(windows)]
enum WindowsKind {
    Disk,
    Pipe,
    Other,
}

/// Whether a standard handle names something: a process started without
/// standard input, as a GUI or a detached process can be, has a null one,
/// and a failed lookup gives an invalid one, neither of which a `File` may
/// hold.
#[cfg(windows)]
fn is_usable_handle(handle: std::os::windows::io::RawHandle) -> bool {
    !handle.is_null() && handle != windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
}

#[cfg(windows)]
fn windows_kind(file: &File) -> WindowsKind {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, FILE_TYPE_PIPE, GetFileType};

    // SAFETY: the handle is the open file's, valid while `file` lives.
    match unsafe { GetFileType(file.as_raw_handle()) } {
        FILE_TYPE_DISK => WindowsKind::Disk,
        FILE_TYPE_PIPE => WindowsKind::Pipe,
        _ => WindowsKind::Other,
    }
}

/// Standard input, at most `limit` bytes, as UTF-8 text. It's read from its
/// descriptor, not through std's buffered stdin, whose buffer is never
/// wiped. A device, such as `/dev/zero`, is refused; the caller refuses a
/// terminal, with its own advice, first.
pub fn read_secret_stdin(limit: usize) -> Result<Zeroizing<String>, SecretReadError> {
    let stdin = io::stdin();
    #[cfg(unix)]
    // SAFETY: standard input stays open for the process, and ManuallyDrop
    // never closes it.
    let file = std::mem::ManuallyDrop::new(unsafe {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        File::from_raw_fd(stdin.as_raw_fd())
    });
    #[cfg(windows)]
    let file = {
        use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _};
        let handle = stdin.as_raw_handle();
        if !is_usable_handle(handle) {
            return Err(SecretReadError::NotFileOrPipe);
        }
        // SAFETY: the handle is standard input's, neither null nor invalid,
        // open for the process; ManuallyDrop never closes it.
        std::mem::ManuallyDrop::new(unsafe { File::from_raw_handle(handle) })
    };
    #[cfg(windows)]
    if matches!(windows_kind(&file), WindowsKind::Other) {
        return Err(SecretReadError::NotFileOrPipe);
    }
    let mut size = 0;
    if let Ok(metadata) = file.metadata() {
        if metadata.is_dir() {
            return Err(SecretReadError::Directory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt as _;
            let kind = metadata.file_type();
            if kind.is_char_device() || kind.is_block_device() {
                return Err(SecretReadError::NotFileOrPipe);
            }
        }
        if metadata.is_file() {
            size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        }
    }
    #[cfg(unix)]
    let reader = WaitingForInput(&file);
    #[cfg(windows)]
    let reader = &*file;
    into_text(read_wiped(reader, limit, size)?)
}

/// Reads that wait for input rather than fail with `WouldBlock`, for a pipe
/// opened non-blocking or a descriptor an earlier program left so, which
/// standard input and, on macOS, a `/dev/fd` path share with that program.
/// Its flags are left alone.
#[cfg(unix)]
struct WaitingForInput<'file>(&'file File);

#[cfg(unix)]
impl Read for WaitingForInput<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd as _;
        loop {
            match (&mut &*self.0).read(buffer) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    #[cfg(test)]
                    if let Some(waiting) = tests::WAITING_FOR_INPUT.get() {
                        waiting();
                    }
                    let mut ready = libc::pollfd {
                        fd: self.0.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    // SAFETY: `ready` is one valid pollfd for the call.
                    if unsafe { libc::poll(&mut ready, 1, -1) } < 0 {
                        let error = io::Error::last_os_error();
                        if error.kind() != io::ErrorKind::Interrupted {
                            return Err(error);
                        }
                    }
                }
                read => return read,
            }
        }
    }
}

/// Everything `reader` holds, refused past `limit` bytes. `size_hint`, a
/// file's length, sizes the buffer so a file that doesn't change is read
/// without growing it.
fn read_wiped(
    mut reader: impl Read,
    limit: usize,
    size_hint: usize,
) -> Result<Zeroizing<Vec<u8>>, SecretReadError> {
    // One byte past the limit tells a source that's too large from one that
    // fills it exactly.
    let most = limit.saturating_add(1);
    let capacity = size_hint
        .saturating_add(1)
        .clamp(INITIAL_CAPACITY.min(most), most);
    let mut bytes = Zeroizing::new(vec![0_u8; capacity]);
    let mut filled = 0;
    loop {
        if filled == bytes.len() {
            if filled == most {
                return Err(SecretReadError::TooLarge);
            }
            let mut grown = Zeroizing::new(vec![0_u8; filled.saturating_mul(2).min(most)]);
            grown[..filled].copy_from_slice(&bytes[..filled]);
            bytes = grown;
        }
        match reader.read(&mut bytes[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(SecretReadError::Io(error)),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

fn into_text(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, SecretReadError> {
    match String::from_utf8(std::mem::take(&mut *bytes)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(error) => {
            error.into_bytes().zeroize();
            Err(SecretReadError::NotText)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the reader that waits for input does each time it finds none.
    #[cfg(unix)]
    pub(super) static WAITING_FOR_INPUT: std::sync::OnceLock<fn()> = std::sync::OnceLock::new();

    #[cfg(windows)]
    #[test]
    fn a_missing_or_invalid_standard_handle_is_never_read() {
        assert!(!is_usable_handle(std::ptr::null_mut()));
        assert!(!is_usable_handle(
            windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE
        ));
    }

    /// Standard input an earlier program left non-blocking is still read
    /// whole: the read waits for what its writer sends. The test runs itself
    /// again as the reader, with the non-blocking end of a pipe for its
    /// standard input. The writer sends each of the value's two pieces only
    /// once the reader found the pipe empty.
    #[cfg(unix)]
    #[test]
    fn standard_input_left_non_blocking_waits_for_its_writer() {
        use std::io::{BufRead as _, Read as _, Write as _};
        use std::os::fd::FromRawFd as _;
        const READER: &str = "LPM_SECRET_READ_NON_BLOCKING_READER";
        if std::env::var_os(READER).is_some() {
            WAITING_FOR_INPUT
                .set(|| {
                    println!("waiting");
                    std::io::stdout().flush().expect("flush");
                })
                .expect("set once");
            match read_secret_stdin(64) {
                Ok(text) => println!("read: {}", text.as_str()),
                Err(error) => println!("failed: {error}"),
            }
            return;
        }
        let mut ends = [0; 2];
        // SAFETY: `ends` has room for the two descriptors `pipe` makes.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors were just made and are owned here.
        let (read_end, mut write_end) =
            unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
        // SAFETY: both ends are open; the calls read and set their flags.
        // Neither end may stay open in the reader beyond its standard
        // input, or a write end it held would keep its read from ending.
        unsafe {
            for end in ends {
                assert_eq!(libc::fcntl(end, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            }
            let flags = libc::fcntl(ends[0], libc::F_GETFL);
            assert_eq!(
                libc::fcntl(ends[0], libc::F_SETFL, flags | libc::O_NONBLOCK),
                0
            );
        }
        let mut reader = std::process::Command::new(std::env::current_exe().expect("this test"))
            .args([
                "--exact",
                "secret_read::tests::standard_input_left_non_blocking_waits_for_its_writer",
                "--nocapture",
            ])
            .env(READER, "1")
            .stdin(read_end)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("run the reader");
        let mut stdout = std::io::BufReader::new(reader.stdout.take().expect("piped"));
        let mut shown = String::new();
        // Each piece is written once the reader found the pipe empty.
        for (written, piece) in [&b"fixture-"[..], b"late"].into_iter().enumerate() {
            while shown.matches("waiting").count() <= written {
                assert_ne!(
                    stdout.read_line(&mut shown).expect("the reader's output"),
                    0,
                    "the reader ended first: {shown}"
                );
            }
            write_end.write_all(piece).expect("the reader is waiting");
        }
        drop(write_end);
        stdout
            .read_to_string(&mut shown)
            .expect("the reader's output");
        let status = reader.wait().expect("the reader ends");
        assert!(status.success(), "{shown}");
        assert!(shown.contains("read: fixture-late"), "{shown}");
    }

    /// Reading standard input takes from its descriptor no more than one byte
    /// past the limit: none of it passes through std's buffered stdin, whose
    /// buffer is never wiped and would have taken the rest. The test runs
    /// itself again as the reader, with a pipe for standard input.
    #[cfg(unix)]
    #[test]
    fn standard_input_is_read_from_its_descriptor_and_no_further_than_needed() {
        use std::io::{Read as _, Write as _};
        use std::os::fd::FromRawFd as _;
        const READER: &str = "LPM_SECRET_READ_STDIN_READER";
        if std::env::var_os(READER).is_some() {
            assert!(matches!(
                read_secret_stdin(4),
                Err(SecretReadError::TooLarge)
            ));
            // SAFETY: standard input stays open; ManuallyDrop never closes it.
            let mut stdin = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(0) });
            let mut rest = Vec::new();
            stdin
                .read_to_end(&mut rest)
                .expect("the rest of standard input");
            println!("left on the descriptor: {}", rest.len());
            return;
        }
        let mut reader = std::process::Command::new(std::env::current_exe().expect("this test"))
            .args([
                "--exact",
                "secret_read::tests::standard_input_is_read_from_its_descriptor_and_no_further_than_needed",
                "--nocapture",
            ])
            .env(READER, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("run the reader");
        reader
            .stdin
            .take()
            .expect("its standard input")
            .write_all(&[b'x'; 64])
            .expect("fill the pipe");
        let output = reader.wait_with_output().expect("the reader ends");
        let shown = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{shown}");
        assert!(shown.contains("left on the descriptor: 59"), "{shown}");
    }

    /// A reader that hands out at most `step` bytes a call, as a pipe does.
    struct Trickle<'a> {
        bytes: &'a [u8],
        step: usize,
    }

    impl Read for Trickle<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let count = self.bytes.len().min(self.step).min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes = &self.bytes[count..];
            Ok(count)
        }
    }

    #[test]
    fn a_stream_is_read_whole_however_it_arrives_up_to_exactly_the_limit() {
        let text = "x".repeat(50_000);
        for step in [1, 7, 4096, 65_536] {
            let read = read_secret_text(
                Trickle {
                    bytes: text.as_bytes(),
                    step,
                },
                text.len(),
            )
            .expect("fits exactly");
            assert_eq!(read.as_str(), text, "{step}");
        }
        assert_eq!(read_secret_text(io::empty(), 10).unwrap().as_str(), "");
    }

    #[test]
    fn a_stream_past_the_limit_is_refused() {
        let text = "x".repeat(10_001);
        assert!(matches!(
            read_secret_text(
                Trickle {
                    bytes: text.as_bytes(),
                    step: 333,
                },
                10_000,
            ),
            Err(SecretReadError::TooLarge)
        ));
    }

    #[test]
    fn bytes_that_are_not_utf8_are_refused() {
        assert!(matches!(
            read_secret_text(&b"fixture\xff"[..], 100),
            Err(SecretReadError::NotText)
        ));
    }

    #[test]
    fn a_file_is_read_and_one_larger_than_the_limit_is_refused_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("value.txt");
        std::fs::write(&path, "fixture-value\n").unwrap();
        assert_eq!(
            read_secret_text_file(&path, 100).unwrap().as_str(),
            "fixture-value\n"
        );
        assert_eq!(
            read_secret_text_file(&path, 14).unwrap().as_str(),
            "fixture-value\n"
        );
        assert!(matches!(
            read_secret_text_file(&path, 13),
            Err(SecretReadError::TooLarge)
        ));
        assert!(matches!(
            read_secret_text_file(&dir.path().join("missing"), 100),
            Err(SecretReadError::NotFound)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_read_through_its_descriptor_path_keeps_the_flags_its_owner_set() {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let mut ends = [0; 2];
        // SAFETY: `ends` holds the two descriptors pipe() returns.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0);
        // SAFETY: pipe() returned both descriptors, owned here alone.
        let (reader, mut writer) = unsafe {
            (
                std::fs::File::from_raw_fd(ends[0]),
                std::fs::File::from_raw_fd(ends[1]),
            )
        };
        // SAFETY: the calls only read and set the reader's status flags.
        let flags = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        // SAFETY: as above.
        unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        writer.write_all(b"fixture-value").unwrap();
        drop(writer);

        let path = std::path::PathBuf::from(format!("/dev/fd/{}", reader.as_raw_fd()));
        let read = read_secret_text_file(&path, 1024).unwrap();

        assert_eq!(read.as_str(), "fixture-value");
        // SAFETY: as above.
        let after = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        assert_ne!(
            after & libc::O_NONBLOCK,
            0,
            "the pipe's owner left it non-blocking, which a read through /dev/fd shares"
        );
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            read_secret_text_file(dir.path(), 100),
            Err(SecretReadError::Directory)
        ));
    }

    #[cfg(unix)]
    fn fifo(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("pipe");
        let name = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: `name` is a valid NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        path
    }

    #[cfg(unix)]
    #[test]
    fn a_named_pipe_is_read_from_its_writer_whenever_it_opens_until_it_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = fifo(dir.path());
        let reader = {
            let path = path.clone();
            std::thread::spawn(move || read_secret_text_file(&path, 100))
        };
        // Opening the writer waits for the reader to open, and reading waits
        // for the writer, in either order.
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        io::Write::write_all(&mut writer, b"fixture-").unwrap();
        io::Write::write_all(&mut writer, b"piped").unwrap();
        drop(writer);
        assert_eq!(reader.join().unwrap().unwrap().as_str(), "fixture-piped");
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_refused() {
        assert!(matches!(
            read_secret_text_file(Path::new("/dev/null"), 100),
            Err(SecretReadError::NotFileOrPipe)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn a_windows_device_is_refused_as_not_a_file_or_a_pipe() {
        assert!(matches!(
            read_secret_text_file(Path::new("NUL"), 100),
            Err(SecretReadError::NotFileOrPipe)
        ));
    }
}
