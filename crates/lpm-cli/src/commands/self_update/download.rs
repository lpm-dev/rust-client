use lpm_common::LpmError;
use sha2::{Digest, Sha256};

pub(super) async fn fetch_bounded(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, LpmError> {
    let Some(mut response) = fetch_bounded_response(client, url, max_bytes).await? else {
        return Ok(None);
    };

    let prealloc = response
        .content_length()
        .map_or(0, |length| (length as usize).min(max_bytes));
    let mut buffer = Vec::with_capacity(prealloc);
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        LpmError::Network(format!(
            "fetch {} body read failed: {}",
            safe_remote_label(url),
            lpm_http::display_error(&error.without_url())
        ))
    })? {
        if buffer.len().saturating_add(chunk.len()) > max_bytes {
            return Err(body_exceeded_cap(url, max_bytes));
        }
        buffer.extend_from_slice(&chunk);
    }
    Ok(Some(buffer))
}

async fn fetch_bounded_response(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
) -> Result<Option<reqwest::Response>, LpmError> {
    let response = client
        .get(url)
        .header("User-Agent", "lpm-cli")
        .send()
        .await
        .map_err(|error| {
            LpmError::Network(format!(
                "release asset fetch from {} failed: {}",
                safe_remote_label(url),
                lpm_http::display_error(&error.without_url())
            ))
        })?;

    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(LpmError::Network(format!(
            "fetch {} returned HTTP {}",
            safe_remote_label(url),
            status.as_u16()
        )));
    }

    if let Some(advertised) = response.content_length()
        && advertised > max_bytes as u64
    {
        return Err(LpmError::SelfUpdate(format!(
            "{} advertises {advertised} bytes; cap of {max_bytes} would be exceeded — refusing the download",
            safe_remote_label(url)
        )));
    }
    Ok(Some(response))
}

fn body_exceeded_cap(url: &str, max_bytes: usize) -> LpmError {
    LpmError::SelfUpdate(format!(
        "{} body exceeded cap of {max_bytes} bytes mid-stream — aborted before the complete download",
        safe_remote_label(url)
    ))
}

pub(super) fn safe_remote_label(url: &str) -> String {
    crate::install_ui::safe_url_origin(url)
}

#[derive(Debug)]
pub(super) struct StagedAsset {
    pub(super) temporary: tempfile::NamedTempFile,
    pub(super) byte_len: usize,
    pub(super) sha256: String,
}

pub(super) fn create_staged_binary(
    current_exe: &std::path::Path,
) -> Result<tempfile::NamedTempFile, LpmError> {
    let file_name = current_exe.file_name().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no file name",
        ))
    })?;
    let parent = current_exe.parent().ok_or_else(|| {
        LpmError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current_exe has no parent directory",
        ))
    })?;

    let mut prefix = std::ffi::OsString::from(".");
    prefix.push(file_name);
    prefix.push(".new-");
    let suffix = current_exe.extension().map(|extension| {
        let mut suffix = std::ffi::OsString::from(".");
        suffix.push(extension);
        suffix
    });
    let mut builder = tempfile::Builder::new();
    builder.prefix(&prefix);
    if let Some(suffix) = &suffix {
        builder.suffix(suffix);
    }
    builder.tempfile_in(parent).map_err(LpmError::Io)
}

pub(super) fn finish_staged_binary(
    mut temporary: tempfile::NamedTempFile,
) -> Result<tempfile::NamedTempFile, LpmError> {
    use std::io::Write as _;

    temporary.as_file_mut().flush().map_err(LpmError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(LpmError::Io)?;
    }

    let writable_identity =
        same_file::Handle::from_file(temporary.as_file().try_clone().map_err(LpmError::Io)?)
            .map_err(LpmError::Io)?;
    let read_only = std::fs::File::open(temporary.path()).map_err(LpmError::Io)?;
    let read_only_identity =
        same_file::Handle::from_file(read_only.try_clone().map_err(LpmError::Io)?)
            .map_err(LpmError::Io)?;
    if writable_identity != read_only_identity {
        return Err(LpmError::SelfUpdate(
            "staged self-update binary changed while it was being sealed".to_string(),
        ));
    }

    // Linux refuses to execute a file while any process has it open for writing.
    let (_, path) = temporary.into_parts();
    Ok(tempfile::NamedTempFile::from_parts(read_only, path))
}

pub(super) fn ensure_staged_file_unchanged(
    temporary: &tempfile::NamedTempFile,
    expected_sha256: &str,
) -> Result<(), LpmError> {
    use std::io::{Read as _, Seek as _};

    let metadata = std::fs::symlink_metadata(temporary.path()).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "staged self-update binary changed after verification: {error}"
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(LpmError::SelfUpdate(
            "staged self-update binary changed after verification".to_string(),
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(LpmError::SelfUpdate(
                "staged self-update binary changed after verification".to_string(),
            ));
        }
    }
    let opened =
        same_file::Handle::from_file(temporary.as_file().try_clone().map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not bind the opened staged self-update binary: {error}"
            ))
        })?)
        .map_err(|error| {
            LpmError::SelfUpdate(format!(
                "could not bind the opened staged self-update binary: {error}"
            ))
        })?;
    let named = same_file::Handle::from_path(temporary.path()).map_err(|error| {
        LpmError::SelfUpdate(format!(
            "staged self-update binary changed after verification: {error}"
        ))
    })?;
    if opened != named {
        return Err(LpmError::SelfUpdate(
            "staged self-update binary changed after verification".to_string(),
        ));
    }

    let mut file = temporary.as_file().try_clone().map_err(LpmError::Io)?;
    file.seek(std::io::SeekFrom::Start(0))
        .map_err(LpmError::Io)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(LpmError::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual_sha256 = hex::encode(hasher.finalize());
    if actual_sha256 != expected_sha256 {
        return Err(LpmError::SelfUpdate(format!(
            "staged self-update binary changed after verification: expected SHA-256 {expected_sha256}, found {actual_sha256}"
        )));
    }
    Ok(())
}

pub(super) async fn fetch_asset_to_staged_file(
    client: &reqwest::Client,
    url: &str,
    max_bytes: usize,
    current_exe: &std::path::Path,
) -> Result<Option<StagedAsset>, LpmError> {
    use std::io::Write as _;

    let Some(mut response) = fetch_bounded_response(client, url, max_bytes).await? else {
        return Ok(None);
    };
    let mut temporary = create_staged_binary(current_exe)?;
    let mut hasher = Sha256::new();
    let mut byte_len = 0_usize;
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        LpmError::Network(format!(
            "fetch {} body read failed: {}",
            safe_remote_label(url),
            lpm_http::display_error(&error.without_url())
        ))
    })? {
        if byte_len.saturating_add(chunk.len()) > max_bytes {
            return Err(body_exceeded_cap(url, max_bytes));
        }
        temporary.as_file_mut().write_all(&chunk).map_err(|error| {
            LpmError::Io(std::io::Error::new(
                error.kind(),
                format!("failed to write staged self-update binary: {error}"),
            ))
        })?;
        hasher.update(&chunk);
        byte_len += chunk.len();
    }
    let temporary = finish_staged_binary(temporary)?;

    Ok(Some(StagedAsset {
        temporary,
        byte_len,
        sha256: hex::encode(hasher.finalize()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[cfg(unix)]
    fn peak_rss_bytes() -> u64 {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: `usage` points to writable storage for `rusage`; a zero return
        // confirms that the OS initialized it before `assume_init`.
        let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        assert_eq!(result, 0, "getrusage must succeed");
        // SAFETY: the successful `getrusage` call initialized every field.
        let peak = unsafe { usage.assume_init() }.ru_maxrss as u64;
        if cfg!(target_os = "macos") {
            peak
        } else {
            peak.saturating_mul(1024)
        }
    }

    fn spawn_fixed_body_server(
        body_len: usize,
    ) -> (String, std::thread::JoinHandle<std::io::Result<()>>) {
        spawn_fixed_body_server_with_length(body_len, Some(body_len))
    }

    fn spawn_fixed_body_server_with_length(
        body_len: usize,
        advertised_len: Option<usize>,
    ) -> (String, std::thread::JoinHandle<std::io::Result<()>>) {
        use std::io::Write as _;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept()?;
            let mut request = [0_u8; 1024];
            let _ = std::io::Read::read(&mut stream, &mut request)?;
            write!(stream, "HTTP/1.1 200 OK\r\n")?;
            if let Some(advertised_len) = advertised_len {
                write!(stream, "Content-Length: {advertised_len}\r\n")?;
            }
            write!(stream, "Connection: close\r\n\r\n")?;
            let chunk = [b'x'; 64 * 1024];
            let mut remaining = body_len;
            while remaining != 0 {
                let count = remaining.min(chunk.len());
                if let Err(error) = stream.write_all(&chunk[..count]) {
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::ConnectionReset
                    ) {
                        return Ok(());
                    }
                    return Err(error);
                }
                remaining -= count;
            }
            Ok(())
        });
        (format!("http://{address}/asset"), server)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn staged_asset_download_hashes_to_disk_without_retaining_the_body() {
        let (url, server) = spawn_fixed_body_server(2 * 1024 * 1024);
        let client = super::super::release_http_client().unwrap();
        let destination_dir = tempdir().unwrap();
        let current_exe = destination_dir.path().join("lpm");

        let staged = fetch_asset_to_staged_file(&client, &url, 4 * 1024 * 1024, &current_exe)
            .await
            .unwrap()
            .expect("asset must exist");
        server.join().unwrap().unwrap();

        assert_eq!(staged.byte_len, 2 * 1024 * 1024);
        assert_eq!(
            staged.sha256,
            hex::encode(Sha256::digest(vec![b'x'; 2 * 1024 * 1024]))
        );
        assert_eq!(
            staged.temporary.path().parent(),
            Some(destination_dir.path())
        );
        assert_eq!(
            std::fs::metadata(staged.temporary.path()).unwrap().len(),
            staged.byte_len as u64
        );
        let staged_path = staged.temporary.path().to_path_buf();
        drop(staged);
        assert!(
            !staged_path.exists(),
            "dropping a staged asset must remove it"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn staged_asset_download_removes_partial_file_when_stream_exceeds_cap() {
        let (url, server) = spawn_fixed_body_server_with_length(2 * 1024 * 1024, None);
        let client = super::super::release_http_client().unwrap();
        let destination_dir = tempdir().unwrap();
        let current_exe = destination_dir.path().join("lpm");

        let error = fetch_asset_to_staged_file(&client, &url, 1024 * 1024, &current_exe)
            .await
            .expect_err("a close-delimited body must still obey the cap");
        server.join().unwrap().unwrap();

        assert!(error.to_string().contains("mid-stream"), "error: {error}");
        assert_eq!(
            std::fs::read_dir(destination_dir.path()).unwrap().count(),
            0,
            "the partial staged binary must be removed"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn release_download_errors_do_not_expose_override_query_secrets() {
        use std::io::{Read as _, Write as _};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let secret = "release-mirror-secret";
        let url = format!("http://{address}/asset?token={secret}");
        let client = reqwest::Client::new();

        let error = fetch_bounded(&client, &url, 1024).await.unwrap_err();
        server.join().unwrap();
        let rendered = error.to_string();

        assert!(!rendered.contains(secret), "secret leaked in: {rendered}");
        assert!(rendered.contains(&format!("http://{address}")));
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "deterministic self-update download memory and latency probe"]
    async fn standalone_asset_download_probe_reports_peak_rss_and_latency() {
        use std::io::Write as _;

        const BODY_LEN: usize = 64 * 1024 * 1024;

        enum RetainedProbeAsset {
            Buffered(Vec<u8>, tempfile::NamedTempFile, String),
            Streaming(StagedAsset),
        }

        let mode = std::env::var("LPM_SELF_UPDATE_DOWNLOAD_BENCH_MODE")
            .unwrap_or_else(|_| "streaming".to_string());
        let (url, server) = spawn_fixed_body_server(BODY_LEN);
        let client = super::super::release_http_client().unwrap();
        let destination_dir = tempdir().unwrap();
        let current_exe = destination_dir.path().join("lpm");
        let peak_before = peak_rss_bytes();
        let started = std::time::Instant::now();
        let retained = match mode.as_str() {
            "buffered" => {
                let bytes = fetch_bounded(&client, &url, super::super::ASSET_MAX_BYTES)
                    .await
                    .unwrap()
                    .expect("asset must exist");
                let digest = hex::encode(Sha256::digest(&bytes));
                let mut temporary = create_staged_binary(&current_exe).unwrap();
                temporary.as_file_mut().write_all(&bytes).unwrap();
                let temporary = finish_staged_binary(temporary).unwrap();
                RetainedProbeAsset::Buffered(bytes, temporary, digest)
            }
            "streaming" => RetainedProbeAsset::Streaming(
                fetch_asset_to_staged_file(
                    &client,
                    &url,
                    super::super::ASSET_MAX_BYTES,
                    &current_exe,
                )
                .await
                .unwrap()
                .expect("asset must exist"),
            ),
            other => panic!("unsupported benchmark mode `{other}`"),
        };
        let elapsed = started.elapsed();
        match &retained {
            RetainedProbeAsset::Buffered(bytes, temporary, digest) => {
                assert_eq!(bytes.len(), BODY_LEN);
                assert_eq!(
                    std::fs::metadata(temporary.path()).unwrap().len(),
                    BODY_LEN as u64
                );
                assert_eq!(digest.len(), 64);
            }
            RetainedProbeAsset::Streaming(staged) => {
                assert_eq!(staged.byte_len, BODY_LEN);
                assert_eq!(
                    std::fs::metadata(staged.temporary.path()).unwrap().len(),
                    BODY_LEN as u64
                );
            }
        }
        std::hint::black_box(&retained);
        let peak_after = peak_rss_bytes();
        server.join().unwrap().unwrap();
        let peak_delta = peak_after.saturating_sub(peak_before);

        eprintln!(
            "self_update_download mode={mode} bytes={BODY_LEN} peak_rss_delta_bytes={peak_delta} elapsed_ms={}",
            elapsed.as_millis()
        );
        if mode == "streaming" {
            assert!(
                peak_delta < 32 * 1024 * 1024,
                "downloading a 64 MiB asset must not retain the complete body in RAM"
            );
        } else {
            assert!(
                peak_delta >= 32 * 1024 * 1024,
                "the buffered control must retain enough memory to validate the probe"
            );
        }
    }
}
