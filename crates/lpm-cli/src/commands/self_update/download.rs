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
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| LpmError::Network(format!("fetch {url} body read failed: {error}")))?
    {
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
                "release asset fetch failed: {}",
                lpm_http::display_error(&error)
            ))
        })?;

    let status = response.status();
    if status.as_u16() == 404 {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(LpmError::Network(format!(
            "fetch {url} returned HTTP {}",
            status.as_u16()
        )));
    }

    if let Some(advertised) = response.content_length()
        && advertised > max_bytes as u64
    {
        return Err(LpmError::SelfUpdate(format!(
            "{url} advertises {advertised} bytes; cap of {max_bytes} would be exceeded — refusing the download"
        )));
    }
    Ok(Some(response))
}

fn body_exceeded_cap(url: &str, max_bytes: usize) -> LpmError {
    LpmError::SelfUpdate(format!(
        "{url} body exceeded cap of {max_bytes} bytes mid-stream — aborted before the complete download"
    ))
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
    temporary: &mut tempfile::NamedTempFile,
) -> Result<(), LpmError> {
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
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| LpmError::Network(format!("fetch {url} body read failed: {error}")))?
    {
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
    finish_staged_binary(&mut temporary)?;

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
                finish_staged_binary(&mut temporary).unwrap();
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
