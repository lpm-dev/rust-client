use super::*;

#[cfg(unix)]
pub(crate) fn ipc_connect_error(err: std::io::Error, socket_path: &Path) -> ProxyError {
    match err.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
            ProxyError::IpcUnavailable(format!("{} ({err})", socket_path.display()))
        }
        _ => ProxyError::Ipc(format!("connect {}: {err}", socket_path.display())),
    }
}
