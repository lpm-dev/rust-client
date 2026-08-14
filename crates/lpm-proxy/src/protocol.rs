use super::*;

pub(crate) async fn send_request_on_stream<S>(
    mut stream: S,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    send_request_on_stream_ref(&mut stream, request).await
}

pub(crate) async fn send_request_on_stream_ref<S>(
    stream: &mut S,
    request: ProxyRequest,
) -> Result<ProxyResponse, ProxyError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(IPC_REQUEST_TIMEOUT, async {
        write_request(stream, &request).await?;
        let response_line = read_ipc_line(stream).await?;
        serde_json::from_slice::<ProxyResponse>(&response_line)
            .map_err(|err| ProxyError::IpcProtocol(err.to_string()))
    })
    .await
    .map_err(|_| {
        ProxyError::Ipc(format!(
            "control request timed out after {IPC_REQUEST_TIMEOUT:?}"
        ))
    })?
}

pub(crate) async fn read_proxy_request<R>(reader: &mut R) -> Result<ProxyRequest, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let request_line = read_ipc_line(reader).await?;
    parse_proxy_request(&request_line)
}

pub(crate) async fn read_proxy_request_with_timeout<R>(
    reader: &mut R,
) -> Result<ProxyRequest, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    tokio::time::timeout(IPC_REQUEST_TIMEOUT, read_proxy_request(reader))
        .await
        .map_err(|_| control_frame_timeout("read initial"))?
}

pub(crate) async fn read_proxy_request_after_activity<R>(
    reader: &mut R,
) -> Result<ProxyRequest, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    let mut first = [0u8; 1];
    let read = reader
        .read(&mut first)
        .await
        .map_err(|err| ProxyError::Ipc(format!("read control frame: {err}")))?;
    if read == 0 {
        return Err(ProxyError::IpcProtocol(EMPTY_CONTROL_FRAME_MESSAGE.into()));
    }
    let request_line = tokio::time::timeout(
        IPC_REQUEST_TIMEOUT,
        read_ipc_line_from(reader, Vec::from(first)),
    )
    .await
    .map_err(|_| control_frame_timeout("read active"))??;
    parse_proxy_request(&request_line)
}

pub(crate) async fn write_request<W>(
    writer: &mut W,
    request: &ProxyRequest,
) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    write_line_json(writer, request).await
}

pub(crate) async fn write_response<W>(
    writer: &mut W,
    response: &ProxyResponse,
) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    tokio::time::timeout(IPC_REQUEST_TIMEOUT, write_line_json(writer, response))
        .await
        .map_err(|_| control_frame_timeout("write"))?
}

pub(crate) async fn write_line_json<W, T>(writer: &mut W, value: &T) -> Result<(), ProxyError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    use tokio::io::AsyncWriteExt;

    let mut bytes = serde_json::to_vec(value).map_err(|err| ProxyError::Ipc(err.to_string()))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|err| ProxyError::Ipc(format!("write control frame: {err}")))?;
    writer
        .flush()
        .await
        .map_err(|err| ProxyError::Ipc(format!("flush control frame: {err}")))?;
    Ok(())
}

pub(crate) async fn read_ipc_line<R>(reader: &mut R) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    read_ipc_line_from(reader, Vec::with_capacity(256)).await
}

async fn read_ipc_line_from<R>(reader: &mut R, mut line: Vec<u8>) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;

    if line.last() == Some(&b'\n') {
        line.pop();
        return Ok(line);
    }
    let mut byte = [0u8; 1];
    loop {
        let read = reader
            .read(&mut byte)
            .await
            .map_err(|err| ProxyError::Ipc(format!("read control frame: {err}")))?;
        if read == 0 {
            if line.is_empty() {
                return Err(ProxyError::IpcProtocol(EMPTY_CONTROL_FRAME_MESSAGE.into()));
            }
            return Ok(line);
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() >= IPC_LINE_CAP_BYTES {
            return Err(ProxyError::IpcProtocol(format!(
                "control frame exceeds {IPC_LINE_CAP_BYTES} bytes"
            )));
        }
        line.push(byte[0]);
    }
}

fn parse_proxy_request(request_line: &[u8]) -> Result<ProxyRequest, ProxyError> {
    serde_json::from_slice::<ProxyRequest>(request_line)
        .map_err(|err| ProxyError::IpcProtocol(err.to_string()))
}

fn control_frame_timeout(operation: &str) -> ProxyError {
    ProxyError::Ipc(format!(
        "{operation} control frame timed out after {IPC_REQUEST_TIMEOUT:?}"
    ))
}
