use lpm_common::LpmError;

pub(crate) async fn read_response(
    mut response: reqwest::Response,
    limit: usize,
    context: &str,
) -> Result<Vec<u8>, LpmError> {
    let too_large = || LpmError::Network(format!("{context} exceeds the {limit} byte limit"));
    if response
        .content_length()
        .is_some_and(|size| size > limit as u64)
    {
        return Err(too_large());
    }
    let capacity = response
        .content_length()
        .and_then(|size| usize::try_from(size).ok())
        .unwrap_or(0)
        .min(limit);
    let mut bytes = Vec::with_capacity(capacity);
    while let Some(chunk) = response.chunk().await.map_err(|error| {
        LpmError::Network(format!(
            "failed to read {context}: {}",
            lpm_http::display_error(&error)
        ))
    })? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(too_large());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn chunked_reads_enforce_the_cap_without_a_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (body, valid) in [
            ("4\r\ndata\r\n0\r\n\r\n", true),
            ("4\r\ndata\r\n1\r\nx\r\n0\r\n\r\n", false),
        ] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).await.unwrap() > 0);
                stream.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{body}").as_bytes()).await.unwrap();
            });
            let response = reqwest::Client::new()
                .get(format!("http://{address}"))
                .send()
                .await
                .unwrap();
            let result = read_response(response, 4, "test body").await;
            assert_eq!(result.is_ok(), valid);
            server.await.unwrap();
        }
    }
}
