use super::*;

pub fn canonical_host_from_header(host_header: &str) -> Result<String, ProxyError> {
    let trimmed = host_header.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidHost {
            host: host_header.to_string(),
            reason: "host header is empty",
        });
    }
    if trimmed.starts_with('[') {
        return Err(ProxyError::InvalidHost {
            host: host_header.to_string(),
            reason: "IP literal host headers are not local-domain routes",
        });
    }

    let host = match trimmed.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => trimmed,
    };
    canonical_host(host)
}

pub fn canonical_host(host: &str) -> Result<String, ProxyError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host is empty",
        });
    }
    if trimmed.starts_with('.') || trimmed.contains("..") {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host must be a bare multi-label hostname",
        });
    }
    if trimmed
        .bytes()
        .any(|b| b <= 0x20 || matches!(b, b'/' | b'\\' | b'@' | b'*' | 0x7f))
    {
        return Err(ProxyError::InvalidHost {
            host: host.to_string(),
            reason: "host contains forbidden characters",
        });
    }

    let host = trimmed.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Err(ProxyError::InvalidHost {
            host,
            reason: "host is empty",
        });
    }
    if !host.contains('.') {
        return Err(ProxyError::InvalidHost {
            host,
            reason: "host must be a bare multi-label hostname",
        });
    }
    Ok(host)
}
