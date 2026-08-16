/// Reason that a command name cannot be used as a portable filesystem entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PortableCommandNameError {
    Empty,
    TooLong,
    PathSeparator,
    ParentTraversal,
    NullByte,
    AlternateDataStream,
    TrailingDotOrSpace,
    WindowsReservedDevice,
}

impl PortableCommandNameError {
    /// Stable explanation suitable for a user-facing validation error.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Empty => "cannot be empty",
            Self::TooLong => "is longer than 255 bytes",
            Self::PathSeparator => "contains a path separator",
            Self::ParentTraversal => "contains '..'",
            Self::NullByte => "contains a NUL byte",
            Self::AlternateDataStream => "contains ':' (NTFS alternate data stream separator)",
            Self::TrailingDotOrSpace => "ends with a dot or space (invalid on Windows)",
            Self::WindowsReservedDevice => "is a Windows reserved device name",
        }
    }
}

/// Validate a command name for use as one filesystem entry on every supported OS.
pub fn validate_portable_command_name(name: &str) -> Result<(), PortableCommandNameError> {
    if name.is_empty() {
        return Err(PortableCommandNameError::Empty);
    }
    if name.len() > 255 {
        return Err(PortableCommandNameError::TooLong);
    }
    if name.contains('/') || name.contains('\\') {
        return Err(PortableCommandNameError::PathSeparator);
    }
    if name.contains("..") {
        return Err(PortableCommandNameError::ParentTraversal);
    }
    if name.contains('\0') {
        return Err(PortableCommandNameError::NullByte);
    }
    if name.contains(':') {
        return Err(PortableCommandNameError::AlternateDataStream);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(PortableCommandNameError::TrailingDotOrSpace);
    }
    if is_windows_reserved_device_name(name) {
        return Err(PortableCommandNameError::WindowsReservedDevice);
    }
    Ok(())
}

fn is_windows_reserved_device_name(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM0", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
        "LPT9",
    ];
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    let normalized: String = stem
        .chars()
        .map(|character| match character {
            '\u{2070}' => '0',
            '\u{00B9}' => '1',
            '\u{00B2}' => '2',
            '\u{00B3}' => '3',
            '\u{2074}' => '4',
            '\u{2075}' => '5',
            '\u{2076}' => '6',
            '\u{2077}' => '7',
            '\u{2078}' => '8',
            '\u{2079}' => '9',
            other => other,
        })
        .flat_map(char::to_uppercase)
        .collect();
    RESERVED.contains(&normalized.as_str())
}
