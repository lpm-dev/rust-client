use std::ffi::{OsStr, OsString};

fn encode(value: &OsStr) -> Vec<u16> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().collect()
    }
    #[cfg(not(windows))]
    {
        value.to_string_lossy().encode_utf16().collect()
    }
}

pub(super) fn build_command_line_wide(program: &OsStr, args: &[OsString]) -> Vec<u16> {
    let program = encode(program);
    let args: Vec<_> = args.iter().map(|arg| encode(arg)).collect();
    let capacity = program.len() + args.iter().map(Vec::len).sum::<usize>() + args.len() * 3 + 3;
    let mut result = Vec::with_capacity(capacity);
    append_quoted_argument(&mut result, &program);
    if !args.is_empty() {
        result.push(b' ' as u16);
        result.extend(render_arguments(&program, &args));
    }
    result.push(0);
    result
}

#[cfg(windows)]
pub(super) fn apply_arguments(
    command: &mut std::process::Command,
    program: &OsStr,
    args: &[OsString],
) {
    use std::os::windows::{ffi::OsStringExt, process::CommandExt};
    let program_wide = encode(program);
    let args_wide: Vec<_> = args.iter().map(|arg| encode(arg)).collect();
    if shell_payload_index(&program_wide, &args_wide).is_some() {
        command.raw_arg(OsString::from_wide(&render_arguments(
            &program_wide,
            &args_wide,
        )));
    } else {
        command.args(args);
    }
}

fn ascii_eq(value: &[u16], ascii: &[u8]) -> bool {
    value.len() == ascii.len()
        && value.iter().zip(ascii).all(|(&left, &right)| {
            u8::try_from(left).is_ok_and(|left| left.eq_ignore_ascii_case(&right))
        })
}

fn shell_payload_index(program: &[u16], args: &[Vec<u16>]) -> Option<usize> {
    let name = program
        .rsplit(|&unit| unit == b'/' as u16 || unit == b'\\' as u16)
        .next()?;
    if !ascii_eq(name, b"cmd.exe") && !ascii_eq(name, b"cmd") {
        return None;
    }
    for (index, arg) in args.iter().enumerate() {
        if ascii_eq(arg, b"/c") {
            return (index + 2 == args.len()).then_some(index + 1);
        }
        if ![
            b"/d".as_slice(),
            b"/s",
            b"/q",
            b"/a",
            b"/u",
            b"/e:on",
            b"/e:off",
            b"/f:on",
            b"/f:off",
            b"/v:on",
            b"/v:off",
        ]
        .iter()
        .any(|option| ascii_eq(arg, option))
        {
            return None;
        }
    }
    None
}

fn render_arguments(program: &[u16], args: &[Vec<u16>]) -> Vec<u16> {
    let payload = shell_payload_index(program, args);
    let has_strip_switch =
        payload.is_some_and(|index| args[..index].iter().any(|arg| ascii_eq(arg, b"/s")));
    let capacity = args.iter().map(Vec::len).sum::<usize>() + args.len() * 3 + 3;
    let mut result = Vec::with_capacity(capacity);
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            result.push(b' ' as u16);
        }
        if payload == Some(index + 1) && !has_strip_switch {
            result.extend("/S ".encode_utf16());
        }
        if payload == Some(index) {
            // cmd /S removes this outer pair; CRT backslash escaping would alter the script.
            result.push(b'"' as u16);
            result.extend(arg);
            result.push(b'"' as u16);
        } else {
            append_quoted_argument(&mut result, arg);
        }
    }
    result
}

fn append_quoted_argument(out: &mut Vec<u16>, arg: &[u16]) {
    if !arg.is_empty()
        && !arg
            .iter()
            .any(|unit| matches!(*unit, 0x20 | 0x09 | 0x22 | 0x0a | 0x0b))
    {
        out.extend(arg);
        return;
    }
    out.push(b'"' as u16);
    let mut backslashes = 0;
    for &unit in arg {
        match unit {
            0x5c => {
                backslashes += 1;
                out.push(unit);
            }
            0x22 => {
                out.extend(std::iter::repeat_n(b'\\' as u16, backslashes + 1));
                out.push(unit);
                backslashes = 0;
            }
            other => {
                backslashes = 0;
                out.push(other);
            }
        }
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
    out.push(b'"' as u16);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_line(program: &str, args: &[&str]) -> String {
        let args: Vec<_> = args.iter().map(OsString::from).collect();
        let wide = build_command_line_wide(OsStr::new(program), &args);
        assert_eq!(wide.last(), Some(&0));
        String::from_utf16(&wide[..wide.len() - 1]).unwrap()
    }

    #[test]
    fn ordinary_arguments_keep_crt_quoting() {
        for (arg, expected) in [
            ("simple", "simple"),
            ("", "\"\""),
            ("hello world", "\"hello world\""),
            (r#"a"b"#, r#""a\"b""#),
            (r#"a\"b"#, r#""a\\\"b""#),
            ("C:\\foo with space\\", "\"C:\\foo with space\\\\\""),
        ] {
            assert_eq!(
                command_line("node.exe", &[arg]),
                format!("node.exe {expected}")
            );
        }
    }

    #[test]
    fn cmd_shell_payload_preserves_quotes_and_operators() {
        for script in [
            r#"node -e "process.exit(17)""#,
            r#""C:\Program Files\node.exe" "script with spaces.js" && exit /b 17"#,
            r#"echo "a&b" > "output file""#,
            r#"(echo first | find "first") || exit /b 9"#,
        ] {
            assert_eq!(
                command_line(r"C:\Windows\System32\cmd.exe", &["/D", "/C", script]),
                format!("C:\\Windows\\System32\\cmd.exe /D /S /C \"{script}\"")
            );
        }
    }

    #[test]
    fn cmd_detection_is_case_insensitive_and_preserves_existing_strip_switch() {
        assert_eq!(
            command_line("CMD.EXE", &["/D", "/S", "/c", "exit 17"]),
            "CMD.EXE /D /S /c \"exit 17\""
        );
    }

    #[test]
    fn tokenized_cmd_arguments_keep_the_existing_contract() {
        assert_eq!(
            command_line("cmd.exe", &["/c", "exit", "7"]),
            "cmd.exe /c exit 7"
        );
        assert_eq!(
            command_line("node.exe", &["/c", "hello world"]),
            "node.exe /c \"hello world\""
        );
    }

    #[test]
    fn shell_detection_does_not_reinterpret_switches_inside_tokenized_commands() {
        assert_eq!(
            command_line("cmd.exe", &["/C", "echo", "/C", "value"]),
            "cmd.exe /C echo /C value"
        );
        assert_eq!(
            command_line("cmd.exe", &["/K", "echo", "/C", "value"]),
            "cmd.exe /K echo /C value"
        );
        assert_eq!(
            command_line("cmd.exe", &["unknown", "/C", "value"]),
            "cmd.exe unknown /C value"
        );
    }

    #[test]
    fn shell_payload_preserves_non_unicode_windows_code_units() {
        let program: Vec<u16> = "cmd.exe".encode_utf16().collect();
        let payload = vec![0xd800, b' ' as u16, b'"' as u16, b'\\' as u16];
        let args = vec!["/C".encode_utf16().collect(), payload.clone()];
        let mut expected: Vec<u16> = "/S /C \"".encode_utf16().collect();
        expected.extend(payload);
        expected.push(b'"' as u16);
        assert_eq!(render_arguments(&program, &args), expected);
    }
}
