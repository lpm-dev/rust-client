//! Cli-binary tier: TTY behavior. `lpm tunnel` draws its live panel only on
//! a real terminal, redrawing it in place as traffic arrives, and quits on a
//! keypress; the workflow harness's pipes get the line-per-request view.
mod common;

#[cfg(all(unix, debug_assertions))]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tunnel_panel_redraws_usage_and_requests_in_place_and_quits_on_q() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::tungstenite::Message;

    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    tokio::spawn(serve_ok(server));

    let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_url = format!("ws://{}/connect", relay.local_addr().unwrap());
    tokio::spawn(async move {
        let (socket, _) = relay.accept().await.unwrap();
        let mut websocket = tokio_tungstenite::accept_async(socket).await.unwrap();
        let hello = serde_json::json!({
            "type": "hello",
            "subdomain": "panel.lpm.test",
            "tunnel_url": "https://panel.lpm.test",
            "session_id": "session-panel",
            "plan": "pro",
            "usage": {
                "accepted_requests": 1_244,
                "included_requests": 100_000,
                "overage_enabled": true
            }
        });
        websocket
            .send(Message::Text(hello.to_string()))
            .await
            .unwrap();
        // The relay reports the account's count with the first request; an
        // older relay's second request leaves the panel to count it.
        for (id, accepted) in [("first", Some(1_245)), ("second", None)] {
            let mut request = serde_json::json!({
                "type": "http_request",
                "id": id,
                "method": "GET",
                "url": format!("/{id}"),
                "headers": {},
                "body": ""
            });
            if let Some(accepted) = accepted {
                request["accepted_requests"] = accepted.into();
            }
            websocket
                .send(Message::Text(request.to_string()))
                .await
                .unwrap();
            loop {
                let Some(Ok(Message::Text(text))) = websocket.next().await else {
                    return;
                };
                let message: serde_json::Value = serde_json::from_str(&text).unwrap();
                if message["type"] == "http_response" && message["id"] == id {
                    break;
                }
            }
        }
        while let Some(Ok(_)) = websocket.next().await {}
    });

    let project = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"panel","version":"1.0.0"}"#,
    )
    .unwrap();
    let mut command = common::lpm_command(
        project.path(),
        home.path(),
        None,
        &[
            "--token",
            "panel-token",
            "tunnel",
            &port.to_string(),
            "--no-inspect",
        ],
    );
    command
        .env("LPM_TUNNEL_RELAY", relay_url)
        .env("TERM", "xterm-256color");

    let (screen, status) = tokio::task::spawn_blocking(move || {
        run_in_terminal(command, |screen| {
            screen
                .iter()
                .any(|row| row.contains("Listening · 2 requests"))
        })
    })
    .await
    .unwrap();

    let transcript = screen.join("\n");
    assert!(
        status.is_some_and(|status| status.success()),
        "{transcript}"
    );
    let rows: Vec<&str> = screen
        .iter()
        .map(String::as_str)
        .skip_while(|row| !row.starts_with("› Tunnel ready"))
        .collect();
    assert_eq!(
        rows,
        [
            "› Tunnel ready",
            "    public URL  https://panel.lpm.test",
            "    plan        pro",
            "    usage       1,246 / 100,000 requests  █░░░░░░░░░  overage on",
            "    session     session-panel",
            &format!("    local       http://127.0.0.1:{port}/"),
            "    domain      panel.lpm.test",
            "",
            "› Tunnel closed · 2 requests",
            &request_row(&screen, "/first"),
            &request_row(&screen, "/second"),
        ],
        "{transcript}"
    );
    assert!(
        !transcript.contains("→ GET"),
        "a terminal gets the panel, not request lines:\n{transcript}"
    );
}

/// The panel's row for a request to `path`, checked to show a timed 200.
#[cfg(all(unix, debug_assertions))]
fn request_row(screen: &[String], path: &str) -> String {
    let row = screen
        .iter()
        .find(|row| row.starts_with(&format!("    GET     {path} ")))
        .unwrap_or_else(|| panic!("no row for {path}:\n{}", screen.join("\n")));
    let columns: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(columns[..3], ["GET", path, "200"], "{row}");
    assert!(
        columns[3].ends_with("ms") || columns[3].ends_with('s'),
        "{row}"
    );
    row.clone()
}

#[cfg(all(unix, debug_assertions))]
async fn serve_ok(listener: tokio::net::TcpListener) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut head = Vec::with_capacity(1024);
            let mut chunk = [0_u8; 1024];
            while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                match socket.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(read) => head.extend_from_slice(&chunk[..read]),
                }
            }
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
    }
}

const COLUMNS: u16 = 100;
const ROWS: u16 = 30;

/// Runs `command` on a 100×30 terminal, presses `q` once `ready` holds for
/// the screen, and returns the screen after it exits.
#[cfg(all(unix, debug_assertions))]
fn run_in_terminal(
    mut command: std::process::Command,
    ready: impl Fn(&[String]) -> bool,
) -> (Vec<String>, Option<std::process::ExitStatus>) {
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::fd::{AsRawFd as _, FromRawFd as _};
    use std::os::unix::process::CommandExt as _;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let (mut master_fd, mut slave_fd) = (-1, -1);
    // SAFETY: openpty initializes both descriptors on success.
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    // SAFETY: each descriptor is uniquely owned after a successful openpty.
    let mut master = unsafe { File::from_raw_fd(master_fd) };
    // SAFETY: as above.
    let slave = unsafe { File::from_raw_fd(slave_fd) };
    let size = libc::winsize {
        ws_row: ROWS,
        ws_col: COLUMNS,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // Sized after opening: openpty's size argument is mutable on macOS only.
    // SAFETY: the descriptor is a terminal and `size` outlives the call.
    assert_eq!(
        unsafe { libc::ioctl(slave.as_raw_fd(), libc::TIOCSWINSZ, &size) },
        0
    );
    for descriptor in [master.as_raw_fd(), slave.as_raw_fd()] {
        // SAFETY: the descriptor is valid; fcntl only sets close-on-exec.
        assert_eq!(
            unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    // SAFETY: the descriptor is valid; fcntl only changes its read mode.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    // SAFETY: the descriptor and flags are valid.
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    command
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave));
    // SAFETY: only async-signal-safe session syscalls run after fork.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1
                || libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY as libc::c_ulong, 0) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    drop(command);

    let mut terminal = Screen::new(usize::from(COLUMNS), usize::from(ROWS));
    let mut buffer = [0_u8; 8192];
    let mut drain = |master: &mut File, terminal: &mut Screen| loop {
        match master.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => terminal.feed(&buffer[..read]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.raw_os_error() == Some(libc::EIO) =>
            {
                break;
            }
            Err(error) => panic!("read terminal: {error}"),
        }
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        drain(&mut master, &mut terminal);
        if ready(&terminal.text()) {
            break;
        }
        assert!(
            Instant::now() < deadline && child.try_wait().unwrap().is_none(),
            "the panel never showed the traffic:\n{}",
            terminal.text().join("\n")
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    master.write_all(b"q").unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        drain(&mut master, &mut terminal);
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            // SAFETY: the child leads the session created for it above.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    drain(&mut master, &mut terminal);
    (terminal.text(), status)
}

/// The screen a terminal shows for what the CLI writes: text with pending
/// autowrap, CR, LF with scrolling, and the cursor and erase sequences a
/// live region uses. Styling and synchronized-update markers are ignored;
/// anything else fails the test.
#[cfg(all(unix, debug_assertions))]
struct Screen {
    width: usize,
    height: usize,
    rows: Vec<Vec<char>>,
    row: usize,
    column: usize,
    wrap_pending: bool,
    pending: Vec<u8>,
}

#[cfg(all(unix, debug_assertions))]
impl Screen {
    fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            rows: vec![Vec::new(); height],
            row: 0,
            column: 0,
            wrap_pending: false,
            pending: Vec::new(),
        }
    }

    fn line_feed(&mut self) {
        if self.row + 1 == self.height {
            self.rows.remove(0);
            self.rows.push(Vec::new());
        } else {
            self.row += 1;
        }
    }

    /// Interprets what arrived, holding back a character or escape sequence
    /// the terminal hasn't received all of yet.
    fn feed(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
        let valid = match std::str::from_utf8(&self.pending) {
            Ok(text) => text.len(),
            Err(error) => error.valid_up_to(),
        };
        let text = std::str::from_utf8(&self.pending[..valid]).unwrap();
        let complete = match text.rfind('\u{1b}') {
            Some(start)
                if !text[start..]
                    .chars()
                    .skip(1)
                    .any(|character| character.is_ascii_alphabetic()) =>
            {
                start
            }
            _ => valid,
        };
        let text = text[..complete].to_owned();
        self.pending.drain(..complete);
        self.interpret(&text);
    }

    fn interpret(&mut self, text: &str) {
        let mut chars = text.chars().peekable();
        while let Some(character) = chars.next() {
            match character {
                '\r' => {
                    self.column = 0;
                    self.wrap_pending = false;
                }
                '\n' => {
                    self.line_feed();
                    self.wrap_pending = false;
                }
                '\u{7}' => {}
                '\u{1b}' => {
                    assert_eq!(chars.next(), Some('['), "only CSI sequences are expected");
                    let mut parameters = String::new();
                    let command = loop {
                        let next = chars.next().expect("a whole sequence per write");
                        if next.is_ascii_alphabetic() {
                            break next;
                        }
                        parameters.push(next);
                    };
                    match command {
                        'A' => {
                            self.row = self.row.saturating_sub(parameters.parse().unwrap_or(1));
                            self.wrap_pending = false;
                        }
                        'J' => {
                            self.rows[self.row].truncate(self.column);
                            for row in &mut self.rows[self.row + 1..] {
                                row.clear();
                            }
                        }
                        'K' => self.rows[self.row].truncate(self.column),
                        'm' | 'h' | 'l' => {}
                        other => panic!("unexpected sequence ESC[{parameters}{other}"),
                    }
                }
                character => {
                    if self.wrap_pending {
                        self.column = 0;
                        self.line_feed();
                        self.wrap_pending = false;
                    }
                    let row = &mut self.rows[self.row];
                    if row.len() < self.column {
                        row.resize(self.column, ' ');
                    }
                    if self.column < row.len() {
                        row[self.column] = character;
                    } else {
                        row.push(character);
                    }
                    if self.column + 1 == self.width {
                        self.wrap_pending = true;
                    } else {
                        self.column += 1;
                    }
                }
            }
        }
    }

    fn text(&self) -> Vec<String> {
        let mut text: Vec<String> = self
            .rows
            .iter()
            .map(|row| row.iter().collect::<String>().trim_end().to_owned())
            .collect();
        while text.last().is_some_and(String::is_empty) {
            text.pop();
        }
        text
    }
}
