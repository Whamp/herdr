//! Integration tests for multi-client server behavior.

mod support;

use std::collections::VecDeque;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Deserialize;
use serde_json::Value;
use support::{
    cleanup_test_base, register_runtime_dir, register_spawned_herdr_pid,
    unregister_spawned_herdr_pid, CURRENT_PROTOCOL,
};

fn unique_test_dir() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    PathBuf::from(format!(
        "/tmp/herdr-multi-client-test-{}-{nanos}",
        std::process::id()
    ))
}

struct SpawnedHerdr {
    _master: Box<dyn MasterPty + Send>,
    input: Option<Box<dyn Write + Send>>,
    child: Box<dyn Child + Send + Sync>,
}

impl SpawnedHerdr {
    fn write_input(&mut self, input: &[u8]) {
        let writer = self.input.as_mut().expect("spawned client input writer");
        writer.write_all(input).expect("write spawned client input");
        writer.flush().expect("flush spawned client input");
    }
}

impl Drop for SpawnedHerdr {
    fn drop(&mut self) {
        let pid = self.child.process_id();
        let _ = self.child.kill();

        if let Some(pid) = pid {
            let deadline = Instant::now() + Duration::from_secs(2);
            while Instant::now() < deadline {
                let mut status = 0;
                let result =
                    unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
                if result == pid as libc::pid_t || result == -1 {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }

            unregister_spawned_herdr_pid(Some(pid));
        }
    }
}

fn cleanup_spawned_herdr(spawned: SpawnedHerdr, base: PathBuf) {
    drop(spawned);
    cleanup_test_base(&base);
}

fn wait_for_child_exit(child: &mut Box<dyn Child + Send + Sync>) {
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_clean_server_exit(child: &mut Box<dyn Child + Send + Sync>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "server should exit cleanly: {status}");
                return;
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => panic!("poll server exit: {error}"),
        }
    }
    panic!("server did not exit cleanly within {timeout:?}");
}

fn test_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wait_for_socket(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("socket did not appear at {}", path.display());
}

fn wait_for_file(path: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() && UnixStream::connect(path).is_ok() {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("socket did not accept connections at {}", path.display());
}

fn accept_spawned_client(
    listener: &UnixListener,
    client: &mut SpawnedHerdr,
    timeout: Duration,
) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("make fake client listener nonblocking");
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => panic!("accept spawned terminal client: {error}"),
        }
        match client.child.try_wait() {
            Ok(Some(status)) => panic!(
                "spawned terminal client exited before connecting: pid={:?}, status={status}",
                client.child.process_id()
            ),
            Ok(None) => {}
            Err(error) => panic!("poll spawned terminal client: {error}"),
        }
        assert!(
            Instant::now() < deadline,
            "spawned terminal client did not connect within {timeout:?}; pid={:?}",
            client.child.process_id()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn test_config_dir(config_home: &Path) -> PathBuf {
    let app_dir = if cfg!(debug_assertions) {
        "herdr-dev"
    } else {
        "herdr"
    };
    config_home.join(app_dir)
}

fn spawn_server(config_home: &Path, runtime_dir: &Path, api_socket_path: &Path) -> SpawnedHerdr {
    spawn_server_with_test_controls(config_home, runtime_dir, api_socket_path, None, None)
}

fn spawn_server_with_test_controls(
    config_home: &Path,
    runtime_dir: &Path,
    api_socket_path: &Path,
    monotonic_clock_path: Option<&Path>,
    external_open_delivery_failure_path: Option<&Path>,
) -> SpawnedHerdr {
    fs::create_dir_all(config_home.join("herdr")).unwrap();
    fs::create_dir_all(runtime_dir).unwrap();
    let opener_bin = config_home.join("recording-opener-bin");
    fs::create_dir_all(&opener_bin).unwrap();
    let opener_script = "#!/bin/sh\nprintf '%s\\n' \"$1\" >> \"$HERDR_TEST_OPEN_LOG\"\n";
    for program in ["xdg-open", "open"] {
        let path = opener_bin.join(program);
        fs::write(&path, opener_script).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = std::env::join_paths(std::iter::once(opener_bin.clone()).chain(
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()),
    ))
    .unwrap();
    register_runtime_dir(runtime_dir);
    fs::write(
        config_home.join("herdr/config.toml"),
        "onboarding = false\n",
    )
    .unwrap();

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    cmd.arg("server");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("HERDR_SOCKET_PATH", api_socket_path);
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env("SHELL", "/bin/sh");
    cmd.env("PATH", path);
    cmd.env("HERDR_TEST_OPEN_LOG", external_open_log_path(config_home));
    if let Some(path) = monotonic_clock_path {
        cmd.env("HERDR_TEST_MONOTONIC_CLOCK_PATH", path);
    }
    if let Some(path) = external_open_delivery_failure_path {
        cmd.env("HERDR_TEST_EXTERNAL_OPEN_DELIVERY_FAILURE_PATH", path);
    }
    cmd.env_remove("HERDR_ENV");

    let child = pair.slave.spawn_command(cmd).unwrap();
    register_spawned_herdr_pid(child.process_id());
    drop(pair.slave);

    SpawnedHerdr {
        _master: pair.master,
        input: None,
        child,
    }
}

fn spawn_client_process(
    config_home: &Path,
    runtime_dir: &Path,
    api_socket_path: &Path,
) -> SpawnedHerdr {
    register_runtime_dir(runtime_dir);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();

    let opener_bin = config_home.join("recording-opener-bin");
    let path = std::env::join_paths(std::iter::once(opener_bin).chain(std::env::split_paths(
        &std::env::var_os("PATH").unwrap_or_default(),
    )))
    .unwrap();
    let input = pair.master.take_writer().expect("client PTY input writer");
    let mut output = pair
        .master
        .try_clone_reader()
        .expect("client PTY output reader");
    thread::spawn(move || {
        let _ = io::copy(&mut output, &mut io::sink());
    });

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    cmd.arg("client");
    cmd.env("HERDR_DISABLE_SOUND", "1");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env("HERDR_SOCKET_PATH", api_socket_path);
    cmd.env_remove("HERDR_CLIENT_SOCKET_PATH");
    cmd.env("SHELL", "/bin/sh");
    cmd.env("PATH", path);
    cmd.env(
        "HERDR_TEST_OPEN_LOG",
        client_external_open_log_path(config_home),
    );
    cmd.env_remove("HERDR_ENV");

    let child = pair.slave.spawn_command(cmd).unwrap();
    register_spawned_herdr_pid(child.process_id());
    drop(pair.slave);

    SpawnedHerdr {
        _master: pair.master,
        input: Some(input),
        child,
    }
}

fn spawn_terminal_client_process(
    config_home: &Path,
    runtime_dir: &Path,
    client_socket_path: &Path,
    args: &[&str],
) -> SpawnedHerdr {
    register_runtime_dir(runtime_dir);
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
    let input = pair
        .master
        .take_writer()
        .expect("terminal client PTY input");
    let mut output = pair
        .master
        .try_clone_reader()
        .expect("terminal client PTY output");
    thread::spawn(move || {
        let _ = io::copy(&mut output, &mut io::sink());
    });

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_herdr"));
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env("HERDR_DISABLE_SOUND", "1");
    cmd.env("XDG_CONFIG_HOME", config_home);
    cmd.env("XDG_RUNTIME_DIR", runtime_dir);
    cmd.env_remove("HERDR_SOCKET_PATH");
    cmd.env("HERDR_CLIENT_SOCKET_PATH", client_socket_path);
    cmd.env("SHELL", "/bin/sh");
    cmd.env_remove("HERDR_ENV");

    let child = pair.slave.spawn_command(cmd).unwrap();
    register_spawned_herdr_pid(child.process_id());
    drop(pair.slave);

    SpawnedHerdr {
        _master: pair.master,
        input: Some(input),
        child,
    }
}

fn external_open_log_path(config_home: &Path) -> PathBuf {
    config_home.join("external-open.log")
}

fn client_external_open_log_path(config_home: &Path) -> PathBuf {
    config_home.join("client-external-open.log")
}

fn set_test_monotonic_time(path: &Path, elapsed: Duration) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create controlled monotonic clock directory");
    }
    fs::write(path, elapsed.as_nanos().to_string()).expect("write controlled monotonic time");
}

fn write_external_open_config(config_home: &Path, enabled: bool) {
    fs::create_dir_all(test_config_dir(config_home)).unwrap();
    fs::write(
        test_config_dir(config_home).join("config.toml"),
        format!("onboarding = false\n\n[experimental]\nopen_remote_links_on_client = {enabled}\n"),
    )
    .unwrap();
}

fn server_log_path(config_home: &Path) -> PathBuf {
    test_config_dir(config_home).join("herdr-server.log")
}

fn count_log_occurrences(path: &Path, needle: &str) -> usize {
    fs::read_to_string(path)
        .ok()
        .map(|text| text.lines().filter(|line| line.contains(needle)).count())
        .unwrap_or(0)
}

fn log_tail(path: &Path, lines: usize) -> String {
    let Ok(text) = fs::read_to_string(path) else {
        return format!("could not read {}", path.display());
    };
    let mut tail = VecDeque::with_capacity(lines);
    for line in text.lines() {
        if tail.len() == lines {
            tail.pop_front();
        }
        tail.push_back(line.to_string());
    }
    tail.into_iter().collect::<Vec<_>>().join("\n")
}

fn wait_for_external_open_log(path: &Path, expected_url: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if fs::read_to_string(path)
            .ok()
            .is_some_and(|text| text.lines().any(|line| line == expected_url))
        {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

fn wait_for_log_occurrence_count(
    path: &Path,
    needle: &str,
    min_count: usize,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if count_log_occurrences(path, needle) >= min_count {
            return true;
        }
        thread::sleep(Duration::from_millis(40));
    }
    false
}

fn structured_diagnostic_lines(path: &Path, message: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| line.contains(message))
        .map(str::to_owned)
        .collect()
}

fn structured_diagnostic_fields(line: &str, message: &str) -> Vec<(String, String)> {
    let (_, fields) = line
        .split_once(message)
        .unwrap_or_else(|| panic!("diagnostic line must contain {message:?}: {line}"));
    fields
        .split_whitespace()
        .map(|field| {
            let (name, value) = field
                .split_once('=')
                .unwrap_or_else(|| panic!("diagnostic field must be named: {field:?} in {line}"));
            (name.to_owned(), value.trim_matches('"').to_owned())
        })
        .collect()
}

fn assert_structured_diagnostic_fields(line: &str, message: &str, expected: &[(&str, String)]) {
    let actual = structured_diagnostic_fields(line, message);
    let expected = expected
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "diagnostic fields must match the allowlist"
    );
    let outcome = actual
        .iter()
        .find_map(|(name, value)| (name == "outcome").then_some(value))
        .expect("allowlisted diagnostic outcome");
    assert!(
        !outcome.contains('(')
            && !outcome.contains(')')
            && outcome.chars().all(|ch| !ch.is_ascii_uppercase()),
        "diagnostic outcome must use canonical vocabulary, not Rust Debug syntax: {outcome}"
    );
}

fn all_external_open_settlement_lines(path: &Path) -> Vec<String> {
    structured_diagnostic_lines(path, "external-open request settled")
}

fn external_open_settlement_lines(path: &Path, request_id: u64) -> Vec<String> {
    let request_id = format!("request_id={request_id}");
    all_external_open_settlement_lines(path)
        .into_iter()
        .filter(|line| line.contains(&request_id))
        .collect()
}

fn settlement_request_id(line: &str) -> Option<u64> {
    line.split_whitespace().find_map(|field| {
        field
            .strip_prefix("request_id=")
            .and_then(|value| value.parse().ok())
    })
}

fn wait_for_external_open_settlement(
    path: &Path,
    request_id: u64,
    expected_outcome: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(line) = external_open_settlement_lines(path, request_id)
            .into_iter()
            .find(|line| line.contains(expected_outcome))
        {
            return line;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!(
        "request {request_id} did not settle as {expected_outcome}; log tail:\n{}",
        log_tail(path, 80)
    );
}

fn assert_no_server_opener_calls(config_home: &Path) {
    let path = external_open_log_path(config_home);
    assert!(
        fs::read_to_string(&path).unwrap_or_default().is_empty(),
        "enabled request must never use server fallback; opener log={:?}",
        fs::read_to_string(path)
    );
}

#[derive(Default)]
struct RecordingOpener {
    request_ids: Vec<u64>,
}

impl RecordingOpener {
    fn invoke_after_next_commit(
        &mut self,
        stream: &mut UnixStream,
        expected_request_id: u64,
    ) -> io::Result<()> {
        let request_id = read_external_request_id(stream, 12, Duration::from_secs(3))?;
        if request_id != expected_request_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected commit {expected_request_id}, got {request_id}"),
            ));
        }
        self.request_ids.push(request_id);
        Ok(())
    }

    fn request_ids(&self) -> &[u64] {
        &self.request_ids
    }
}

fn ping_socket(socket_path: &Path) -> String {
    let mut stream = UnixStream::connect(socket_path).expect("should connect to API socket");
    writeln!(
        stream,
        "{{\"id\":\"ping\",\"method\":\"ping\",\"params\":{{}}}}"
    )
    .unwrap();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    response.trim().to_string()
}

fn send_json_request(socket_path: &Path, request: &str) -> Value {
    let mut stream = UnixStream::connect(socket_path).expect("should connect to API socket");
    writeln!(stream, "{request}").unwrap();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();

    serde_json::from_str(&response).expect("response should be valid JSON")
}

fn stop_server_normally(socket_path: &Path) {
    let response = send_json_request(
        socket_path,
        r#"{"id":"external-open-shutdown","method":"server.stop","params":{}}"#,
    );
    assert!(
        response.get("error").is_none(),
        "server.stop should succeed: {response}"
    );
}

fn create_workspace_and_root_terminal(socket_path: &Path, label: &str) -> (String, String, String) {
    let response = send_json_request(
        socket_path,
        &format!(
            "{{\"id\":\"ws_create\",\"method\":\"workspace.create\",\"params\":{{\"label\":\"{label}\"}}}}"
        ),
    );

    if response.get("error").is_some() {
        panic!("workspace.create failed: {response}");
    }

    let workspace_id = response
        .pointer("/result/workspace/workspace_id")
        .and_then(Value::as_str)
        .expect("workspace.create should return workspace id")
        .to_string();

    let pane_id = response
        .pointer("/result/root_pane/pane_id")
        .and_then(Value::as_str)
        .expect("workspace.create should return root pane id")
        .to_string();

    let terminal_id = response
        .pointer("/result/root_pane/terminal_id")
        .and_then(Value::as_str)
        .expect("workspace.create should return terminal id")
        .to_string();

    (workspace_id, pane_id, terminal_id)
}

fn create_workspace_and_root_pane(socket_path: &Path, label: &str) -> (String, String) {
    let (workspace_id, pane_id, _) = create_workspace_and_root_terminal(socket_path, label);
    (workspace_id, pane_id)
}

fn pane_send_input(socket_path: &Path, pane_id: &str, text: &str) {
    let request = format!(
        "{{\"id\":\"send_input\",\"method\":\"pane.send_input\",\"params\":{{\"pane_id\":\"{pane_id}\",\"text\":\"{}\",\"keys\":[\"Enter\"]}}}}",
        text.replace('"', "\\\"")
    );
    let response = send_json_request(socket_path, &request);
    if response.get("error").is_some() {
        panic!("pane.send_input failed: {response}");
    }
}

fn pane_read_recent(socket_path: &Path, pane_id: &str, lines: usize) -> String {
    let response = send_json_request(
        socket_path,
        &format!(
            "{{\"id\":\"pane_read\",\"method\":\"pane.read\",\"params\":{{\"pane_id\":\"{pane_id}\",\"source\":\"recent\",\"lines\":{lines}}}}}"
        ),
    );

    if response.get("error").is_some() {
        panic!("pane.read failed: {response}");
    }

    response
        .pointer("/result/read/text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn pane_read_recent_contains(
    socket_path: &Path,
    pane_id: &str,
    needle: &str,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if pane_read_recent(socket_path, pane_id, 200).contains(needle) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

fn parse_size_after_marker(text: &str, marker: &str) -> Option<(u16, u16)> {
    let mut seen_marker = false;
    for line in text.lines() {
        if !seen_marker {
            if line.contains(marker) {
                seen_marker = true;
            }
            continue;
        }

        let mut parts = line.split_whitespace();
        let Some(rows_raw) = parts.next() else {
            continue;
        };
        let Some(cols_raw) = parts.next() else {
            continue;
        };

        let Ok(rows) = rows_raw.parse::<u16>() else {
            continue;
        };
        let Ok(cols) = cols_raw.parse::<u16>() else {
            continue;
        };

        return Some((rows, cols));
    }

    None
}

fn try_read_pane_tty_size(
    socket_path: &Path,
    pane_id: &str,
    timeout: Duration,
) -> Option<(u16, u16)> {
    let marker = format!(
        "SIZE_MARKER_{}_{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );

    pane_send_input(socket_path, pane_id, &format!("echo {marker}; stty size"));

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let text = pane_read_recent(socket_path, pane_id, 200);
        if let Some(size) = parse_size_after_marker(&text, &marker) {
            return Some(size);
        }
        thread::sleep(Duration::from_millis(50));
    }

    None
}

fn read_pane_tty_size(socket_path: &Path, pane_id: &str, timeout: Duration) -> (u16, u16) {
    if let Some(size) = try_read_pane_tty_size(socket_path, pane_id, timeout) {
        return size;
    }

    let snapshot = pane_read_recent(socket_path, pane_id, 200);
    panic!(
        "did not observe tty size after marker. pane output:\n{}",
        snapshot
    );
}

// ---------------------------------------------------------------------------
// Minimal bincode v2 varint helpers for protocol tests
// ---------------------------------------------------------------------------

fn encode_varint_u32(v: u32) -> Vec<u8> {
    if v < 251 {
        vec![v as u8]
    } else if v < 65536 {
        let mut buf = vec![251u8];
        buf.extend_from_slice(&(v as u16).to_le_bytes());
        buf
    } else {
        let mut buf = vec![252u8];
        buf.extend_from_slice(&v.to_le_bytes());
        buf
    }
}

fn encode_varint_u16(v: u16) -> Vec<u8> {
    if v < 251 {
        vec![v as u8]
    } else {
        let mut buf = vec![251u8];
        buf.extend_from_slice(&v.to_le_bytes());
        buf
    }
}

fn frame_message(payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut framed = len.to_le_bytes().to_vec();
    framed.extend_from_slice(payload);
    framed
}

fn decode_varint_u32(payload: &[u8], offset: usize) -> Result<(u32, usize), String> {
    if offset >= payload.len() {
        return Err("payload too short for varint".into());
    }
    let first_byte = payload[offset];
    match first_byte {
        0..=250 => Ok((first_byte as u32, 1)),
        251 => {
            if offset + 3 > payload.len() {
                return Err("payload too short for u16 varint".into());
            }
            let v = u16::from_le_bytes(
                payload[offset + 1..offset + 3]
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
            );
            Ok((v as u32, 3))
        }
        252 => {
            if offset + 5 > payload.len() {
                return Err("payload too short for u32 varint".into());
            }
            let v = u32::from_le_bytes(
                payload[offset + 1..offset + 5]
                    .try_into()
                    .map_err(|e: std::array::TryFromSliceError| e.to_string())?,
            );
            Ok((v, 5))
        }
        _ => Err(format!("unsupported varint tag: {first_byte}")),
    }
}

fn is_timeout(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn read_server_variant(stream: &mut UnixStream, timeout: Duration) -> io::Result<u32> {
    stream.set_read_timeout(Some(timeout))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length payload",
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;

    let (variant, _consumed) = decode_varint_u32(&payload, 0)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(variant)
}

fn complete_fake_terminal_client_handshake(stream: &mut UnixStream) {
    let (variant, payload) =
        read_server_message_payload(stream, Duration::from_secs(5)).expect("terminal client hello");
    assert_eq!(variant, 0, "first client message must be Hello");

    let mut offset = 0;
    for field in [
        "version",
        "cols",
        "rows",
        "cell width",
        "cell height",
        "render encoding",
    ] {
        let (_, consumed) = decode_varint_u32(&payload, offset)
            .unwrap_or_else(|error| panic!("decode Hello {field}: {error}"));
        offset += consumed;
    }
    let (keybindings, consumed) =
        decode_varint_u32(&payload, offset).expect("decode Hello keybindings");
    offset += consumed;
    assert_eq!(
        keybindings, 0,
        "test terminal client should use server keys"
    );
    let (launch_mode, consumed) =
        decode_varint_u32(&payload, offset).expect("decode Hello launch mode");
    offset += consumed;
    assert_eq!(launch_mode, 1, "terminal client launch mode");
    assert_eq!(
        payload.get(offset),
        Some(&0),
        "terminal policy must be absent"
    );

    let mut welcome = encode_varint_u32(0); // ServerMessage::Welcome
    welcome.extend_from_slice(&encode_varint_u32(CURRENT_PROTOCOL));
    welcome.extend_from_slice(&encode_varint_u32(1)); // RenderEncoding::TerminalAnsi
    welcome.push(0); // no handshake error
    send_client_message(stream, welcome);
}

fn assert_no_client_policy_update(stream: &mut UnixStream, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(75));
        match read_server_message_payload(stream, slice) {
            Ok((10, _)) => panic!("terminal client leaked ExternalOpenPolicyUpdate"),
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {}
            Err(error) => panic!("terminal client connection failed during privacy check: {error}"),
        }
    }
}

fn client_handshake_with_kind(
    stream: &mut UnixStream,
    version: u32,
    cols: u16,
    rows: u16,
    launch_mode: u32,
    external_open_policy: Option<u32>,
    render_encoding: u32,
) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;

    // ClientMessage::Hello = variant 0
    let mut hello_payload = encode_varint_u32(0);
    hello_payload.extend_from_slice(&encode_varint_u32(version));
    hello_payload.extend_from_slice(&encode_varint_u16(cols));
    hello_payload.extend_from_slice(&encode_varint_u16(rows));
    hello_payload.extend_from_slice(&encode_varint_u32(8));
    hello_payload.extend_from_slice(&encode_varint_u32(16));
    hello_payload.extend_from_slice(&encode_varint_u32(render_encoding));
    hello_payload.extend_from_slice(&encode_varint_u32(0)); // ClientKeybindings::Server
    hello_payload.extend_from_slice(&encode_varint_u32(launch_mode));
    match external_open_policy {
        Some(policy) => {
            hello_payload.extend_from_slice(&encode_varint_u32(1));
            hello_payload.extend_from_slice(&encode_varint_u32(policy));
        }
        None => hello_payload.extend_from_slice(&encode_varint_u32(0)),
    }
    stream
        .write_all(&frame_message(&hello_payload))
        .map_err(|e| e.to_string())?;
    stream.flush().map_err(|e| e.to_string())?;

    // Read ServerMessage::Welcome = variant 0
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(len_buf) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).map_err(|e| e.to_string())?;

    let mut offset = 0;
    let (variant, consumed) = decode_varint_u32(&payload, offset)?;
    offset += consumed;
    if variant != 0 {
        return Err(format!("expected Welcome variant 0, got {variant}"));
    }

    let (_server_version, consumed) = decode_varint_u32(&payload, offset)?;
    offset += consumed;

    let (_encoding, consumed) = decode_varint_u32(&payload, offset)?;
    offset += consumed;

    if offset >= payload.len() {
        return Err("payload too short for Welcome.error option tag".into());
    }
    let option_tag = payload[offset];
    offset += 1;

    if option_tag == 1 {
        let (str_len, consumed) = decode_varint_u32(&payload, offset)?;
        offset += consumed;
        let str_len = str_len as usize;
        if offset + str_len > payload.len() {
            return Err("payload too short for welcome error string".into());
        }
        let err = String::from_utf8(payload[offset..offset + str_len].to_vec())
            .map_err(|e| e.to_string())?;
        return Err(format!("handshake rejected: {err}"));
    }

    Ok(())
}

fn connect_raw_client(client_socket: &Path, cols: u16, rows: u16) -> UnixStream {
    connect_full_app_client(client_socket, cols, rows, false)
}

fn connect_full_app_client(
    client_socket: &Path,
    cols: u16,
    rows: u16,
    external_open_enabled: bool,
) -> UnixStream {
    let mut stream = UnixStream::connect(client_socket).expect("should connect to client socket");
    client_handshake_with_kind(
        &mut stream,
        CURRENT_PROTOCOL,
        cols,
        rows,
        0,
        Some(u32::from(external_open_enabled)),
        0,
    )
    .expect("full app handshake should succeed");
    stream
}

fn connect_terminal_connection(client_socket: &Path, cols: u16, rows: u16) -> UnixStream {
    let mut stream = UnixStream::connect(client_socket).expect("should connect to client socket");
    client_handshake_with_kind(&mut stream, CURRENT_PROTOCOL, cols, rows, 1, None, 1)
        .expect("terminal connection handshake should succeed");
    stream
}

fn send_client_input(stream: &mut UnixStream, data: &[u8]) {
    // ClientMessage::Input = variant 1
    let payload = {
        let mut buf = encode_varint_u32(1);
        buf.extend_from_slice(&encode_varint_u32(data.len() as u32));
        buf.extend_from_slice(data);
        buf
    };
    stream.write_all(&frame_message(&payload)).unwrap();
    stream.flush().unwrap();
}

fn send_client_detach(stream: &mut UnixStream) {
    // ClientMessage::Detach = variant 4
    let payload = encode_varint_u32(4);
    stream.write_all(&frame_message(&payload)).unwrap();
    stream.flush().unwrap();
}

fn encode_string(value: &str) -> Vec<u8> {
    let mut encoded = encode_varint_u32(value.len() as u32);
    encoded.extend_from_slice(value.as_bytes());
    encoded
}

fn try_send_client_message(stream: &mut UnixStream, payload: Vec<u8>) -> io::Result<()> {
    stream.write_all(&frame_message(&payload))?;
    stream.flush()
}

fn send_client_message(stream: &mut UnixStream, payload: Vec<u8>) {
    try_send_client_message(stream, payload).unwrap();
}

fn send_ctrl_click(stream: &mut UnixStream, column: u16, row: u16) {
    let mut payload = encode_varint_u32(7); // ClientMessage::InputEvents
    payload.extend_from_slice(&encode_varint_u32(1)); // one event
    payload.extend_from_slice(&encode_varint_u32(1)); // ClientInputEvent::Mouse
    payload.extend_from_slice(&encode_varint_u32(0)); // ClientMouseKind::Down
    payload.extend_from_slice(&encode_varint_u32(0)); // ClientMouseButton::Left
    payload.extend_from_slice(&encode_varint_u16(column));
    payload.extend_from_slice(&encode_varint_u16(row));
    payload.push(2); // KeyModifiers::CONTROL
    send_client_message(stream, payload);
}

fn send_spawned_client_ctrl_click(client: &mut SpawnedHerdr, column: u16, row: u16) {
    let input = format!("\x1b[<16;{};{}M", column + 1, row + 1);
    client.write_input(input.as_bytes());
}

fn send_focus_gained(stream: &mut UnixStream) {
    let mut payload = encode_varint_u32(7); // ClientMessage::InputEvents
    payload.extend_from_slice(&encode_varint_u32(1));
    payload.extend_from_slice(&encode_varint_u32(3)); // ClientInputEvent::FocusGained
    send_client_message(stream, payload);
}

fn send_external_open_policy(stream: &mut UnixStream, enabled: bool) {
    let mut payload = encode_varint_u32(10); // ClientMessage::ExternalOpenPolicyUpdate
    payload.extend_from_slice(&encode_varint_u32(u32::from(enabled)));
    send_client_message(stream, payload);
}

fn send_external_ready_direct(stream: &mut UnixStream, request_id: u64) {
    let mut payload = encode_varint_u32(11); // ClientMessage::ExternalOpenReady
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(0)); // ExternalOpenTarget::Direct
    send_client_message(stream, payload);
}

fn send_external_ready_forwarded(stream: &mut UnixStream, request_id: u64, remapped: bool) {
    let mut payload = encode_varint_u32(11); // ClientMessage::ExternalOpenReady
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(1)); // ExternalOpenTarget::Forwarded
    payload.extend_from_slice(&encode_varint_u32(u32::from(remapped))); // port status
    send_client_message(stream, payload);
}

fn send_external_opened_directly(stream: &mut UnixStream, request_id: u64) {
    let mut payload = encode_varint_u32(13); // ClientMessage::ExternalOpenResult
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(0)); // ExternalOpenResult::OpenedDirectly
    send_client_message(stream, payload);
}

fn send_external_opened_through_same_port(stream: &mut UnixStream, request_id: u64) {
    let mut payload = encode_varint_u32(13); // ClientMessage::ExternalOpenResult
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(1)); // OpenedThroughForward
    payload.extend_from_slice(&encode_varint_u32(0)); // SamePort
    send_client_message(stream, payload);
}

fn send_external_opener_rejected(stream: &mut UnixStream, request_id: u64) {
    let mut payload = encode_varint_u32(13); // ClientMessage::ExternalOpenResult
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(2)); // PlatformOpenRejected
    send_client_message(stream, payload);
}

fn send_external_preparation_failed(stream: &mut UnixStream, request_id: u64, reason_tag: u32) {
    let mut payload = encode_varint_u32(12); // ClientMessage::ExternalOpenPreparationFailed
    payload.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    payload.extend_from_slice(&encode_varint_u32(reason_tag));
    send_client_message(stream, payload);
}

fn send_terminal_attach(stream: &mut UnixStream, terminal_id: &str) {
    let mut payload = encode_varint_u32(5); // ClientMessage::AttachTerminal
    payload.extend_from_slice(&encode_string(terminal_id));
    payload.push(0); // takeover = false
    send_client_message(stream, payload);
}

fn send_terminal_observe(stream: &mut UnixStream, pane_id: &str) {
    let mut payload = encode_varint_u32(8); // ClientMessage::ObserveTerminal
    payload.extend_from_slice(&encode_string(pane_id));
    send_client_message(stream, payload);
}

fn send_terminal_control(stream: &mut UnixStream, pane_id: &str) {
    let mut payload = encode_varint_u32(9); // ClientMessage::ControlTerminal
    payload.extend_from_slice(&encode_string(pane_id));
    payload.push(0); // takeover = false
    send_client_message(stream, payload);
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct FrameWire {
    cells: Vec<CellWire>,
    width: u16,
    height: u16,
    cursor: Option<CursorWire>,
    hyperlinks: Vec<String>,
    graphics: Vec<u8>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct CellWire {
    symbol: String,
    fg: u32,
    bg: u32,
    modifier: u16,
    skip: bool,
    hyperlink: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct CursorWire {
    x: u16,
    y: u16,
    visible: bool,
    shape: u8,
}

fn decode_frame_payload(payload: &[u8]) -> io::Result<FrameWire> {
    bincode::serde::decode_from_slice(payload, bincode::config::standard())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
        .and_then(|(frame, consumed): (FrameWire, usize)| {
            if consumed != payload.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "frame payload had trailing bytes: consumed={}, len={}",
                        consumed,
                        payload.len()
                    ),
                ));
            }
            Ok(frame)
        })
}

fn read_server_message_payload(
    stream: &mut UnixStream,
    timeout: Duration,
) -> io::Result<(u32, Vec<u8>)> {
    stream.set_read_timeout(Some(timeout))?;

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zero-length payload",
        ));
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;

    let (variant, consumed) = decode_varint_u32(&payload, 0)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok((variant, payload[consumed..].to_vec()))
}

fn read_external_server_message(
    stream: &mut UnixStream,
    expected_variant: u32,
    timeout: Duration,
) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        match read_server_message_payload(stream, slice) {
            Ok((variant, payload)) if variant == expected_variant => return Ok(payload),
            Ok((variant, _)) if (11..=13).contains(&variant) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected external-open variant {expected_variant}, got {variant}"),
                ));
            }
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("external-open variant {expected_variant} not received"),
    ))
}

fn decode_external_request_id(payload: &[u8]) -> io::Result<(u64, usize)> {
    decode_varint_u32(payload, 0)
        .map(|(request_id, consumed)| (u64::from(request_id), consumed))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_external_prepare(stream: &mut UnixStream, timeout: Duration) -> io::Result<(u64, String)> {
    let payload = read_external_server_message(stream, 11, timeout)?;
    let (request_id, consumed) = decode_external_request_id(&payload)?;
    let (length, length_bytes) = decode_varint_u32(&payload, consumed)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let start = consumed + length_bytes;
    let end = start + length as usize;
    let url = payload
        .get(start..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated prepare URL"))?;
    String::from_utf8(url.to_vec())
        .map(|url| (request_id, url))
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn read_external_request_id(
    stream: &mut UnixStream,
    expected_variant: u32,
    timeout: Duration,
) -> io::Result<u64> {
    let payload = read_external_server_message(stream, expected_variant, timeout)?;
    decode_external_request_id(&payload).map(|(request_id, _)| request_id)
}

fn assert_no_external_server_message(stream: &mut UnixStream, duration: Duration) {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(50));
        match read_server_message_payload(stream, slice) {
            Ok((variant, _)) => assert!(
                !(11..=13).contains(&variant),
                "connection leaked external-open server variant {variant}"
            ),
            Err(error) if is_timeout(&error) => {}
            Err(_) => break,
        }
    }
}

fn read_until_server_disconnect(stream: &mut UnixStream, timeout: Duration) -> Vec<u32> {
    let deadline = Instant::now() + timeout;
    let mut variants = Vec::new();
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        match read_server_message_payload(stream, slice) {
            Ok((variant, _)) => variants.push(variant),
            Err(error) if is_timeout(&error) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                        | io::ErrorKind::NotConnected
                ) =>
            {
                return variants;
            }
            Err(error) => panic!("read client connection through server shutdown: {error}"),
        }
    }
    panic!("client connection remained open after {timeout:?}");
}

fn wait_for_terminal_frame(stream: &mut UnixStream, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        match read_server_variant(stream, slice) {
            Ok(2) => return true,
            Ok(4) => return false,
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {}
            Err(_) => return false,
        }
    }
    false
}

fn drain_server_messages(stream: &mut UnixStream, max_drain: Duration) {
    let deadline = Instant::now() + max_drain;
    while Instant::now() < deadline {
        match read_server_variant(stream, Duration::from_millis(50)) {
            Ok(_) => {}
            Err(err) if is_timeout(&err) => break,
            Err(_) => break,
        }
    }
}

fn wait_for_frame(stream: &mut UnixStream, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let slice = remaining.min(Duration::from_millis(75));
        match read_server_variant(stream, slice) {
            Ok(1) => return true, // ServerMessage::Frame
            Ok(_) => {}
            Err(err) if is_timeout(&err) => {}
            Err(_) => return false,
        }
    }
    false
}

fn wait_for_frame_matching_with_snapshots(
    stream: &mut UnixStream,
    timeout: Duration,
    predicate: impl Fn(&FrameWire) -> bool,
) -> io::Result<(bool, Vec<String>)> {
    let deadline = Instant::now() + timeout;
    let mut snapshots = VecDeque::with_capacity(5);
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(80));
        match read_server_message_payload(stream, slice) {
            Ok((1, frame_payload)) => {
                let frame = decode_frame_payload(&frame_payload)?;
                if snapshots.len() == 5 {
                    snapshots.pop_front();
                }
                snapshots.push_back(frame_text(&frame));
                if predicate(&frame) {
                    return Ok((true, snapshots.into_iter().collect()));
                }
            }
            Ok((_variant, _payload)) => {}
            Err(err) if is_timeout(&err) => {}
            Err(err) => return Err(err),
        }
    }

    Ok((false, snapshots.into_iter().collect()))
}

fn frame_text(frame: &FrameWire) -> String {
    if frame.cells.is_empty() {
        return String::new();
    }

    let row_width = frame.width.max(1) as usize;
    let mut full_text = String::new();

    for row in frame.cells.chunks(row_width) {
        for cell in row {
            let _ = (cell.fg, cell.bg, cell.modifier, cell.skip);
            full_text.push_str(&cell.symbol);
        }
        full_text.push('\n');
    }

    let _ = (frame.height, frame.graphics.len());
    if let Some(cursor) = frame.cursor.as_ref() {
        let _ = (cursor.x, cursor.y, cursor.visible, cursor.shape);
    }

    full_text
}

fn frame_contains_text(frame: &FrameWire, needle: &str) -> bool {
    frame_text(frame).contains(needle)
}

fn frame_text_position(frame: &FrameWire, needle: &str) -> Option<(u16, u16)> {
    let width = usize::from(frame.width.max(1));
    for (row_index, row) in frame.cells.chunks(width).enumerate() {
        let text = row
            .iter()
            .map(|cell| cell.symbol.as_str())
            .collect::<String>();
        let Some(byte_offset) = text.find(needle) else {
            continue;
        };
        let mut consumed = 0usize;
        for (column, cell) in row.iter().enumerate() {
            if consumed == byte_offset {
                return Some((column as u16, row_index as u16));
            }
            consumed += cell.symbol.len();
            if consumed > byte_offset {
                break;
            }
        }
    }
    None
}

fn wait_for_text_position(
    stream: &mut UnixStream,
    needle: &str,
    timeout: Duration,
) -> io::Result<(u16, u16)> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let slice = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        match read_server_message_payload(stream, slice) {
            Ok((1, payload)) => {
                let frame = decode_frame_payload(&payload)?;
                if let Some(position) = frame_text_position(&frame, needle) {
                    return Ok(position);
                }
            }
            Ok(_) => {}
            Err(error) if is_timeout(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("did not render text position for {needle}"),
    ))
}

#[test]
fn explicit_config_reload_replaces_real_full_client_policy_in_both_directions() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    write_external_open_config(&config_home, true);
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-config-reload");

    let server_log = server_log_path(&config_home);
    let connected_before = count_log_occurrences(&server_log, "client connected");
    let mut client = spawn_client_process(&config_home, &runtime_dir, &api_socket);
    assert!(wait_for_log_occurrence_count(
        &server_log,
        "client connected",
        connected_before + 1,
        Duration::from_secs(8),
    ));
    let mut observer = connect_full_app_client(&client_socket, 80, 24, false);
    assert!(wait_for_frame(&mut observer, Duration::from_secs(3)));
    client.write_input(b"echo spawned-client-input-ready\n");
    assert!(
        pane_read_recent_contains(
            &api_socket,
            &link_pane,
            "spawned-client-input-ready",
            Duration::from_secs(3),
        ),
        "spawned client PTY input must reach the production client loop"
    );

    let enabled_url = "https://example.com/herdr-ticket-30-reload-enabled";
    pane_send_input(&api_socket, &link_pane, &format!("echo {enabled_url}"));
    let (column, row) = wait_for_text_position(&mut observer, enabled_url, Duration::from_secs(8))
        .expect("observer should locate enabled-policy link");
    thread::sleep(Duration::from_millis(100));
    send_spawned_client_ctrl_click(&mut client, column, row);
    assert!(wait_for_external_open_log(
        &client_external_open_log_path(&config_home),
        enabled_url,
        Duration::from_secs(3),
    ));
    assert!(!wait_for_external_open_log(
        &external_open_log_path(&config_home),
        enabled_url,
        Duration::from_millis(200),
    ));

    write_external_open_config(&config_home, false);
    let response = send_json_request(
        &api_socket,
        r#"{"id":"disable-client-open","method":"server.reload_config","params":{}}"#,
    );
    assert!(
        response.get("result").is_some(),
        "reload response: {response}"
    );
    assert!(wait_for_log_occurrence_count(
        &server_log,
        "external-open policy updated",
        1,
        Duration::from_secs(3),
    ));

    let disabled_url = "https://example.com/herdr-ticket-30-reload-disabled";
    pane_send_input(&api_socket, &link_pane, &format!("echo {disabled_url}"));
    let (column, row) = wait_for_text_position(&mut observer, disabled_url, Duration::from_secs(8))
        .expect("observer should locate disabled-policy link");
    thread::sleep(Duration::from_millis(100));
    send_spawned_client_ctrl_click(&mut client, column, row);
    assert!(wait_for_external_open_log(
        &external_open_log_path(&config_home),
        disabled_url,
        Duration::from_secs(3),
    ));
    assert!(!wait_for_external_open_log(
        &client_external_open_log_path(&config_home),
        disabled_url,
        Duration::from_millis(200),
    ));

    write_external_open_config(&config_home, true);
    let response = send_json_request(
        &api_socket,
        r#"{"id":"enable-client-open","method":"server.reload_config","params":{}}"#,
    );
    assert!(
        response.get("result").is_some(),
        "reload response: {response}"
    );
    assert!(wait_for_log_occurrence_count(
        &server_log,
        "external-open policy updated",
        2,
        Duration::from_secs(3),
    ));

    let reenabled_url = "https://example.com/herdr-ticket-30-reload-reenabled";
    pane_send_input(&api_socket, &link_pane, &format!("echo {reenabled_url}"));
    let (column, row) =
        wait_for_text_position(&mut observer, reenabled_url, Duration::from_secs(8))
            .expect("observer should locate re-enabled-policy link");
    thread::sleep(Duration::from_millis(100));
    send_spawned_client_ctrl_click(&mut client, column, row);
    assert!(wait_for_external_open_log(
        &client_external_open_log_path(&config_home),
        reenabled_url,
        Duration::from_secs(3),
    ));
    assert!(!wait_for_external_open_log(
        &external_open_log_path(&config_home),
        reenabled_url,
        Duration::from_millis(200),
    ));

    drop(client);
    cleanup_spawned_herdr(server, base);
}

#[test]
fn explicit_config_reload_never_advertises_policy_from_terminal_connection_kinds() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    fs::create_dir_all(&runtime_dir).unwrap();

    for (name, args, initial_variant) in [
        ("attach", ["terminal", "attach", "term-test", "", "", ""], 5),
        (
            "observe",
            ["terminal", "session", "observe", "w1:p1", "--cols", "80"],
            8,
        ),
        (
            "control",
            ["terminal", "session", "control", "w1:p1", "--cols", "80"],
            9,
        ),
    ] {
        write_external_open_config(&config_home, false);
        let client_socket = runtime_dir.join(format!("fake-{name}.sock"));
        let _ = fs::remove_file(&client_socket);
        let listener = UnixListener::bind(&client_socket).expect("bind fake client socket");
        let args = args
            .iter()
            .copied()
            .filter(|arg| !arg.is_empty())
            .collect::<Vec<_>>();
        let mut client =
            spawn_terminal_client_process(&config_home, &runtime_dir, &client_socket, &args);
        let mut stream = accept_spawned_client(&listener, &mut client, Duration::from_secs(5));
        complete_fake_terminal_client_handshake(&mut stream);
        let (variant, _) = read_server_message_payload(&mut stream, Duration::from_secs(5))
            .expect("terminal client mode request");
        assert_eq!(variant, initial_variant, "connection kind={name}");

        write_external_open_config(&config_home, true);
        send_client_message(&mut stream, encode_varint_u32(8)); // ReloadClientConfig
        assert_no_client_policy_update(&mut stream, Duration::from_millis(500));

        drop(stream);
        drop(listener);
        drop(client);
        let _ = fs::remove_file(client_socket);
    }

    cleanup_test_base(&base);
}

#[test]
fn external_open_routes_only_to_source_full_app_across_focus_and_connection_kinds() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let (_, link_pane, _) = create_workspace_and_root_terminal(&api_socket, "external-open-link");
    let (_, attach_pane, attach_terminal) =
        create_workspace_and_root_terminal(&api_socket, "external-open-attach");
    let (_, observe_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-observe");
    let (_, control_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-control");

    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let mut attach = connect_terminal_connection(&client_socket, 80, 24);
    send_terminal_attach(&mut attach, &attach_terminal);
    assert!(
        wait_for_terminal_frame(&mut attach, Duration::from_secs(3)),
        "attach connection should enter terminal streaming for {attach_pane}"
    );
    let mut observe = connect_terminal_connection(&client_socket, 80, 24);
    send_terminal_observe(&mut observe, &observe_pane);
    assert!(
        wait_for_terminal_frame(&mut observe, Duration::from_secs(3)),
        "observe connection should enter terminal streaming"
    );
    let mut control = connect_terminal_connection(&client_socket, 80, 24);
    send_terminal_control(&mut control, &control_pane);
    assert!(
        wait_for_terminal_frame(&mut control, Duration::from_secs(3)),
        "control connection should enter terminal streaming"
    );

    let url = "https://example.com/herdr-ticket-30-isolation";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .unwrap_or_else(|error| {
            panic!(
                "source should render clickable URL: {error}; pane output:\n{}\nserver log:\n{}",
                pane_read_recent(&api_socket, &link_pane, 100),
                log_tail(&server_log_path(&config_home), 80)
            )
        });
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);

    send_focus_gained(&mut other);
    thread::sleep(Duration::from_millis(150));
    assert_no_external_server_message(&mut other, Duration::from_millis(100));
    assert_no_external_server_message(&mut attach, Duration::from_millis(100));
    assert_no_external_server_message(&mut observe, Duration::from_millis(100));
    assert_no_external_server_message(&mut control, Duration::from_millis(100));

    let mut opener = RecordingOpener::default();
    assert!(
        opener.request_ids().is_empty(),
        "prepare must not invoke the opener"
    );
    send_external_ready_direct(&mut source, request_id);
    opener
        .invoke_after_next_commit(&mut source, request_id)
        .expect("source commit invokes opener");
    assert_no_external_server_message(&mut other, Duration::from_millis(150));
    assert_no_external_server_message(&mut attach, Duration::from_millis(100));
    assert_no_external_server_message(&mut observe, Duration::from_millis(100));
    assert_no_external_server_message(&mut control, Duration::from_millis(100));
    send_external_opened_directly(&mut source, request_id);
    assert_eq!(opener.request_ids(), &[request_id]);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "matching source result must settle exactly once"
    );
    assert_no_server_opener_calls(&config_home);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_socket_lifecycle_covers_forwarded_success_preparation_failure_and_opener_rejection(
) {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-forwarded-lifecycle");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));

    let url = "http://127.0.0.1:8080/private?a=%2F#frag";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render numeric loopback URL");
    let mut opener = RecordingOpener::default();

    send_ctrl_click(&mut source, column, row);
    let (same_port_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("same-port prepare");
    assert_eq!(prepared_url, url);
    assert!(opener.request_ids().is_empty());
    send_external_ready_forwarded(&mut source, same_port_id, false);
    opener
        .invoke_after_next_commit(&mut source, same_port_id)
        .expect("forwarded readiness commits");
    send_external_opened_through_same_port(&mut source, same_port_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        same_port_id,
        "opened_through_forward",
        Duration::from_secs(3),
    );

    send_ctrl_click(&mut source, column, row);
    let (failed_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("failed prepare");
    assert_eq!(prepared_url, url);
    send_external_preparation_failed(&mut source, failed_id, 14); // ForwardCommandRejected
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        failed_id,
        "forward_command_rejected",
        Duration::from_secs(3),
    );
    assert_eq!(
        opener.request_ids(),
        &[same_port_id],
        "preparation failure must not invoke the opener"
    );

    send_ctrl_click(&mut source, column, row);
    let (rejected_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("remapped prepare");
    assert_eq!(prepared_url, url);
    send_external_ready_forwarded(&mut source, rejected_id, true);
    opener
        .invoke_after_next_commit(&mut source, rejected_id)
        .expect("remapped readiness commits");
    send_external_opener_rejected(&mut source, rejected_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        rejected_id,
        "platform_open_rejected",
        Duration::from_secs(3),
    );

    assert_eq!(opener.request_ids(), &[same_port_id, rejected_id]);
    assert_no_server_opener_calls(&config_home);
    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_policy_update_cancels_uncommitted_request_and_isolates_late_messages() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-policy-cancel");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-policy-cancel";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render cancellable URL");
    send_ctrl_click(&mut source, column, row);
    let (cancelled_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("cancelled prepare");
    assert_eq!(prepared_url, url);

    let mut opener = RecordingOpener::default();
    assert!(
        opener.request_ids().is_empty(),
        "prepare cannot invoke opener"
    );
    send_external_open_policy(&mut source, false);
    assert_eq!(
        read_external_request_id(&mut source, 13, Duration::from_secs(3))
            .expect("policy revocation cancel"),
        cancelled_id
    );
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        cancelled_id,
        "cancelled_before_commit",
        Duration::from_secs(3),
    );
    assert!(
        opener.request_ids().is_empty(),
        "policy cancellation before commit must make zero opener calls"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(150));
    assert_no_server_opener_calls(&config_home);

    send_external_ready_direct(&mut source, cancelled_id);
    send_external_opened_directly(&mut source, cancelled_id);
    send_external_preparation_failed(&mut source, cancelled_id, 3);
    send_external_opened_directly(&mut other, cancelled_id);
    send_external_open_policy(&mut source, true);
    assert!(wait_for_log_occurrence_count(
        &server_log_path(&config_home),
        "external-open policy updated",
        2,
        Duration::from_secs(3),
    ));
    let policy_diagnostics = structured_diagnostic_lines(
        &server_log_path(&config_home),
        "external-open policy updated",
    );
    assert_eq!(policy_diagnostics.len(), 2);
    for policy_diagnostic in policy_diagnostics {
        assert_structured_diagnostic_fields(
            &policy_diagnostic,
            "external-open policy updated",
            &[
                ("lifecycle_phase", "policy_change".to_owned()),
                ("outcome", "applied".to_owned()),
            ],
        );
    }

    send_ctrl_click(&mut source, column, row);
    let (next_id, _) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("re-enabled prepare");
    let unknown_id = next_id + 10_000;
    send_external_ready_direct(&mut source, cancelled_id);
    send_external_opened_directly(&mut source, unknown_id);
    send_external_preparation_failed(&mut source, unknown_id, 3);
    send_external_ready_direct(&mut other, next_id);
    assert_no_external_server_message(&mut source, Duration::from_millis(150));

    send_external_ready_direct(&mut source, next_id);
    opener
        .invoke_after_next_commit(&mut source, next_id)
        .expect("re-enabled request commit");
    send_external_opened_directly(&mut source, next_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        next_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    send_external_opened_directly(&mut source, next_id);
    send_external_ready_direct(&mut source, next_id);
    thread::sleep(Duration::from_millis(100));

    assert_eq!(opener.request_ids(), &[next_id]);
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), cancelled_id).len(),
        1,
        "cancelled request must settle exactly once"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), next_id).len(),
        1,
        "re-enabled request must settle exactly once"
    );
    assert!(
        external_open_settlement_lines(&server_log_path(&config_home), unknown_id).is_empty(),
        "unknown messages must not settle"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(150));
    assert_no_server_opener_calls(&config_home);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_immediate_target_queue_failure_is_delivery_failed_without_reroute() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let delivery_failure_path = base.join("fail-next-external-open-delivery");
    let server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        None,
        Some(&delivery_failure_path),
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-queue-failure");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-queue-failure";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let source_position = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render clickable URL");
    let other_position = wait_for_text_position(&mut other, url, Duration::from_secs(8))
        .expect("other should render clickable URL");
    fs::write(&delivery_failure_path, b"fail next prepare enqueue")
        .expect("arm immediate delivery failure");

    let mut opener = RecordingOpener::default();
    send_ctrl_click(&mut source, source_position.0, source_position.1);
    assert!(wait_for_log_occurrence_count(
        &server_log_path(&config_home),
        "external-open request settled",
        1,
        Duration::from_secs(3),
    ));
    let settlements = all_external_open_settlement_lines(&server_log_path(&config_home));
    assert_eq!(settlements.len(), 1, "failed enqueue must settle once");
    assert!(
        settlements[0].contains("client_delivery_failed"),
        "immediate enqueue failure must not be classified as disconnect: {}",
        settlements[0]
    );
    let failed_id = settlement_request_id(&settlements[0]).expect("failed request id in log");
    assert!(
        opener.request_ids().is_empty(),
        "failed prepare enqueue must make zero opener calls"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(250));
    assert_no_server_opener_calls(&config_home);

    send_ctrl_click(&mut other, other_position.0, other_position.1);
    let (next_id, prepared_url) =
        read_external_prepare(&mut other, Duration::from_secs(3)).expect("other client prepare");
    assert_eq!(prepared_url, url);
    assert_ne!(next_id, failed_id);
    let unknown_id = next_id + 10_000;
    send_external_ready_direct(&mut other, failed_id);
    send_external_opened_directly(&mut other, failed_id);
    send_external_preparation_failed(&mut other, failed_id, 3);
    send_external_ready_direct(&mut other, unknown_id);
    send_external_opened_directly(&mut other, unknown_id);
    assert_no_external_server_message(&mut other, Duration::from_millis(150));
    assert!(
        opener.request_ids().is_empty(),
        "only commit can invoke opener"
    );

    send_external_ready_direct(&mut other, next_id);
    opener
        .invoke_after_next_commit(&mut other, next_id)
        .expect("other client's own request commits");
    send_external_opened_directly(&mut other, next_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        next_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    send_external_opened_directly(&mut other, next_id);
    send_external_ready_direct(&mut other, next_id);
    thread::sleep(Duration::from_millis(100));

    assert_eq!(opener.request_ids(), &[next_id]);
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), failed_id).len(),
        1,
        "delivery failure must remain settled exactly once"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), next_id).len(),
        1,
        "unrelated client request must settle exactly once"
    );
    assert!(
        external_open_settlement_lines(&server_log_path(&config_home), unknown_id).is_empty(),
        "unknown IDs must remain isolated"
    );
    assert_no_server_opener_calls(&config_home);
    assert!(ping_socket(&api_socket).contains("pong"));

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_precommit_connection_loss_never_reroutes_or_falls_back() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-precommit-loss");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-precommit-loss";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render clickable URL");
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);
    let opener = RecordingOpener::default();

    drop(source);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "client_disconnected_before_commit",
        Duration::from_secs(3),
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "pre-commit connection loss must settle exactly once"
    );
    assert!(
        opener.request_ids().is_empty(),
        "pre-commit connection loss must make zero opener calls"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(300));
    assert_no_server_opener_calls(&config_home);
    assert!(ping_socket(&api_socket).contains("pong"));

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_normal_shutdown_before_commit_settles_once_without_opener_or_late_work() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let clock_path = base.join("precommit-shutdown-monotonic-clock");
    set_test_monotonic_time(&clock_path, Duration::ZERO);
    let mut server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        Some(&clock_path),
        None,
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-precommit-shutdown");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-precommit-shutdown";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render shutdown URL");
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);
    let opener = RecordingOpener::default();
    assert!(
        opener.request_ids().is_empty(),
        "prepare before shutdown must not invoke opener"
    );

    set_test_monotonic_time(&clock_path, Duration::from_secs(1));
    stop_server_normally(&api_socket);
    let source_variants = read_until_server_disconnect(&mut source, Duration::from_secs(5));
    let other_variants = read_until_server_disconnect(&mut other, Duration::from_secs(5));
    assert!(
        source_variants.contains(&4),
        "source should receive ServerShutdown"
    );
    assert!(
        other_variants.contains(&4),
        "other should receive ServerShutdown"
    );
    assert!(
        source_variants.iter().all(|variant| !(11..=13).contains(variant)),
        "shutdown before commit must not grant authority or emit another external-open message: {source_variants:?}"
    );
    assert!(
        other_variants
            .iter()
            .all(|variant| !(11..=13).contains(variant)),
        "shutdown must not leak external-open work to another client: {other_variants:?}"
    );
    wait_for_clean_server_exit(&mut server.child, Duration::from_secs(5));

    let settlement = wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "client_disconnected_before_commit",
        Duration::from_secs(1),
    );
    assert_structured_diagnostic_fields(
        &settlement,
        "external-open request settled",
        &[
            ("request_id", request_id.to_string()),
            ("lifecycle_phase", "terminal".to_owned()),
            ("outcome", "client_disconnected_before_commit".to_owned()),
            ("elapsed_ms", "1000".to_owned()),
            ("commit_state", "uncommitted".to_owned()),
            ("forward_status", "no".to_owned()),
        ],
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "complete_shutdown followed by Drop must settle exactly once"
    );
    assert!(
        opener.request_ids().is_empty(),
        "normal shutdown before commit must make zero opener calls"
    );
    assert_no_server_opener_calls(&config_home);
    assert!(UnixStream::connect(&client_socket).is_err());

    let mut late_result = encode_varint_u32(13); // ClientMessage::ExternalOpenResult
    late_result.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    late_result.extend_from_slice(&encode_varint_u32(0)); // OpenedDirectly
    assert!(
        try_send_client_message(&mut source, late_result).is_err(),
        "a disconnected initiating client cannot send a late result"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "late work after process exit cannot create another terminal event"
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_normal_shutdown_after_commit_is_unknown_once_without_retry_or_late_work() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let clock_path = base.join("committed-shutdown-monotonic-clock");
    set_test_monotonic_time(&clock_path, Duration::ZERO);
    let mut server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        Some(&clock_path),
        None,
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-committed-shutdown");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-committed-shutdown";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render committed shutdown URL");
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);
    let mut opener = RecordingOpener::default();
    assert!(
        opener.request_ids().is_empty(),
        "prepare before shutdown must not invoke opener"
    );

    set_test_monotonic_time(&clock_path, Duration::from_secs(1));
    send_external_ready_direct(&mut source, request_id);
    opener
        .invoke_after_next_commit(&mut source, request_id)
        .expect("commit authorizes exactly one opener call");
    assert_eq!(opener.request_ids(), &[request_id]);

    set_test_monotonic_time(&clock_path, Duration::from_secs(2));
    stop_server_normally(&api_socket);
    let source_variants = read_until_server_disconnect(&mut source, Duration::from_secs(5));
    let other_variants = read_until_server_disconnect(&mut other, Duration::from_secs(5));
    assert!(
        source_variants.contains(&4),
        "source should receive ServerShutdown"
    );
    assert!(
        other_variants.contains(&4),
        "other should receive ServerShutdown"
    );
    assert!(
        source_variants.iter().all(|variant| !(11..=13).contains(variant)),
        "shutdown after commit must not retry or emit another external-open message: {source_variants:?}"
    );
    assert!(
        other_variants
            .iter()
            .all(|variant| !(11..=13).contains(variant)),
        "shutdown must not leak committed work to another client: {other_variants:?}"
    );
    wait_for_clean_server_exit(&mut server.child, Duration::from_secs(5));

    let settlement = wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "committed_outcome_unknown",
        Duration::from_secs(1),
    );
    assert_structured_diagnostic_fields(
        &settlement,
        "external-open request settled",
        &[
            ("request_id", request_id.to_string()),
            ("lifecycle_phase", "terminal".to_owned()),
            ("outcome", "committed_outcome_unknown".to_owned()),
            ("elapsed_ms", "2000".to_owned()),
            ("commit_state", "committed".to_owned()),
            ("forward_status", "no".to_owned()),
        ],
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "complete_shutdown followed by Drop must settle committed work exactly once"
    );
    assert_eq!(
        opener.request_ids(),
        &[request_id],
        "normal shutdown after commit must not retry the opener"
    );
    assert_no_server_opener_calls(&config_home);
    assert!(UnixStream::connect(&client_socket).is_err());

    let mut late_result = encode_varint_u32(13); // ClientMessage::ExternalOpenResult
    late_result.extend_from_slice(&encode_varint_u32(u32::try_from(request_id).unwrap()));
    late_result.extend_from_slice(&encode_varint_u32(0)); // OpenedDirectly
    assert!(
        try_send_client_message(&mut source, late_result).is_err(),
        "a disconnected initiating client cannot report a late committed result"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "late committed work after process exit cannot create another terminal event"
    );
    assert_eq!(opener.request_ids(), &[request_id]);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_result_before_commit_closes_without_revival_or_reroute() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let clock_path = base.join("invalid-result-monotonic-clock");
    set_test_monotonic_time(&clock_path, Duration::ZERO);
    let server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        Some(&clock_path),
        None,
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-invalid-result");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-invalid-result";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render clickable URL");
    let mut opener = RecordingOpener::default();

    send_ctrl_click(&mut source, column, row);
    let (invalid_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("invalid prepare");
    assert_eq!(prepared_url, url);
    let unknown_id = invalid_id + 10_000;

    set_test_monotonic_time(&clock_path, Duration::from_secs(1));
    send_external_opened_directly(&mut source, invalid_id);
    let invalid_settlement = wait_for_external_open_settlement(
        &server_log_path(&config_home),
        invalid_id,
        "invalid_client_result",
        Duration::from_secs(3),
    );
    assert_structured_diagnostic_fields(
        &invalid_settlement,
        "external-open request settled",
        &[
            ("request_id", invalid_id.to_string()),
            ("lifecycle_phase", "terminal".to_owned()),
            ("outcome", "invalid_client_result".to_owned()),
            ("elapsed_ms", "1000".to_owned()),
            ("commit_state", "uncommitted".to_owned()),
            ("forward_status", "no".to_owned()),
        ],
    );
    assert!(
        opener.request_ids().is_empty(),
        "a result before commit must make zero opener calls"
    );

    send_external_ready_direct(&mut source, invalid_id);
    send_external_opened_directly(&mut source, invalid_id);
    send_external_opened_through_same_port(&mut source, invalid_id);
    send_external_preparation_failed(&mut source, invalid_id, 3);
    send_external_ready_direct(&mut other, invalid_id);
    send_external_opened_directly(&mut other, invalid_id);
    send_external_ready_direct(&mut source, unknown_id);
    send_external_opened_directly(&mut source, unknown_id);
    send_external_preparation_failed(&mut source, unknown_id, 3);
    set_test_monotonic_time(&clock_path, Duration::from_secs(10));
    assert!(ping_socket(&api_socket).contains("pong"));
    assert_no_external_server_message(&mut source, Duration::from_millis(250));
    assert_no_external_server_message(&mut other, Duration::from_millis(250));
    assert!(
        opener.request_ids().is_empty(),
        "late, mismatched, unknown, and deadline events cannot revive a closed request"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), invalid_id).len(),
        1,
        "invalid result must settle exactly once"
    );
    assert!(
        external_open_settlement_lines(&server_log_path(&config_home), unknown_id).is_empty(),
        "unknown IDs must never settle"
    );
    assert_no_server_opener_calls(&config_home);

    set_test_monotonic_time(&clock_path, Duration::from_secs(11));
    send_ctrl_click(&mut source, column, row);
    let (next_id, next_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("isolated next prepare");
    assert_eq!(next_url, url);
    assert_ne!(next_id, invalid_id);
    send_external_opened_directly(&mut other, next_id);
    set_test_monotonic_time(&clock_path, Duration::from_secs(12));
    send_external_ready_direct(&mut source, next_id);
    opener
        .invoke_after_next_commit(&mut source, next_id)
        .expect("isolated next request commits");
    send_external_opened_directly(&mut source, next_id);
    let opened_settlement = wait_for_external_open_settlement(
        &server_log_path(&config_home),
        next_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    assert_structured_diagnostic_fields(
        &opened_settlement,
        "external-open request settled",
        &[
            ("request_id", next_id.to_string()),
            ("lifecycle_phase", "terminal".to_owned()),
            ("outcome", "opened_directly".to_owned()),
            ("elapsed_ms", "1000".to_owned()),
            ("commit_state", "committed".to_owned()),
            ("forward_status", "no".to_owned()),
        ],
    );
    send_external_ready_direct(&mut source, invalid_id);
    send_external_opened_directly(&mut source, invalid_id);
    send_external_opened_directly(&mut source, next_id);
    thread::sleep(Duration::from_millis(100));

    assert_eq!(opener.request_ids(), &[next_id]);
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), invalid_id).len(),
        1,
        "closed request must remain terminal after unrelated success"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), next_id).len(),
        1,
        "isolated next request must settle exactly once"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(250));
    assert_no_server_opener_calls(&config_home);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_commit_writer_failure_is_unknown_without_opener_or_retry() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-commit-writer-failure");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-commit-writer-failure";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render clickable URL");
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);

    drain_server_messages(&mut source, Duration::from_millis(100));
    source
        .shutdown(Shutdown::Read)
        .expect("half-close source receive side");
    let opener = RecordingOpener::default();
    send_external_ready_direct(&mut source, request_id);

    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "committed_outcome_unknown",
        Duration::from_secs(3),
    );
    thread::sleep(Duration::from_millis(150));
    assert!(
        opener.request_ids().is_empty(),
        "a client that never receives commit must make zero opener calls"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "commit writer failure must settle exactly once"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(300));
    assert_no_server_opener_calls(&config_home);
    assert!(ping_socket(&api_socket).contains("pong"));

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_postcommit_connection_loss_is_unknown_without_retry() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-postcommit-loss");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-postcommit-loss";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render clickable URL");
    send_ctrl_click(&mut source, column, row);
    let (request_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("source prepare");
    assert_eq!(prepared_url, url);

    let mut opener = RecordingOpener::default();
    assert!(
        opener.request_ids().is_empty(),
        "prepare must not invoke the opener"
    );
    send_external_ready_direct(&mut source, request_id);
    opener
        .invoke_after_next_commit(&mut source, request_id)
        .expect("irrevocable source commit invokes opener");
    drop(source);

    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        request_id,
        "committed_outcome_unknown",
        Duration::from_secs(3),
    );
    thread::sleep(Duration::from_millis(150));
    assert_eq!(
        opener.request_ids(),
        &[request_id],
        "post-commit loss must not retry"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
        1,
        "post-commit connection loss must settle exactly once"
    );
    assert_no_external_server_message(&mut other, Duration::from_millis(300));
    assert_no_server_opener_calls(&config_home);
    assert!(ping_socket(&api_socket).contains("pong"));

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_committed_deadline_without_result_is_unknown_without_retry() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let clock_path = base.join("committed-monotonic-clock");
    set_test_monotonic_time(&clock_path, Duration::ZERO);
    let server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        Some(&clock_path),
        None,
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-committed-deadline");
    let mut source = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut source, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-committed-deadline";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut source, url, Duration::from_secs(8))
        .expect("source should render committed-deadline URL");
    let mut opener = RecordingOpener::default();

    send_ctrl_click(&mut source, column, row);
    let (committed_id, prepared_url) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("committed prepare");
    assert_eq!(prepared_url, url);
    assert!(
        opener.request_ids().is_empty(),
        "prepare cannot invoke opener"
    );
    set_test_monotonic_time(&clock_path, Duration::from_secs(1));
    send_external_ready_direct(&mut source, committed_id);
    opener
        .invoke_after_next_commit(&mut source, committed_id)
        .expect("commit authorizes opener");
    assert_eq!(opener.request_ids(), &[committed_id]);

    set_test_monotonic_time(&clock_path, Duration::from_secs(10));
    assert!(ping_socket(&api_socket).contains("pong"));
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        committed_id,
        "committed_outcome_unknown",
        Duration::from_secs(3),
    );
    assert_no_external_server_message(&mut source, Duration::from_millis(200));
    assert_no_external_server_message(&mut other, Duration::from_millis(150));
    assert_eq!(
        opener.request_ids(),
        &[committed_id],
        "committed result loss must not retry opener"
    );

    send_external_opened_directly(&mut source, committed_id);
    send_external_opened_directly(&mut source, committed_id);
    send_external_opened_through_same_port(&mut source, committed_id);
    send_external_ready_direct(&mut source, committed_id);
    send_external_preparation_failed(&mut source, committed_id, 3);
    send_external_opened_directly(&mut other, committed_id);

    send_ctrl_click(&mut source, column, row);
    let (next_id, _) =
        read_external_prepare(&mut source, Duration::from_secs(3)).expect("next prepare");
    let unknown_id = next_id + 10_000;
    send_external_ready_direct(&mut source, committed_id);
    send_external_opened_directly(&mut source, unknown_id);
    send_external_preparation_failed(&mut source, unknown_id, 3);
    send_external_ready_direct(&mut other, next_id);
    assert_no_external_server_message(&mut source, Duration::from_millis(150));
    assert_eq!(
        opener.request_ids(),
        &[committed_id],
        "noise before the next commit cannot invoke opener"
    );

    set_test_monotonic_time(&clock_path, Duration::from_secs(11));
    send_external_ready_direct(&mut source, next_id);
    opener
        .invoke_after_next_commit(&mut source, next_id)
        .expect("isolated next request commit");
    send_external_opened_directly(&mut source, next_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        next_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    send_external_opened_directly(&mut source, next_id);
    thread::sleep(Duration::from_millis(100));

    assert_eq!(opener.request_ids(), &[committed_id, next_id]);
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), committed_id).len(),
        1,
        "committed unknown must settle exactly once"
    );
    assert_eq!(
        external_open_settlement_lines(&server_log_path(&config_home), next_id).len(),
        1,
        "next request must settle exactly once"
    );
    assert!(
        external_open_settlement_lines(&server_log_path(&config_home), unknown_id).is_empty(),
        "unknown IDs must remain isolated"
    );
    assert_no_server_opener_calls(&config_home);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn disabled_external_open_policy_uses_server_fallback_without_client_prepare() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-disabled");
    let mut client = connect_full_app_client(&client_socket, 100, 30, false);
    assert!(wait_for_frame(&mut client, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-disabled";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut client, url, Duration::from_secs(8))
        .expect("disabled client should render clickable URL");
    send_ctrl_click(&mut client, column, row);

    assert_no_external_server_message(&mut client, Duration::from_millis(400));
    let opener_log = external_open_log_path(&config_home);
    assert!(
        wait_for_external_open_log(&opener_log, url, Duration::from_secs(3)),
        "server fallback opener should receive original URL; log={:?}",
        fs::read_to_string(&opener_log)
    );
    assert_eq!(
        fs::read_to_string(opener_log)
            .expect("opener log")
            .lines()
            .collect::<Vec<_>>(),
        vec![url]
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn external_open_deadline_orders_strict_before_equality_and_after_without_wall_waiting() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");
    let clock_path = base.join("monotonic-clock");
    set_test_monotonic_time(&clock_path, Duration::ZERO);
    let server = spawn_server_with_test_controls(
        &config_home,
        &runtime_dir,
        &api_socket,
        Some(&clock_path),
        None,
    );
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));
    let (_, link_pane, _) =
        create_workspace_and_root_terminal(&api_socket, "external-open-deadline-ordering");
    let mut client = connect_full_app_client(&client_socket, 100, 30, true);
    let mut other = connect_full_app_client(&client_socket, 100, 30, true);
    assert!(wait_for_frame(&mut client, Duration::from_secs(3)));
    assert!(wait_for_frame(&mut other, Duration::from_secs(3)));

    let url = "https://example.com/herdr-ticket-30-deadline-ordering";
    pane_send_input(&api_socket, &link_pane, &format!("echo {url}"));
    let (column, row) = wait_for_text_position(&mut client, url, Duration::from_secs(8))
        .expect("enabled client should render clickable URL");
    let mut opener = RecordingOpener::default();

    send_ctrl_click(&mut client, column, row);
    let (before_id, prepared_url) =
        read_external_prepare(&mut client, Duration::from_secs(3)).expect("before prepare");
    assert_eq!(prepared_url, url);
    set_test_monotonic_time(
        &clock_path,
        Duration::from_secs(10) - Duration::from_nanos(1),
    );
    assert!(
        opener.request_ids().is_empty(),
        "prepare cannot invoke opener"
    );
    send_external_ready_direct(&mut client, before_id);
    opener
        .invoke_after_next_commit(&mut client, before_id)
        .expect("strict-before readiness commits");
    send_external_opened_directly(&mut client, before_id);
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        before_id,
        "opened_directly",
        Duration::from_secs(3),
    );
    send_external_ready_direct(&mut client, before_id);
    send_external_opened_through_same_port(&mut client, before_id);
    send_external_ready_direct(&mut other, before_id);

    send_ctrl_click(&mut client, column, row);
    let (equality_id, _) =
        read_external_prepare(&mut client, Duration::from_secs(3)).expect("equality prepare");
    set_test_monotonic_time(
        &clock_path,
        Duration::from_secs(20) - Duration::from_nanos(1),
    );
    send_external_ready_direct(&mut client, equality_id);
    assert_eq!(
        read_external_request_id(&mut client, 13, Duration::from_secs(3))
            .expect("equality must cancel"),
        equality_id
    );
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        equality_id,
        "timed_out_before_commit",
        Duration::from_secs(3),
    );
    send_external_ready_direct(&mut client, equality_id);
    send_external_opened_directly(&mut client, equality_id);
    send_external_preparation_failed(&mut client, equality_id, 3);
    send_external_opened_directly(&mut other, equality_id);

    send_ctrl_click(&mut client, column, row);
    let (after_id, _) =
        read_external_prepare(&mut client, Duration::from_secs(3)).expect("after prepare");
    let unknown_id = after_id + 10_000;
    set_test_monotonic_time(&clock_path, Duration::from_secs(30));
    send_external_ready_direct(&mut client, after_id);
    assert_eq!(
        read_external_request_id(&mut client, 13, Duration::from_secs(3))
            .expect("after-deadline readiness must cancel"),
        after_id
    );
    wait_for_external_open_settlement(
        &server_log_path(&config_home),
        after_id,
        "timed_out_before_commit",
        Duration::from_secs(3),
    );
    send_external_ready_direct(&mut client, after_id);
    send_external_opened_directly(&mut client, after_id);
    send_external_preparation_failed(&mut client, unknown_id, 3);
    send_external_opened_directly(&mut other, unknown_id);
    assert_no_external_server_message(&mut client, Duration::from_millis(250));
    assert_no_external_server_message(&mut other, Duration::from_millis(250));

    assert_eq!(opener.request_ids(), &[before_id]);
    for request_id in [before_id, equality_id, after_id] {
        assert_eq!(
            external_open_settlement_lines(&server_log_path(&config_home), request_id).len(),
            1,
            "deadline-bound request {request_id} must settle exactly once"
        );
    }
    assert!(
        external_open_settlement_lines(&server_log_path(&config_home), unknown_id).is_empty(),
        "unknown IDs must remain isolated"
    );
    assert_no_server_opener_calls(&config_home);

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_allows_multiple_simultaneous_connections() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let mut client_a = connect_raw_client(&client_socket, 120, 40);
    let mut client_b = connect_raw_client(&client_socket, 100, 30);

    assert!(
        wait_for_frame(&mut client_a, Duration::from_secs(2)),
        "client A should receive frames"
    );
    assert!(
        wait_for_frame(&mut client_b, Duration::from_secs(2)),
        "client B should receive frames"
    );

    let ping = ping_socket(&api_socket);
    assert!(
        ping.contains("pong"),
        "server should remain responsive: {ping}"
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_effective_size_shrinks_when_smaller_client_joins() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let (_workspace_id, pane_id) = create_workspace_and_root_pane(&api_socket, "size-shrink");

    let mut large = connect_raw_client(&client_socket, 120, 40);
    assert!(wait_for_frame(&mut large, Duration::from_secs(2)));
    let large_only_size = read_pane_tty_size(&api_socket, &pane_id, Duration::from_secs(5));

    let mut small = connect_raw_client(&client_socket, 80, 24);
    assert!(wait_for_frame(&mut small, Duration::from_secs(2)));
    let with_small_size = read_pane_tty_size(&api_socket, &pane_id, Duration::from_secs(5));

    assert!(
        with_small_size.0 < large_only_size.0 && with_small_size.1 < large_only_size.1,
        "effective pane size should shrink when smaller client joins: before={:?}, after={:?}",
        large_only_size,
        with_small_size
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_broadcasts_frame_updates_to_all_clients() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let mut client_a = connect_raw_client(&client_socket, 100, 30);
    let mut client_b = connect_raw_client(&client_socket, 100, 30);

    // Ensure we have an active pane that can reflect input changes.
    let (_workspace_id, pane_id) =
        create_workspace_and_root_pane(&api_socket, "broadcast-client-a-to-b");

    // Drain initial frames so we measure the frame caused by new input.
    drain_server_messages(&mut client_a, Duration::from_millis(300));
    drain_server_messages(&mut client_b, Duration::from_millis(300));

    let marker = format!(
        "MB{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    send_client_input(&mut client_a, format!("echo {marker}\n").as_bytes());
    if !pane_read_recent_contains(&api_socket, &pane_id, &marker, Duration::from_secs(5)) {
        panic!(
            "pane output should include client A marker so broadcast reflects a real state change. pane output:\n{}\nserver log tail:\n{}",
            pane_read_recent(&api_socket, &pane_id, 200),
            log_tail(&server_log_path(&config_home), 80)
        );
    }
    let (received, client_b_frames) =
        wait_for_frame_matching_with_snapshots(&mut client_b, Duration::from_secs(10), |frame| {
            frame_contains_text(frame, &marker)
        })
        .expect("frame decoding should succeed");

    assert!(
        received,
        "client B should receive a broadcast frame containing client A marker. pane output:\n{}\nclient B frame snapshots:\n{}\nserver log tail:\n{}",
        pane_read_recent(&api_socket, &pane_id, 200),
        client_b_frames.join("\n--- frame ---\n"),
        log_tail(&server_log_path(&config_home), 80)
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_disconnect_recalculates_to_next_smallest() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let (_workspace_id, pane_id) =
        create_workspace_and_root_pane(&api_socket, "size-next-smallest");

    let mut c120 = connect_raw_client(&client_socket, 120, 40);
    let mut c100 = connect_raw_client(&client_socket, 100, 30);
    let mut c80 = connect_raw_client(&client_socket, 80, 24);

    assert!(wait_for_frame(&mut c120, Duration::from_secs(2)));
    assert!(wait_for_frame(&mut c100, Duration::from_secs(2)));
    assert!(wait_for_frame(&mut c80, Duration::from_secs(2)));

    let size_with_three = read_pane_tty_size(&api_socket, &pane_id, Duration::from_secs(5));

    drain_server_messages(&mut c100, Duration::from_millis(250));

    // Smallest client disconnects; effective size should increase to the next-smallest.
    send_client_detach(&mut c80);
    drop(c80);

    assert!(
        wait_for_frame(&mut c100, Duration::from_secs(2)),
        "next-smallest client should receive resized-up frame"
    );

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut size_after_smallest_disconnect = None;
    while Instant::now() < deadline {
        let maybe_size = try_read_pane_tty_size(&api_socket, &pane_id, Duration::from_millis(400));
        if let Some(size) = maybe_size {
            if size.0 > size_with_three.0 && size.1 > size_with_three.1 {
                size_after_smallest_disconnect = Some(size);
                break;
            }
        }
        thread::sleep(Duration::from_millis(60));
    }

    assert!(
        size_after_smallest_disconnect.is_some(),
        "effective pane size should increase after smallest disconnects: before={:?}, last_seen={:?}",
        size_with_three,
        try_read_pane_tty_size(&api_socket, &pane_id, Duration::from_millis(300))
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_smallest_leaving_resizes_up_for_remaining_clients() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let (_workspace_id, pane_id) = create_workspace_and_root_pane(&api_socket, "size-resize-up");

    let mut large = connect_raw_client(&client_socket, 120, 40);
    let mut small = connect_raw_client(&client_socket, 80, 24);

    assert!(wait_for_frame(&mut large, Duration::from_secs(2)));
    assert!(wait_for_frame(&mut small, Duration::from_secs(2)));

    let size_with_small_client = read_pane_tty_size(&api_socket, &pane_id, Duration::from_secs(5));

    drain_server_messages(&mut large, Duration::from_millis(250));

    send_client_detach(&mut small);
    drop(small);

    // Remaining client should receive a new (larger) frame.
    assert!(
        wait_for_frame(&mut large, Duration::from_secs(2)),
        "remaining client should receive resized-up frame"
    );

    let size_after_small_leaves = read_pane_tty_size(&api_socket, &pane_id, Duration::from_secs(5));

    assert!(
        size_after_small_leaves.0 > size_with_small_client.0
            && size_after_small_leaves.1 > size_with_small_client.1,
        "remaining clients should get larger effective pane size after smallest leaves: before={:?}, after={:?}",
        size_with_small_client,
        size_after_small_leaves
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_client_crash_sigkill_does_not_affect_server() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    let mut survivor = connect_raw_client(&client_socket, 100, 30);
    assert!(wait_for_frame(&mut survivor, Duration::from_secs(2)));

    let log_path = server_log_path(&config_home);
    let connected_before = count_log_occurrences(&log_path, "client connected");

    let crashing_client = spawn_client_process(&config_home, &runtime_dir, &api_socket);

    let attached_before_kill = wait_for_log_occurrence_count(
        &log_path,
        "client connected",
        connected_before + 1,
        Duration::from_secs(8),
    );
    assert!(
        attached_before_kill,
        "thin client must complete handshake/attachment before SIGKILL"
    );

    if let Some(pid) = crashing_client.child.process_id() {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGKILL);
        }
    }
    let mut crashing_client = crashing_client;
    wait_for_child_exit(&mut crashing_client.child);

    let ping = ping_socket(&api_socket);
    assert!(
        ping.contains("pong"),
        "server should stay healthy after SIGKILLed client: {ping}"
    );

    drain_server_messages(&mut survivor, Duration::from_millis(250));
    send_client_input(&mut survivor, b"echo survivor-still-works\n");
    assert!(
        wait_for_frame(&mut survivor, Duration::from_secs(2)),
        "remaining client should continue receiving frames"
    );

    cleanup_spawned_herdr(server, base);
}

#[test]
fn multi_client_rapid_connect_disconnect_stress_10_cycles() {
    let _lock = test_lock();
    let base = unique_test_dir();
    let config_home = base.join("config");
    let runtime_dir = base.join("runtime");
    let api_socket = runtime_dir.join("herdr.sock");
    let client_socket = runtime_dir.join("herdr-client.sock");

    let server = spawn_server(&config_home, &runtime_dir, &api_socket);
    wait_for_socket(&api_socket, Duration::from_secs(10));
    wait_for_file(&client_socket, Duration::from_secs(10));

    for i in 0..10u16 {
        let mut client = connect_raw_client(&client_socket, 80 + i, 24 + (i % 4));
        let _ = wait_for_frame(&mut client, Duration::from_millis(500));
        send_client_detach(&mut client);
        drop(client);
        thread::sleep(Duration::from_millis(40));
    }

    let ping = ping_socket(&api_socket);
    assert!(
        ping.contains("pong"),
        "server should remain healthy after rapid connect/disconnect: {ping}"
    );

    let mut final_client = connect_raw_client(&client_socket, 100, 30);
    assert!(
        wait_for_frame(&mut final_client, Duration::from_secs(2)),
        "new client should still connect and receive frames after stress"
    );

    cleanup_spawned_herdr(server, base);
}
