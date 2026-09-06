use std::fs;
use std::ffi::OsString;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Child, Stdio};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};

mod native_ssh;
mod remote_files;

use native_ssh::{classify_ssh_failure, run_process, ExecOutcome, NativeError, NativeErrorCode, OpenSshClients, SentinelParser, SshConfig};

struct SshSession {
    generation: u64,
    master: Box<dyn MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    timeout_cancel: mpsc::Sender<()>,
}

struct SshManager {
    session: Arc<Mutex<Option<SshSession>>>,
    next_generation: AtomicU64,
}

impl Default for SshManager {
    fn default() -> Self {
        Self { session: Arc::new(Mutex::new(None)), next_generation: AtomicU64::new(1) }
    }
}

#[derive(Default)]
struct LogStreamManager {
    child: Mutex<Option<Child>>,
}

#[derive(Default)]
struct MonitorStreamManager {
    child: Mutex<Option<Child>>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum SshPhase {
    Starting,
    Authenticated,
    Failed,
    Closed,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SshStartReceipt {
    generation: u64,
    phase: SshPhase,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SshLifecycleEvent {
    generation: u64,
    phase: SshPhase,
    error: Option<NativeError>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SshOutputEvent {
    generation: u64,
    data: String,
}

#[tauri::command]
fn start_ssh(
    app: AppHandle,
    state: State<'_, SshManager>,
    host: String,
    port: String,
    username: String,
    key_path: String,
    cols: u16,
    rows: u16,
) -> Result<SshStartReceipt, NativeError> {
    let config = SshConfig::parse(&host, &port, &username, &key_path)?;
    let clients = OpenSshClients::resolve()?;
    if cols > 400 || rows > 200 {
        return Err(NativeError::invalid_settings("Geçersiz terminal boyutu."));
    }
    if let Some(generation) = close_ssh_internal(&state.session, None)? {
        let _ = app.emit("ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Closed, error: None });
    }
    let generation = state.next_generation.fetch_add(1, Ordering::Relaxed);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: rows.max(10),
            cols: cols.max(40),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| NativeError { code: NativeErrorCode::LaunchFailed, message_tr: format!("PTY oluşturulamadı: {error}"), retryable: true })?;

    let sentinel = format!("__JARVIS_AUTH_{}_{}_{}__", std::process::id(), generation, unix_millis());
    let remote_command = format!("printf '%s\\n' {}; exec env TERM=xterm-256color \"${{SHELL:-/bin/sh}}\" -l", shell_single_quote(&sentinel));
    let mut command = CommandBuilder::new(clients.ssh.as_os_str());
    command.env("TERM", "xterm-256color");
    command.arg("-tt");
    for argument in config.common_args(false) {
        command.arg(argument);
    }
    command.arg(remote_command);

    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|error| NativeError { code: NativeErrorCode::LaunchFailed, message_tr: format!("SSH başlatılamadı: {error}"), retryable: true })?;

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("SSH çıktı okuyucusu oluşturulamadı: {error}"), retryable: true })?;

    let writer = pair
        .master
        .take_writer()
        .map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("SSH giriş yazıcısı oluşturulamadı: {error}"), retryable: true })?;

    let writer = Arc::new(Mutex::new(writer));
    let child = Arc::new(Mutex::new(child));
    let (timeout_cancel, timeout_receiver) = mpsc::channel();

    {
        let mut guard = state
            .session
            .lock()
            .map_err(|_| NativeError { code: NativeErrorCode::IoFailed, message_tr: "SSH oturum kilidi kullanılamadı.".into(), retryable: true })?;
        *guard = Some(SshSession {
            generation,
            master: pair.master,
            writer: Arc::clone(&writer),
            child: Arc::clone(&child),
            timeout_cancel: timeout_cancel.clone(),
        });
    }

    let reader_sessions = Arc::clone(&state.session);
    let reader_app = app.clone();
    let reader_cancel = timeout_cancel;
    let sentinel_bytes = sentinel.into_bytes();
    thread::spawn(move || {
        let mut parser = SentinelParser::new(sentinel_bytes);
        let mut pre_auth_output = Vec::new();
        let mut authenticated = false;
        let mut read_error = None;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    if !authenticated { pre_auth_output.extend_from_slice(&buffer[..size]); }
                    let parsed = parser.push(&buffer[..size]);
                    if parsed.authenticated {
                        authenticated = true;
                        let _ = reader_cancel.send(());
                        emit_if_current(&reader_app, &reader_sessions, generation, "ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Authenticated, error: None });
                    }
                    if !parsed.output.is_empty() {
                        emit_if_current(&reader_app, &reader_sessions, generation, "ssh-output", SshOutputEvent { generation, data: String::from_utf8_lossy(&parsed.output).into_owned() });
                    }
                }
                Err(error) => {
                    read_error = Some(error.to_string());
                    break;
                }
            }
        }
        let removed = take_current_session(&reader_sessions, generation);
        if removed.is_some() {
            if authenticated {
                let _ = reader_app.emit("ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Closed, error: None });
            } else {
                let mut diagnostic = String::from_utf8_lossy(&pre_auth_output).into_owned();
                if let Some(error) = read_error { diagnostic.push_str(&error); }
                let error = classify_ssh_failure(&diagnostic, false);
                let _ = reader_app.emit("ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Failed, error: Some(error) });
            }
        }
    });

    let timeout_sessions = Arc::clone(&state.session);
    thread::spawn(move || {
        if timeout_receiver.recv_timeout(Duration::from_secs(15)).is_err() {
            if let Some(session) = take_current_session(&timeout_sessions, generation) {
                if let Ok(mut child) = session.child.lock() { let _ = child.kill(); }
                let error = classify_ssh_failure("", true);
                let _ = app.emit("ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Failed, error: Some(error) });
            }
        }
    });

    Ok(SshStartReceipt { generation, phase: SshPhase::Starting })
}

#[tauri::command]
fn write_ssh(state: State<'_, SshManager>, generation: u64, data: String) -> Result<(), NativeError> {
    let guard = state
        .session
        .lock()
        .map_err(|_| NativeError { code: NativeErrorCode::IoFailed, message_tr: "SSH oturum kilidi kullanılamadı.".into(), retryable: true })?;
    let session = guard
        .as_ref()
        .filter(|session| session.generation == generation)
        .ok_or_else(|| NativeError::invalid_settings("SSH oturumu artık etkin değil."))?;

    let mut writer = session
        .writer
        .lock()
        .map_err(|_| NativeError { code: NativeErrorCode::IoFailed, message_tr: "SSH yazıcı kilidi kullanılamadı.".into(), retryable: true })?;
    writer
        .write_all(data.as_bytes())
        .map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("SSH girişi yazılamadı: {error}"), retryable: true })?;
    writer
        .flush()
        .map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("SSH girişi gönderilemedi: {error}"), retryable: true })?;
    Ok(())
}

#[tauri::command]
fn resize_ssh(state: State<'_, SshManager>, generation: u64, cols: u16, rows: u16) -> Result<(), NativeError> {
    if cols > 400 || rows > 200 {
        return Err(NativeError::invalid_settings("Geçersiz terminal boyutu."));
    }
    let guard = state
        .session
        .lock()
        .map_err(|_| NativeError { code: NativeErrorCode::IoFailed, message_tr: "SSH oturum kilidi kullanılamadı.".into(), retryable: true })?;
    let session = guard
        .as_ref()
        .filter(|session| session.generation == generation)
        .ok_or_else(|| NativeError::invalid_settings("SSH oturumu artık etkin değil."))?;

    session
        .master
        .resize(PtySize {
            rows: rows.max(10),
            cols: cols.max(40),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("Terminal boyutu değiştirilemedi: {error}"), retryable: true })
}

#[tauri::command]
fn close_ssh(app: AppHandle, state: State<'_, SshManager>, generation: u64) -> Result<SshStartReceipt, NativeError> {
    close_ssh_internal(&state.session, Some(generation))?;
    let receipt = SshStartReceipt { generation, phase: SshPhase::Closed };
    let _ = app.emit("ssh-lifecycle", SshLifecycleEvent { generation, phase: SshPhase::Closed, error: None });
    Ok(receipt)
}

fn close_ssh_internal(sessions: &Arc<Mutex<Option<SshSession>>>, expected_generation: Option<u64>) -> Result<Option<u64>, NativeError> {
    let mut guard = sessions.lock().map_err(|_| NativeError { code: NativeErrorCode::IoFailed, message_tr: "SSH oturum kilidi kullanılamadı.".into(), retryable: true })?;
    if let (Some(expected), Some(active)) = (expected_generation, guard.as_ref()) {
        if active.generation != expected {
            return Err(NativeError::invalid_settings("Eski SSH oturumu yeni bağlantıyı kapatamaz."));
        }
    }
    let session = guard.take();
    drop(guard);
    if let Some(session) = session {
        let _ = session.timeout_cancel.send(());
        if let Ok(mut child) = session.child.lock() { let _ = child.kill(); }
        return Ok(Some(session.generation));
    }
    Ok(None)
}

fn take_current_session(sessions: &Arc<Mutex<Option<SshSession>>>, generation: u64) -> Option<SshSession> {
    let Ok(mut guard) = sessions.lock() else { return None; };
    if guard.as_ref().map(|session| session.generation) == Some(generation) { guard.take() } else { None }
}

fn emit_if_current<S: Serialize + Clone>(app: &AppHandle, sessions: &Arc<Mutex<Option<SshSession>>>, generation: u64, event: &str, payload: S) {
    let current = sessions.lock().ok().and_then(|guard| guard.as_ref().map(|session| session.generation));
    if current == Some(generation) { let _ = app.emit(event, payload); }
}

fn unix_millis() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) { Ok(duration) => duration.as_millis(), Err(_) => 0 }
}


fn parse_mac_address(value: &str) -> Result<[u8; 6], String> {
    let normalized = value.trim().replace('-', ":").to_ascii_lowercase();
    let parts: Vec<&str> = normalized.split(':').collect();
    if parts.len() != 6 || parts.iter().any(|p| p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit())) {
        return Err("Geçersiz MAC adresi. Örnek: 9C:A2:F4:E1:FD:46".into());
    }
    let mut mac = [0u8; 6];
    for (index, part) in parts.iter().enumerate() {
        mac[index] = u8::from_str_radix(part, 16).map_err(|_| "Geçersiz MAC adresi.".to_string())?;
    }
    if mac == [0; 6] || mac == [0xff; 6] {
        return Err("Yayın MAC adresi geçersiz.".into());
    }
    Ok(mac)
}

#[tauri::command]
fn wake_on_lan(mac: String, broadcast: String, port: u16, repeats: u8) -> Result<String, String> {
    let mac_bytes = parse_mac_address(&mac)?;
    if port == 0 {
        return Err("Wake-on-LAN portu 0 olamaz.".into());
    }
    let addr: SocketAddr = format!("{}:{}", broadcast.trim(), port)
        .parse()
        .map_err(|_| "Geçersiz yayın adresi veya Wake-on-LAN portu.".to_string())?;
    if !addr.ip().is_ipv4() {
        return Err("Wake-on-LAN için IPv4 yayın adresi kullanılmalı.".into());
    }

    let mut packet = [0u8; 102];
    packet[0..6].fill(0xff);
    for chunk in packet[6..].chunks_exact_mut(6) {
        chunk.copy_from_slice(&mac_bytes);
    }

    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP soketi açılamadı: {e}"))?;
    socket.set_broadcast(true).map_err(|e| format!("Broadcast izni ayarlanamadı: {e}"))?;
    let count = repeats.clamp(1, 5);
    for _ in 0..count {
        socket.send_to(&packet, addr).map_err(|e| format!("Wake-on-LAN paketi gönderilemedi: {e}"))?;
    }
    Ok(format!("Wake-on-LAN paketi {count} kez gönderildi: {mac}"))
}

#[tauri::command]
fn probe_server(host: String, port: String, timeout_ms: u64) -> Result<bool, String> {
    validate_host(&host)?;
    let port_num = validate_port(&port)?;
    let timeout = std::time::Duration::from_millis(timeout_ms.clamp(250, 5000));
    let addr_text = if host.contains(':') && !host.starts_with('[') { format!("[{host}]:{port_num}") } else { format!("{host}:{port_num}") };
    let addr: SocketAddr = addr_text.parse().map_err(|_| "Sunucu adresi çözümlenemedi.".to_string())?;
    Ok(TcpStream::connect_timeout(&addr, timeout).is_ok())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RemoteFileEntry {
    name: String,
    path: String,
    kind: String,
    size: u64,
    modified: String,
}

fn validate_host(host: &str) -> Result<(), String> {
    let value = host.trim();
    if value.is_empty() || value.len() > 253 {
        return Err("Geçersiz sunucu adresi.".into());
    }
    if value.chars().any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))) {
        return Err("Sunucu adresi beklenmeyen karakter içeriyor.".into());
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<u16, String> {
    let parsed = port.trim().parse::<u16>().map_err(|_| "Geçersiz port.".to_string())?;
    if parsed == 0 {
        return Err("Port 0 olamaz.".into());
    }
    Ok(parsed)
}

fn validate_key_path(key_path: &str) -> Result<(), String> {
    let path = Path::new(key_path.trim());
    if key_path.trim().is_empty() {
        return Err("SSH özel anahtar yolu boş olamaz.".into());
    }
    if !path.is_file() {
        return Err("SSH özel anahtar dosyası bulunamadı.".into());
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), String> {
    if username.is_empty() || username.len() > 64 {
        return Err("Geçersiz kullanıcı adı.".into());
    }
    if !username.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')) {
        return Err("Kullanıcı adı beklenmeyen karakter içeriyor.".into());
    }
    Ok(())
}

fn remote_root(username: &str) -> Result<String, String> {
    validate_username(username)?;
    Ok(format!("/home/{username}"))
}

fn normalize_remote_path(username: &str, requested: &str) -> Result<String, String> {
    let root = remote_root(username)?;
    let trimmed = requested.trim();
    let path = if trimmed.is_empty() { root.clone() } else if trimmed.starts_with('/') { trimmed.to_string() } else { format!("{root}/{trimmed}") };
    let normalized = path.replace("//", "/");
    let mut parts: Vec<&str> = Vec::new();
    for part in normalized.split('/') {
        if part.is_empty() || part == "." { continue; }
        if part == ".." {
            if parts.is_empty() { return Err("Path çalışma alanının dışına çıkıyor.".into()); }
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    let result = format!("/{}", parts.join("/"));
    if result != root && !result.starts_with(&(root.clone() + "/")) {
        return Err("Sadece kullanıcı çalışma alanına erişebilirsin.".into());
    }
    Ok(result)
}

fn shell_single_quote(value: &str) -> String {
    remote_files::shell_single_quote(value)
}

#[tauri::command]
fn remote_exec(host: String, port: String, username: String, key_path: String, remote_command: String, timeout_ms: u64) -> Result<ExecOutcome, NativeError> {
    let config = SshConfig::parse(&host, &port, &username, &key_path)?;
    run_ssh_exec_outcome(&config, &remote_command, Duration::from_millis(timeout_ms.clamp(1_000, 180_000)))
}

fn run_ssh_exec_outcome(config: &SshConfig, remote_command: &str, timeout: Duration) -> Result<ExecOutcome, NativeError> {
    let clients = OpenSshClients::resolve()?;
    let mut args = config.common_args(true);
    args.push(OsString::from(remote_command));
    run_process(&clients.ssh, &args, timeout)
}

fn run_ssh_exec(host: &str, port: &str, username: &str, key_path: &str, remote_command: &str) -> Result<(String, String), String> {
    let config = SshConfig::parse(host, port, username, key_path).map_err(|error| error.message())?;
    let outcome = run_ssh_exec_outcome(&config, remote_command, Duration::from_secs(60)).map_err(|error| error.message())?;
    if outcome.exit_code != 0 {
        if (40..=49).contains(&outcome.exit_code) {
            return Err(remote_file_error(outcome.exit_code));
        }
        return Err(classify_ssh_failure(&outcome.stderr, outcome.timed_out).message());
    }
    Ok((outcome.stdout, outcome.stderr))
}

fn run_scp(config: &SshConfig, operands: &[OsString]) -> Result<(), String> {
    let clients = OpenSshClients::resolve().map_err(|error| error.message())?;
    let mut args = config.scp_args();
    args.extend_from_slice(operands);
    let outcome = run_process(&clients.scp, &args, Duration::from_secs(120)).map_err(|error| error.message())?;
    if outcome.exit_code != 0 {
        return Err(classify_ssh_failure(&outcome.stderr, outcome.timed_out).message());
    }
    Ok(())
}

fn remote_file_error(exit_code: i32) -> String {
    match exit_code {
        40 | 41 => "Uzak kullanıcı kökü güvenli biçimde doğrulanamadı.".into(),
        42 | 43 => "Uzak dosya veya üst dizini bulunamadı.".into(),
        44 => "Sembolik bağlantı kullanıcı çalışma alanının dışına çıkıyor.".into(),
        45 => "Uzak hedef beklenen dosya veya dizin türünde değil.".into(),
        47 => "Dosya, editörün 2 MB okuma sınırını aşıyor.".into(),
        _ => "Uzak dosya güvenlik denetimi başarısız oldu.".into(),
    }
}

fn temp_file(name_hint: &str) -> PathBuf {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
    let safe = name_hint.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect::<String>();
    std::env::temp_dir().join(format!("jarvis-{stamp}-{safe}"))
}

#[tauri::command]
fn file_list(host: String, port: String, username: String, key_path: String, path: String) -> Result<Vec<RemoteFileEntry>, String> {
    let cmd = remote_files::guarded_list_command(&username, &path)?;
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, &cmd)?;
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let mut it = line.splitn(4, '\t');
        let kind = match it.next() { Some("d") => "directory", Some("l") => "symlink", Some(_) => "file", None => continue };
        let full_path = match it.next() { Some(v) => v.to_string(), None => continue };
        let size = it.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let modified = it.next().and_then(|v| v.parse::<f64>().ok()).map(|v| v.round().to_string()).unwrap_or_else(|| "".into());
        let name = full_path.rsplit('/').next().unwrap_or(&full_path).to_string();
        entries.push(RemoteFileEntry { name, path: full_path, kind: kind.into(), size, modified });
    }
    Ok(entries)
}

#[tauri::command]
fn file_read(host: String, port: String, username: String, key_path: String, path: String) -> Result<String, String> {
    let cmd = remote_files::guarded_read_command(&username, &path)?;
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, &cmd)?;
    Ok(stdout)
}

#[tauri::command]
fn file_write(host: String, port: String, username: String, key_path: String, path: String, content: String) -> Result<(), String> {
    if content.len() > 2_500_000 { return Err("Editör için dosya boyutu 2.5 MB sınırını aşıyor.".into()); }
    let config = SshConfig::parse(&host, &port, &username, &key_path).map_err(|error| error.message())?;
    let target = remote_files::normalize_remote_path(&username, &path)?;
    let staging = remote_stage_path(&username, "write")?;
    let root_check = remote_files::guarded_root_command(&username)?;
    run_ssh_exec(&host, &port, &username, &key_path, &root_check)?;
    let temp = temp_file("edit.txt");
    fs::write(&temp, content.as_bytes()).map_err(|e| format!("Geçici dosya yazılamadı: {e}"))?;
    let remote = format!("{}:{}", config.target(), staging);
    let result = run_scp(&config, &[temp.as_os_str().to_owned(), OsString::from(remote)])
        .and_then(|()| remote_files::guarded_replace_command(&username, &target, &staging))
        .and_then(|command| run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ()));
    let _ = fs::remove_file(&temp);
    let _ = cleanup_remote_stage(&host, &port, &username, &key_path, &staging);
    result
}

#[tauri::command]
fn file_mkdir(host: String, port: String, username: String, key_path: String, path: String, name: String) -> Result<(), String> {
    let command = remote_files::guarded_mkdir_command(&username, &path, &name)?;
    run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ())
}

#[tauri::command]
fn file_touch(host: String, port: String, username: String, key_path: String, path: String, name: String) -> Result<(), String> {
    let command = remote_files::guarded_touch_command(&username, &path, &name)?;
    run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ())
}

#[tauri::command]
fn file_rename(host: String, port: String, username: String, key_path: String, old_path: String, new_name: String) -> Result<(), String> {
    let command = remote_files::guarded_rename_command(&username, &old_path, &new_name)?;
    run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ())
}

#[tauri::command]
fn file_delete(host: String, port: String, username: String, key_path: String, path: String, is_directory: bool) -> Result<(), String> {
    let command = remote_files::guarded_delete_command(&username, &path, is_directory)?;
    run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ())
}

#[tauri::command]
fn file_upload(host: String, port: String, username: String, key_path: String, local_path: String, remote_dir: String) -> Result<(), String> {
    let local = Path::new(&local_path);
    if !local.exists() || !local.is_file() { return Err("Yerel dosya bulunamadı.".into()); }
    let file_name = local.file_name().and_then(|name| name.to_str()).ok_or_else(|| "Yerel dosya adı UTF-8 olarak okunamadı.".to_string())?;
    let target = remote_files::upload_target(&username, &remote_dir, file_name)?;
    let staging = remote_stage_path(&username, "upload")?;
    let config = SshConfig::parse(&host, &port, &username, &key_path).map_err(|error| error.message())?;
    let root_check = remote_files::guarded_root_command(&username)?;
    run_ssh_exec(&host, &port, &username, &key_path, &root_check)?;
    let remote = format!("{}:{}", config.target(), staging);
    let result = run_scp(&config, &[local.as_os_str().to_owned(), OsString::from(remote)])
        .and_then(|()| remote_files::guarded_replace_command(&username, &target, &staging))
        .and_then(|command| run_ssh_exec(&host, &port, &username, &key_path, &command).map(|_| ()));
    let _ = cleanup_remote_stage(&host, &port, &username, &key_path, &staging);
    result
}

#[tauri::command]
fn file_download(host: String, port: String, username: String, key_path: String, remote_path: String, local_path: String) -> Result<(), String> {
    let config = SshConfig::parse(&host, &port, &username, &key_path).map_err(|error| error.message())?;
    let staging = remote_stage_path(&username, "download")?;
    let stage_command = remote_files::guarded_stage_download_command(&username, &remote_path, &staging)?;
    run_ssh_exec(&host, &port, &username, &key_path, &stage_command)?;
    let remote = format!("{}:{}", config.target(), staging);
    let result = run_scp(&config, &[OsString::from(remote), OsString::from(local_path)]);
    let _ = cleanup_remote_stage(&host, &port, &username, &key_path, &staging);
    result
}

fn remote_stage_path(username: &str, operation: &str) -> Result<String, String> {
    let root = remote_files::remote_root(username)?;
    Ok(format!("{root}/.jarvis-{operation}-{}-{}", std::process::id(), unix_millis()))
}

fn cleanup_remote_stage(host: &str, port: &str, username: &str, key_path: &str, staging: &str) -> Result<(), String> {
    let command = remote_files::guarded_delete_command(username, staging, false)?;
    run_ssh_exec(host, port, username, key_path, &command).map(|_| ())
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdatePackage {
    name: String,
    current: String,
    candidate: String,
    architecture: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UpdateInfo {
    available: usize,
    security: usize,
    reboot_required: bool,
    reboot_packages: Vec<String>,
    last_apt_list_refresh: String,
    packages: Vec<UpdatePackage>,
    history: String,
}

fn parse_upgradable_packages(stdout: &str) -> Vec<UpdatePackage> {
    let mut packages = Vec::new();
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with("Listing...") || line.starts_with("WARNING:") { continue; }
        let before = line.split(" [upgradable from:").next().unwrap_or(line).trim();
        let current = line.split("[upgradable from:").nth(1)
            .and_then(|v| v.split(']').next())
            .unwrap_or("—")
            .trim();
        let first = before.split_whitespace().collect::<Vec<_>>();
        if first.len() < 2 { continue; }
        let ident = first[0];
        let candidate = first[1];
        let (name, source_part) = ident.split_once('/').unwrap_or((ident, ""));
        let architecture = first.get(2).copied().unwrap_or("").trim_matches('[').trim_matches(']').to_string();
        let architecture = if architecture == "upgradable" || architecture == "" { "unknown".to_string() } else { architecture };
        packages.push(UpdatePackage {
            name: name.to_string(),
            current: current.to_string(),
            candidate: candidate.to_string(),
            architecture,
        });
        let _ = source_part;
        if packages.len() >= 200 { break; }
    }
    packages
}

fn update_snapshot_command() -> &'static str {
    "printf '__JARVIS_UPGRADABLE__\\n'; apt list --upgradable 2>/dev/null; printf '__JARVIS_REBOOT__\\n'; if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi; if [ -f /var/run/reboot-required.pkgs ]; then cat /var/run/reboot-required.pkgs; fi; printf '__JARVIS_LIST_MTIME__\\n'; ts=$(find /var/lib/apt/lists -type f -printf '%T@\\n' 2>/dev/null | sort -nr | head -1); if [ -n \"$ts\" ]; then date -d \"@$ts\" '+%Y-%m-%d %H:%M:%S'; else echo unknown; fi"
}

#[tauri::command]
fn update_inspect(host: String, port: String, username: String, key_path: String) -> Result<UpdateInfo, String> {
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, update_snapshot_command())?;
    let mut sections = std::collections::HashMap::<String, Vec<String>>::new();
    let mut current = String::new();
    for line in stdout.lines() {
        if line.starts_with("__JARVIS_") && line.ends_with("__") {
            current = line.trim_matches('_').to_string();
            sections.entry(current.clone()).or_default();
        } else if !current.is_empty() {
            sections.entry(current.clone()).or_default().push(line.to_string());
        }
    }

    let raw = sections.get("JARVIS_UPGRADABLE").cloned().unwrap_or_default().join("\n");
    let packages = parse_upgradable_packages(&raw);
    let security = packages.iter().filter(|p| raw.lines().any(|line| line.starts_with(&format!("{}/", p.name)) && line.contains("-security"))).count();
    let reboot_lines = sections.get("JARVIS_REBOOT").cloned().unwrap_or_default();
    let reboot_required = reboot_lines.iter().any(|v| v.trim() == "yes");
    let reboot_packages = reboot_lines.iter().skip_while(|v| v.trim() != "yes").skip(1).filter(|v| !v.trim().is_empty()).take(50).cloned().collect::<Vec<_>>();
    let last_apt_list_refresh = sections.get("JARVIS_LIST_MTIME").and_then(|v| v.iter().find(|x| !x.trim().is_empty())).cloned().unwrap_or_else(|| "unknown".to_string());
    let history = read_update_history(&host, &port, &username, &key_path).unwrap_or_default();

    Ok(UpdateInfo {
        available: packages.len(), security, reboot_required, reboot_packages,
        last_apt_list_refresh, packages, history,
    })
}

fn read_update_history(host: &str, port: &str, username: &str, key_path: &str) -> Result<String, String> {
    let command = "{ [ -f /var/log/apt/history.log ] && echo '=== APT HISTORY ===' && tail -n 100 /var/log/apt/history.log; } 2>/dev/null; { echo; echo '=== DPKG RECENT ==='; zgrep -hE ' (upgrade|install|remove) ' /var/log/dpkg.log* 2>/dev/null | tail -n 100; }";
    let (stdout, _) = run_ssh_exec(host, port, username, key_path, command)?;
    Ok(stdout.trim().to_string())
}

#[tauri::command]
fn update_history(host: String, port: String, username: String, key_path: String) -> Result<String, String> {
    read_update_history(&host, &port, &username, &key_path)
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ServiceInfo {
    name: String,
    unit: String,
    description: String,
    active: String,
    sub_state: String,
    enabled: String,
    main_pid: u32,
    memory: String,
    cpu: String,
}

fn allowed_service(service: &str) -> Option<(&'static str, &'static str)> {
    match service {
        "ssh" => Some(("ssh.service", "OpenSSH Secure Shell server")),
        "docker" => Some(("docker.service", "Docker Application Container Engine")),
        "nginx" => Some(("nginx.service", "Nginx web server and reverse proxy")),
        "mariadb" => Some(("mariadb.service", "MariaDB database server")),
        "php8.5-fpm" => Some(("php8.5-fpm.service", "PHP 8.5 FastCGI Process Manager")),
        "armanc-node-api" => Some(("armanc-node-api.service", "Armanc Server Node.js Test API")),
        "armanc-python-api" => Some(("armanc-python-api.service", "Armanc Server Python FastAPI")),
        "jarvis-host-telemetry" => Some(("jarvis-host-telemetry.service", "J.A.R.V.I.S. Host Telemetry")),
        _ => None,
    }
}

fn service_display_name(service: &str) -> &'static str {
    match service {
        "ssh" => "SSH",
        "docker" => "Docker",
        "nginx" => "Nginx",
        "mariadb" => "MariaDB",
        "php8.5-fpm" => "PHP 8.5 FPM",
        "armanc-node-api" => "Armanc Node API",
        "armanc-python-api" => "Armanc Python API",
        "jarvis-host-telemetry" => "J.A.R.V.I.S Host Telemetry",
        _ => "Service",
    }
}

#[tauri::command]
fn service_list(host: String, port: String, username: String, key_path: String) -> Result<Vec<ServiceInfo>, String> {
    let services = [
        "ssh", "docker", "nginx", "mariadb", "php8.5-fpm",
        "armanc-node-api", "armanc-python-api", "jarvis-host-telemetry",
    ];
    let units = services.iter().filter_map(|s| allowed_service(s).map(|(unit, _)| (*s, unit))).collect::<Vec<_>>();
    let quoted = units.iter().map(|(_, unit)| shell_single_quote(unit)).collect::<Vec<_>>().join(" ");
    let cmd = format!(
        "for u in {quoted}; do printf 'UNIT=%s\\n' \"$u\"; systemctl show \"$u\" --no-page --property=Description,ActiveState,SubState,UnitFileState,MainPID,MemoryCurrent,CPUUsageNSec --value | paste -sd '\\t' -; done"
    );
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, &cmd)?;
    let mut out = Vec::new();
    let mut lines = stdout.lines();
    while let Some(unit_line) = lines.next() {
        if !unit_line.starts_with("UNIT=") { continue; }
        let unit = unit_line.trim_start_matches("UNIT=").trim();
        let values = lines.next().unwrap_or("").split('\t').collect::<Vec<_>>();
        let service_key = units.iter().find(|(_, u)| *u == unit).map(|(k, _)| *k).unwrap_or(unit.trim_end_matches(".service"));
        out.push(ServiceInfo {
            name: service_display_name(service_key).to_string(),
            unit: unit.to_string(),
            description: allowed_service(service_key).map(|(_, d)| d).unwrap_or("systemd service").to_string(),
            active: values.get(1).copied().unwrap_or("unknown").to_string(),
            sub_state: values.get(2).copied().unwrap_or("unknown").to_string(),
            enabled: values.get(3).copied().unwrap_or("unknown").to_string(),
            main_pid: values.get(4).and_then(|v| v.parse::<u32>().ok()).unwrap_or(0),
            memory: {
                let bytes = values.get(5).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                if bytes >= 1024 * 1024 { format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0) }
                else if bytes >= 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
                else { format!("{} B", bytes) }
            },
            cpu: {
                let ns = values.get(6).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
                if ns == 0 { "0 ms".to_string() } else { format!("{:.2} s", ns as f64 / 1_000_000_000.0) }
            },
        });
    }
    Ok(out)
}

#[tauri::command]
fn service_action(host: String, port: String, username: String, key_path: String, service: String, action: String) -> Result<String, String> {
    let (unit, _) = allowed_service(&service).ok_or_else(|| "Bu servis yönetim için izinli değil.".to_string())?;
    let action = match action.as_str() {
        "start" | "stop" | "restart" | "enable" | "disable" | "reload" => action,
        _ => return Err("Geçersiz servis işlemi.".into()),
    };
    let command = format!("sudo -n systemctl {} {}", action, shell_single_quote(unit));
    let (stdout, stderr) = run_ssh_exec(&host, &port, &username, &key_path, &command)?;
    Ok(if stdout.trim().is_empty() { stderr } else { stdout })
}

fn log_service_keys(service: &str) -> Result<Vec<&'static str>, String> {
    match service {
        "all" => Ok(vec![
            "ssh", "docker", "nginx", "mariadb", "php8.5-fpm",
            "armanc-node-api", "armanc-python-api", "jarvis-host-telemetry",
        ]),
        "ssh" => Ok(vec!["ssh"]),
        "docker" => Ok(vec!["docker"]),
        "nginx" => Ok(vec!["nginx"]),
        "mariadb" => Ok(vec!["mariadb"]),
        "php8.5-fpm" => Ok(vec!["php8.5-fpm"]),
        "armanc-node-api" => Ok(vec!["armanc-node-api"]),
        "armanc-python-api" => Ok(vec!["armanc-python-api"]),
        "jarvis-host-telemetry" => Ok(vec!["jarvis-host-telemetry"]),
        _ => Err("Bu servis logları için izinli değil.".into()),
    }
}

#[tauri::command]
fn logs_query(
    host: String,
    port: String,
    username: String,
    key_path: String,
    service: String,
    lines: u32,
    since_hours: u32,
) -> Result<String, String> {
    let count = lines.clamp(20, 300);
    let services = log_service_keys(&service)?;
    let units = services.iter()
        .filter_map(|key| allowed_service(key).map(|(unit, _)| shell_single_quote(unit)))
        .collect::<Vec<_>>();
    let unit_args = units.iter().map(|u| format!("-u {}", u)).collect::<Vec<_>>().join(" ");
    let time_args = match since_hours {
        0 => String::new(),
        1 => "--since '1 hour ago'".to_string(),
        6 => "--since '6 hours ago'".to_string(),
        24 => "--since '24 hours ago'".to_string(),
        168 => "--since '7 days ago'".to_string(),
        _ => return Err("Geçersiz zaman filtresi.".into()),
    };
    let command = format!(
        "journalctl {} {} -n {} -o short-iso --no-pager --no-hostname",
        unit_args, time_args, count
    );
    let (stdout, stderr) = run_ssh_exec(&host, &port, &username, &key_path, &command)?;
    Ok(if stdout.trim().is_empty() { stderr } else { stdout })
}

#[tauri::command]
fn stop_log_stream(state: State<'_, LogStreamManager>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|_| "Log stream lock hatası".to_string())?;
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

#[tauri::command]
fn start_log_stream(
    app: AppHandle,
    state: State<'_, LogStreamManager>,
    host: String,
    port: String,
    username: String,
    key_path: String,
    service: String,
    lines: u32,
) -> Result<(), String> {
    validate_username(&username)?;

    // Stop any previous stream before starting a new persistent journalctl session.
    {
        let mut guard = state.child.lock().map_err(|_| "Log stream lock hatası".to_string())?;
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    let services = log_service_keys(&service)?;
    let units = services
        .iter()
        .filter_map(|key| allowed_service(key).map(|(unit, _)| shell_single_quote(unit)))
        .collect::<Vec<_>>();
    let unit_args = units.iter().map(|u| format!("-u {}", u)).collect::<Vec<_>>().join(" ");
    let count = lines.clamp(20, 300);
    let remote_command = format!(
        "exec journalctl {} -n {} -f -o short-iso --no-pager --no-hostname",
        unit_args, count
    );

    let target = format!("{username}@{host}");
    let mut child = ProcessCommand::new("ssh.exe")
        .args([
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-p", &port,
            "-i", &key_path,
            &target,
            &remote_command,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("Log SSH oturumu başlatılamadı: {e}"))?;

    let stdout = child.stdout.take().ok_or_else(|| "Log stdout alınamadı.".to_string())?;
    let stderr = child.stderr.take().ok_or_else(|| "Log stderr alınamadı.".to_string())?;

    {
        let mut guard = state.child.lock().map_err(|_| "Log stream lock hatası".to_string())?;
        *guard = Some(child);
    }

    let app_stdout = app.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let _ = app_stdout.emit("logs-output", line);
                }
                Err(error) => {
                    let _ = app_stdout.emit("logs-error", format!("Log stream read error: {error}"));
                    break;
                }
            }
        }
        let _ = app_stdout.emit("logs-stream-closed", ());
    });

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut collected = String::new();
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if !line.trim().is_empty() {
                        if !collected.is_empty() { collected.push('\n'); }
                        collected.push_str(&line);
                    }
                }
                Err(_) => break,
            }
        }
        if !collected.is_empty() {
            let _ = app.emit("logs-error", collected);
        }
    });

    Ok(())
}

#[tauri::command]
fn service_logs(host: String, port: String, username: String, key_path: String, service: String, lines: u32, follow: bool) -> Result<String, String> {
    let (unit, _) = allowed_service(&service).ok_or_else(|| "Bu servis logları için izinli değil.".to_string())?;
    let count = lines.clamp(10, 300);
    let command = if follow {
        format!("journalctl -u {} -n {} --no-pager", shell_single_quote(unit), count)
    } else {
        format!("journalctl -u {} -n {} --no-pager", shell_single_quote(unit), count)
    };
    let (stdout, stderr) = run_ssh_exec(&host, &port, &username, &key_path, &command)?;
    Ok(if stdout.trim().is_empty() { stderr } else { stdout })
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MonitorTopProcess {
    pid: u32,
    command: String,
    cpu_percent: f64,
    memory_percent: f64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct MonitorSnapshot {
    cpu_percent: f64,
    memory_percent: f64,
    memory_used_bytes: u64,
    memory_total_bytes: u64,
    swap_percent: f64,
    swap_used_bytes: u64,
    swap_total_bytes: u64,
    disk_percent: f64,
    disk_used_bytes: u64,
    disk_total_bytes: u64,
    disk_free_bytes: u64,
    load1: f64,
    load5: f64,
    load15: f64,
    uptime_seconds: u64,
    uptime: String,
    temperature: Option<f64>,
    network_interface: String,
    rx_bytes: u64,
    tx_bytes: u64,
    process_count: u32,
    top_process: Option<MonitorTopProcess>,
}

fn monitor_stream_script(interval_seconds: u32) -> String {
    let interval = interval_seconds.clamp(2, 30);
    format!(r#"LC_ALL=C
while true; do
read -r _ u n sy i iw irq si st _ < /proc/stat
TOTAL1=$((u+n+sy+i+iw+irq+si+st)); IDLE1=$((i+iw)); sleep 0.35
read -r _ u n sy i iw irq si st _ < /proc/stat
TOTAL2=$((u+n+sy+i+iw+irq+si+st)); IDLE2=$((i+iw)); DT=$((TOTAL2-TOTAL1)); DI=$((IDLE2-IDLE1))
CPU=$(awk -v dt="$DT" -v di="$DI" 'BEGIN {{ if (dt <= 0) print 0; else printf "%.2f", 100*(dt-di)/dt }}')
MEM=$(free -b | awk '/^Mem:/ {{used=$2-$7; printf "%d %d %.2f", used, $2, (used/$2)*100}}')
SWAP=$(free -b | awk '/^Swap:/ {{used=$3; total=$2; pct=(total>0 ? used/total*100 : 0); printf "%d %d %.2f", used,total,pct}}')
DISK=$(df -B1 -P / | awk 'NR==2 {{gsub(/%/,"",$5); printf "%d %d %d %d", $3,$2,$4,$5}}')
LOAD=$(awk '{{print $1,$2,$3}}' /proc/loadavg)
UPTIME=$(awk '{{printf "%d", $1}}' /proc/uptime)
UPTIME_PRETTY=$(uptime -p)
TEMP=$(for f in /sys/class/thermal/thermal_zone*/temp; do [ -r "$f" ] && awk '{{printf "%.1f\n",$1/1000}}' "$f"; done | sort -nr | head -n1)
IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {{print $5}}')
NET=$(awk -v d="$IFACE" '$1 ~ "^" d ":" {{print $2,$10}}' /proc/net/dev)
PROC_COUNT=$(ps -e --no-headers 2>/dev/null | wc -l)
TOP=$(ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu 2>/dev/null | head -n1)
printf "__JCPU__%s\n" "$CPU"
printf "__JMEM__%s\n" "$MEM"
printf "__JSWAP__%s\n" "$SWAP"
printf "__JDISK__%s\n" "$DISK"
printf "__JLOAD__%s\n" "$LOAD"
printf "__JUPTIME__%s\n" "$UPTIME"
printf "__JUPTIMEPRETTY__%s\n" "$UPTIME_PRETTY"
printf "__JTEMP__%s\n" "${{TEMP:-0}}"
printf "__JIFACE__%s\n" "$IFACE"
printf "__JNET__%s\n" "$NET"
printf "__JPROC__%s\n" "$PROC_COUNT"
printf "__JTOP__%s\n" "$TOP"
printf "__JMON_END__\n"
sleep {interval}
done"#)
}

#[tauri::command]
fn start_monitor_stream(
    app: AppHandle,
    state: State<'_, MonitorStreamManager>,
    host: String,
    port: String,
    username: String,
    key_path: String,
    interval_seconds: u32,
) -> Result<(), String> {
    validate_username(&username)?;
    {
        let mut guard = state.child.lock().map_err(|_| "Monitor stream lock hatası".to_string())?;
        if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    let target = format!("{username}@{host}");
    let remote_command = monitor_stream_script(interval_seconds);
    let mut child = ProcessCommand::new("ssh.exe")
        .args([
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=2",
            "-p", &port,
            "-i", &key_path,
            &target,
            &remote_command,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("Monitor SSH oturumu başlatılamadı: {e}"))?;

    let stdout = child.stdout.take().ok_or_else(|| "Monitor stdout alınamadı.".to_string())?;
    let stderr = child.stderr.take().ok_or_else(|| "Monitor stderr alınamadı.".to_string())?;
    {
        let mut guard = state.child.lock().map_err(|_| "Monitor stream lock hatası".to_string())?;
        *guard = Some(child);
    }

    let app_stdout = app.clone();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(line) => { let _ = app_stdout.emit("monitor-output", line); }
                Err(error) => { let _ = app_stdout.emit("monitor-error", format!("Monitor stream read error: {error}")); break; }
            }
        }
        let _ = app_stdout.emit("monitor-stream-closed", ());
    });

    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut collected = String::new();
        for line in reader.lines() {
            match line {
                Ok(line) if !line.trim().is_empty() => {
                    if !collected.is_empty() { collected.push('\n'); }
                    collected.push_str(&line);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        if !collected.is_empty() {
            let _ = app.emit("monitor-error", collected);
        }
    });

    Ok(())
}

#[tauri::command]
fn stop_monitor_stream(state: State<'_, MonitorStreamManager>) -> Result<(), String> {
    let mut guard = state.child.lock().map_err(|_| "Monitor stream lock hatası".to_string())?;
    if let Some(mut child) = guard.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Ok(())
}

#[tauri::command]
fn monitor_snapshot(host: String, port: String, username: String, key_path: String) -> Result<MonitorSnapshot, String> {
    let cmd = r#"LC_ALL=C
read -r _ u n sy i iw irq si st _ < /proc/stat
TOTAL1=$((u+n+sy+i+iw+irq+si+st)); IDLE1=$((i+iw)); sleep 0.35
read -r _ u n sy i iw irq si st _ < /proc/stat
TOTAL2=$((u+n+sy+i+iw+irq+si+st)); IDLE2=$((i+iw)); DT=$((TOTAL2-TOTAL1)); DI=$((IDLE2-IDLE1))
CPU=$(awk -v dt="$DT" -v di="$DI" 'BEGIN { if (dt <= 0) print 0; else printf "%.2f", 100*(dt-di)/dt }')
MEM=$(free -b | awk '/^Mem:/ {used=$2-$7; printf "%d %d %.2f", used, $2, (used/$2)*100}')
SWAP=$(free -b | awk '/^Swap:/ {used=$3; total=$2; pct=(total>0 ? used/total*100 : 0); printf "%d %d %.2f", used,total,pct}')
DISK=$(df -B1 -P / | awk 'NR==2 {gsub(/%/,"",$5); printf "%d %d %d %d", $3,$2,$4,$5}')
LOAD=$(awk '{print $1,$2,$3}' /proc/loadavg)
UPTIME=$(awk '{printf "%d", $1}' /proc/uptime)
UPTIME_PRETTY=$(uptime -p)
TEMP=$(for f in /sys/class/thermal/thermal_zone*/temp; do [ -r "$f" ] && awk '{printf "%.1f\n",$1/1000}' "$f"; done | sort -nr | head -n1)
IFACE=$(ip route show default 2>/dev/null | awk 'NR==1 {print $5}')
NET=$(awk -v d="$IFACE" '$1 ~ "^" d ":" {print $2,$10}' /proc/net/dev)
PROC_COUNT=$(ps -e --no-headers 2>/dev/null | wc -l)
TOP=$(ps -eo pid=,comm=,%cpu=,%mem= --sort=-%cpu 2>/dev/null | head -n1)
printf "__JCPU__%s\n" "$CPU"
printf "__JMEM__%s\n" "$MEM"
printf "__JSWAP__%s\n" "$SWAP"
printf "__JDISK__%s\n" "$DISK"
printf "__JLOAD__%s\n" "$LOAD"
printf "__JUPTIME__%s\n" "$UPTIME"
printf "__JUPTIMEPRETTY__%s\n" "$UPTIME_PRETTY"
printf "__JTEMP__%s\n" "${TEMP:-0}"
printf "__JIFACE__%s\n" "$IFACE"
printf "__JNET__%s\n" "$NET"
printf "__JPROC__%s\n" "$PROC_COUNT"
printf "__JTOP__%s\n" "$TOP""#;
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, cmd)?;
    let mut values = std::collections::HashMap::<String, String>::new();
    for line in stdout.lines() {
        if let Some((k,v)) = line.split_once("__") { let _ = (k,v); }
        if let Some(idx) = line.find("__") { if let Some(end) = line[idx+2..].find("__") { let key = &line[idx..idx+end+4]; let val = &line[idx+end+4..]; values.insert(key.to_string(), val.trim().to_string()); } }
    }
    let nums = |key: &str| -> Vec<f64> { values.get(key).map(|v| v.split_whitespace().filter_map(|x| x.parse::<f64>().ok()).collect()).unwrap_or_default() };
    let mem=nums("__JMEM__"); let swap=nums("__JSWAP__"); let disk=nums("__JDISK__"); let load=nums("__JLOAD__"); let net=nums("__JNET__");
    let top=values.get("__JTOP__").and_then(|v| { let p=v.split_whitespace().collect::<Vec<_>>(); if p.len()>=4 { Some(MonitorTopProcess{ pid:p[0].parse().ok()?, command:p[1].to_string(), cpu_percent:p[2].parse().unwrap_or(0.0), memory_percent:p[3].parse().unwrap_or(0.0) }) } else { None } });
    Ok(MonitorSnapshot {
        cpu_percent: values.get("__JCPU__").and_then(|v| v.parse().ok()).unwrap_or(0.0),
        memory_percent: *mem.get(2).unwrap_or(&0.0), memory_used_bytes: *mem.get(0).unwrap_or(&0.0) as u64, memory_total_bytes: *mem.get(1).unwrap_or(&0.0) as u64,
        swap_percent: *swap.get(2).unwrap_or(&0.0), swap_used_bytes: *swap.get(0).unwrap_or(&0.0) as u64, swap_total_bytes: *swap.get(1).unwrap_or(&0.0) as u64,
        disk_used_bytes: *disk.get(0).unwrap_or(&0.0) as u64, disk_total_bytes: *disk.get(1).unwrap_or(&0.0) as u64, disk_free_bytes: *disk.get(2).unwrap_or(&0.0) as u64, disk_percent: *disk.get(3).unwrap_or(&0.0),
        load1: *load.get(0).unwrap_or(&0.0), load5: *load.get(1).unwrap_or(&0.0), load15: *load.get(2).unwrap_or(&0.0),
        uptime_seconds: values.get("__JUPTIME__").and_then(|v| v.parse().ok()).unwrap_or(0), uptime: values.get("__JUPTIMEPRETTY__").cloned().unwrap_or_else(|| "unknown".into()),
        temperature: values.get("__JTEMP__").and_then(|v| v.parse::<f64>().ok()).filter(|v| *v > 0.0),
        network_interface: values.get("__JIFACE__").cloned().unwrap_or_default(), rx_bytes: *net.get(0).unwrap_or(&0.0) as u64, tx_bytes: *net.get(1).unwrap_or(&0.0) as u64,
        process_count: values.get("__JPROC__").and_then(|v| v.parse().ok()).unwrap_or(0), top_process: top,
    })
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RemotePort { proto: String, address: String, port: u16, process: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RemoteInterface { name: String, state: String, ipv4: String, ipv6: String }

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct RemoteAccessSnapshot {
    ssh_port: u16, auth_method: String, ufw_active: Option<bool>, ufw_output: String, ufw_rule_count: usize,
    fail2ban_active: Option<bool>, fail2ban_output: String, fail2ban_jail_count: usize, fail2ban_banned: usize,
    ports: Vec<RemotePort>, interfaces: Vec<RemoteInterface>, auth_log: String,
}

#[tauri::command]
fn remote_access_snapshot(host: String, port: String, username: String, key_path: String) -> Result<RemoteAccessSnapshot, String> {
    let command = r#"LC_ALL=C
SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port / {print $2; exit}')
[ -n "$SSH_PORT" ] || SSH_PORT=$(ss -lnt 2>/dev/null | awk '$4 ~ /:22$/ {print 22; exit}')

# UFW status can be determined without sudo. Rule listing may still require sudo.
UFW_ENABLED=$(awk -F= '/^ENABLED=/{print $2; exit}' /etc/ufw/ufw.conf 2>/dev/null || true)
UFW_RULES=$(sudo -n ufw status numbered 2>&1 || true)
UFW_RULE_COUNT=$(printf '%s\n' "$UFW_RULES" | sed -n 's/^\[[[:space:]]*[0-9][0-9]*\][[:space:]]*//p' | wc -l | tr -d ' ')
if printf '%s' "$UFW_RULES" | grep -q '^Status: active'; then
  UFW_STATE="ACTIVE"
  UFW=$(printf 'Status: active\n%s' "$UFW_RULES")
elif printf '%s' "$UFW_RULES" | grep -q '^Status: inactive'; then
  UFW_STATE="INACTIVE"
  UFW=$(printf 'Status: inactive\n%s' "$UFW_RULES")
elif [ "$UFW_ENABLED" = "yes" ]; then
  UFW_STATE="ACTIVE"
  UFW=$(printf 'Status: active\nDetailed rules require passwordless sudo. Configuration: ENABLED=yes')
  UFW_RULE_COUNT=0
elif [ "$UFW_ENABLED" = "no" ]; then
  UFW_STATE="INACTIVE"
  UFW=$(printf 'Status: inactive\nConfiguration: ENABLED=no')
  UFW_RULE_COUNT=0
else
  UFW_STATE="UNKNOWN"
  UFW="UFW status unavailable."
  UFW_RULE_COUNT=0
fi

# Fail2Ban service state is readable without sudo. Jail details may require sudo.
F2B_ACTIVE=$(systemctl is-active fail2ban.service 2>/dev/null || true)
F2B_ENABLED=$(systemctl is-enabled fail2ban.service 2>/dev/null || true)
F2B_RULES=$(sudo -n fail2ban-client status 2>&1 || true)
F2B_JAIL_COUNT=$(printf '%s\n' "$F2B_RULES" | sed -n 's/^Number of jail:[[:space:]]*//p' | head -1 | tr -cd '0-9')
F2B_BANNED=$(printf '%s\n' "$F2B_RULES" | sed -n 's/^Number of currently banned:[[:space:]]*//p' | head -1 | tr -cd '0-9')
[ -n "$F2B_JAIL_COUNT" ] || F2B_JAIL_COUNT=0
[ -n "$F2B_BANNED" ] || F2B_BANNED=0
if [ "$F2B_ACTIVE" = "active" ]; then
  F2B_STATE="ACTIVE"
  if [ -n "$F2B_RULES" ] && ! printf '%s' "$F2B_RULES" | grep -Eqi 'sudo:|password.*required|permission denied'; then
    F2B=$(printf 'Service: active\nEnabled: %s\n%s' "$F2B_ENABLED" "$F2B_RULES")
  else
    F2B=$(printf 'Service: active\nEnabled: %s\nJail details require passwordless sudo.' "$F2B_ENABLED")
  fi
elif [ "$F2B_ACTIVE" = "inactive" ] || [ "$F2B_ACTIVE" = "failed" ]; then
  F2B_STATE="INACTIVE"
  F2B=$(printf 'Service: %s\nEnabled: %s' "$F2B_ACTIVE" "$F2B_ENABLED")
elif [ "$F2B_ACTIVE" = "unknown" ] || [ "$F2B_ACTIVE" = "" ]; then
  F2B_STATE="UNKNOWN"
  F2B="Fail2Ban service state unavailable."
else
  F2B_STATE="UNKNOWN"
  F2B=$(printf 'Service: %s\nEnabled: %s' "$F2B_ACTIVE" "$F2B_ENABLED")
fi

PORTS=$(sudo -n ss -H -lntup 2>/dev/null || ss -H -lntup 2>/dev/null || true)
IFSACES=$(ip -j address show 2>/dev/null || true)
AUTH=$(journalctl -u ssh -n 20 --no-pager -o short-iso 2>/dev/null || true)
printf '__JRSSH__%s\n' "${SSH_PORT:-22}"
printf '__JRUFWSTATE__%s\n' "$UFW_STATE"
printf '__JRUFWCOUNT__%s\n' "$UFW_RULE_COUNT"
printf '__JRUFW__\n%s\n__ENDUFW__\n' "$UFW"
printf '__JRF2BSTATE__%s\n' "$F2B_STATE"
printf '__JRF2BJAILS__%s\n' "$F2B_JAIL_COUNT"
printf '__JRF2BBANNED__%s\n' "$F2B_BANNED"
printf '__JRF2B__\n%s\n__ENDJRF2B__\n' "$F2B"
printf '__JRPORTS__\n%s\n__ENDPORTS__\n' "$PORTS"
printf '__JRIFACESJSON__\n%s\n__ENDIFACESJSON__\n' "$IFSACES"
printf '__JRAUTH__\n%s\n__ENDAUTH__\n' "$AUTH""#;
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, command)?;
    let mut ssh_port = 22u16;
    let mut ufw_output = String::new();
    let mut ufw_rule_count = 0usize;
    let mut fail2ban_output = String::new();
    let mut fail2ban_jail_count = 0usize;
    let mut fail2ban_banned = 0usize;
    let mut ufw_state = String::from("UNKNOWN");
    let mut fail2ban_state = String::from("UNKNOWN");
    let mut ports = Vec::new();
    let mut interfaces: std::collections::HashMap<String, RemoteInterface> = std::collections::HashMap::new();
    let mut auth_log = String::new();
    let lines: Vec<&str> = stdout.lines().collect();
    let mut section = "";
    let mut iface_json = String::new();

    for line in &lines {
        if let Some(v) = line.strip_prefix("__JRSSH__") { ssh_port = v.trim().parse().unwrap_or(22); section=""; continue; }
        if let Some(v) = line.strip_prefix("__JRUFWSTATE__") { ufw_state = v.trim().to_string(); continue; }
        if let Some(v) = line.strip_prefix("__JRUFWCOUNT__") { ufw_rule_count = v.trim().parse().unwrap_or(0); continue; }
        if *line == "__JRUFW__" { section="ufw"; continue; }
        if *line == "__ENDUFW__" { section=""; continue; }
        if let Some(v) = line.strip_prefix("__JRF2BSTATE__") { fail2ban_state = v.trim().to_string(); continue; }
        if let Some(v) = line.strip_prefix("__JRF2BJAILS__") { fail2ban_jail_count = v.trim().parse().unwrap_or(0); continue; }
        if let Some(v) = line.strip_prefix("__JRF2BBANNED__") { fail2ban_banned = v.trim().parse().unwrap_or(0); continue; }
        if *line == "__JRF2B__" { section="f2b"; continue; }
        if *line == "__ENDJRF2B__" { section=""; continue; }
        if *line == "__JRPORTS__" { section="ports"; continue; }
        if *line == "__ENDPORTS__" { section=""; continue; }
        if *line == "__JRIFACESJSON__" { section="ifacesjson"; continue; }
        if *line == "__ENDIFACESJSON__" { section=""; continue; }
        if *line == "__JRAUTH__" { section="auth"; continue; }
        if *line == "__ENDAUTH__" { section=""; continue; }

        match section {
            "ports" => {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 6 {
                    let proto = parts[0].to_string();
                    let local = parts[4].to_string();
                    let (mut address, portnum) = local.rsplit_once(':')
                        .map(|(a,p)| (a.trim_matches('[').trim_matches(']').to_string(), p.parse().unwrap_or(0)))
                        .unwrap_or((local, 0));
                    if let Some((base,_scope)) = address.rsplit_once('%') { address = base.to_string(); }
                    let proc = if parts.len() > 6 { parts[6..].join(" ") } else { String::new() };
                    ports.push(RemotePort{ proto, address, port: portnum, process: proc });
                }
            }
            "ifacesjson" => {
                if !iface_json.is_empty() { iface_json.push('\n'); }
                iface_json.push_str(line);
            }
            "ufw" => { if !ufw_output.is_empty() { ufw_output.push('\n'); } ufw_output.push_str(line); }
            "f2b" => { if !fail2ban_output.is_empty() { fail2ban_output.push('\n'); } fail2ban_output.push_str(line); }
            "auth" => { auth_log.push_str(line); auth_log.push('\n'); }
            _ => {}
        }
    }

    if let Ok(values) = serde_json::from_str::<serde_json::Value>(iface_json.trim()) {
        if let Some(items) = values.as_array() {
            for item in items {
                let name = item.get("ifname").and_then(|v| v.as_str()).unwrap_or("").to_string();
                if name.is_empty() { continue; }
                let state = item.get("operstate").and_then(|v| v.as_str())
                    .or_else(|| item.get("state").and_then(|v| v.as_str()))
                    .unwrap_or("UNKNOWN").to_uppercase();
                let entry = interfaces.entry(name.clone()).or_insert(RemoteInterface{name: name.clone(), state: state.clone(), ipv4:String::new(), ipv6:String::new()});
                entry.state = state;
                if let Some(addr_info) = item.get("addr_info").and_then(|v| v.as_array()) {
                    for addr in addr_info {
                        let family = addr.get("family").and_then(|v| v.as_str()).unwrap_or("");
                        let local = addr.get("local").and_then(|v| v.as_str()).unwrap_or("").to_string();
                        match family {
                            "inet" if entry.ipv4.is_empty() => entry.ipv4 = local,
                            "inet6" if entry.ipv6.is_empty() => entry.ipv6 = local,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    let ufw_active = match ufw_state.as_str() { "ACTIVE" => Some(true), "INACTIVE" => Some(false), _ => None };
    let fail2ban_active = match fail2ban_state.as_str() { "ACTIVE" => Some(true), "INACTIVE" => Some(false), _ => None };
    Ok(RemoteAccessSnapshot{ ssh_port, auth_method:"publickey".into(), ufw_active, ufw_output, ufw_rule_count, fail2ban_active, fail2ban_output, fail2ban_jail_count, fail2ban_banned, ports, interfaces:interfaces.into_values().collect(), auth_log })
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityFinding {
    severity: String,
    title: String,
    detail: String,
    recommendation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityCheck {
    key: String,
    label: String,
    state: String,
    value: String,
    detail: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityListener {
    protocol: String,
    address: String,
    port: u16,
    process: String,
    pid: Option<u32>,
    scope: String,
    service: String,
    status: String,
    firewall: String,
    exposure: String,
    unit: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityAudit {
    score: u8,
    grade: String,
    ssh_port: u16,
    password_authentication: Option<bool>,
    pubkey_authentication: Option<bool>,
    permit_root_login: String,
    max_auth_tries: Option<u32>,
    x11_forwarding: Option<bool>,
    ufw_active: Option<bool>,
    fail2ban_active: Option<bool>,
    external_listening_ports: usize,
    exposed_listener_ports: usize,
    protected_listener_ports: usize,
    review_listener_ports: usize,
    listeners: Vec<SecurityListener>,
    findings: Vec<SecurityFinding>,
    checks: Vec<SecurityCheck>,
    generated_at: String,
}

#[tauri::command]
fn security_audit(host: String, port: String, username: String, key_path: String) -> Result<SecurityAudit, String> {
    let command = r#"LC_ALL=C
SSHD_BIN=$(command -v sshd || true)
[ -n "$SSHD_BIN" ] || SSHD_BIN=/usr/sbin/sshd
HELPER=/usr/local/sbin/jarvis-remediation

# Read the daemon's effective configuration through the restricted, root-owned
# J.A.R.V.I.S helper first. A direct unprivileged sshd -T call can fail on
# installations where host-key/config reads require root, which previously
# caused the audit to fall back to misleading defaults such as password_auth=yes.
SSHD_CFG=$(sudo -n "$HELPER" --effective-config 2>/dev/null || true)
if [ -z "$SSHD_CFG" ]; then
  SSHD_CFG=$(sudo -n "$SSHD_BIN" -T 2>/dev/null || true)
fi
if [ -z "$SSHD_CFG" ]; then
  SSHD_CFG=$("$SSHD_BIN" -T 2>/dev/null || true)
fi

# Best-effort fallback only when the effective-config query is unavailable.
if [ -z "$SSHD_CFG" ]; then
  SSHD_CFG=$(grep -hE '^[[:space:]]*(port|passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|x11forwarding)[[:space:]]+' \
    /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)
fi

cfg_value() {
  key="$1"
  printf '%s\n' "$SSHD_CFG" | awk -v k="$key" 'tolower($1)==tolower(k) {print $2; exit}'
}

SSH_PORT=$(cfg_value port)
PWA=$(cfg_value passwordauthentication)
PUB=$(cfg_value pubkeyauthentication)
ROOT=$(cfg_value permitrootlogin)
MAX=$(cfg_value maxauthtries)
X11=$(cfg_value x11forwarding)

    # Preserve unknown values when the effective configuration cannot be read.
    # An audit must never claim that a default is an observed server setting.
    [ -n "$SSH_PORT" ] || SSH_PORT=22

UFW_ENABLED=$(awk -F= '/^ENABLED=/{print $2; exit}' /etc/ufw/ufw.conf 2>/dev/null || true)
UFW_STATUS=$(ufw status 2>&1 || true)
if printf '%s\n' "$UFW_STATUS" | grep -q '^Status: active'; then UFW_STATE=ACTIVE
elif printf '%s\n' "$UFW_STATUS" | grep -q '^Status: inactive'; then UFW_STATE=INACTIVE
elif [ "$UFW_ENABLED" = "yes" ]; then UFW_STATE=ACTIVE
elif [ "$UFW_ENABLED" = "no" ]; then UFW_STATE=INACTIVE
else UFW_STATE=UNKNOWN
fi

F2B_ACTIVE=$(systemctl is-active fail2ban.service 2>/dev/null || true)
if [ "$F2B_ACTIVE" = "active" ]; then F2B_STATE=ACTIVE
elif [ "$F2B_ACTIVE" = "inactive" ] || [ "$F2B_ACTIVE" = "failed" ]; then F2B_STATE=INACTIVE
else F2B_STATE=UNKNOWN
fi

# Read listener inventory with process ownership where available. This is read-only.
LISTEN=$(sudo -n "$HELPER" --network-intel 2>/dev/null || true)
if [ -z "$LISTEN" ]; then
  LISTEN=$(sudo -n "$HELPER" --listeners 2>/dev/null || ss -H -lntup 2>/dev/null || true)
fi
printf '__JARVIS_NETWORK_RAW__\n%s\n__END_JARVIS_NETWORK_RAW__\n' "$LISTEN"

if [ -n "$SSHD_CFG" ]; then SSHD_CFG_SOURCE=effective-or-file; else SSHD_CFG_SOURCE=defaults; fi
printf '__JSAUDIT__\n'
printf 'ssh_port=%s\n' "${SSH_PORT:-22}"
printf 'password_auth=%s\n' "${PWA:-unknown}"
printf 'pubkey_auth=%s\n' "${PUB:-unknown}"
printf 'permit_root=%s\n' "${ROOT:-unknown}"
printf 'max_auth_tries=%s\n' "${MAX:-unknown}"
printf 'x11_forwarding=%s\n' "${X11:-unknown}"
printf 'ssh_config_source=%s\n' "${SSHD_CFG_SOURCE:-best-effort}"
printf 'ufw=%s\n' "$UFW_STATE"
printf 'fail2ban=%s\n' "$F2B_STATE"
printf '__ENDJSAUDIT__\n'"#;
    let (stdout, _) = run_ssh_exec(&host, &port, &username, &key_path, command)?;
    let mut ssh_port = 22u16;
    let mut password_auth = None;
    let mut pubkey_auth = None;
    let mut permit_root = String::from("unknown");
    let mut max_auth_tries: Option<u32> = None;
    let mut x11_forwarding = None;
    let mut ufw_active = None;
    let mut fail2ban_active = None;
    let mut external_listening_ports = 0usize;
    let mut listeners = Vec::new();
    let mut exposed_listener_ports = 0usize;
    let mut protected_listener_ports = 0usize;
    let mut review_listener_ports = 0usize;
    let mut network_mode = false;
    for line in stdout.lines() {
        if line == "__JARVIS_NETWORK_RAW__" { network_mode = true; continue; }
        if line == "__END_JARVIS_NETWORK_RAW__" { network_mode = false; continue; }
        if let Some(v) = line.strip_prefix("ssh_port=") { ssh_port = v.trim().parse().unwrap_or(22); }
        else if let Some(v) = line.strip_prefix("password_auth=") { password_auth = match v.trim() { "yes" => Some(true), "no" => Some(false), _ => None }; }
        else if let Some(v) = line.strip_prefix("pubkey_auth=") { pubkey_auth = match v.trim() { "yes" => Some(true), "no" => Some(false), _ => None }; }
        else if let Some(v) = line.strip_prefix("permit_root=") { permit_root = v.trim().to_string(); }
        else if let Some(v) = line.strip_prefix("max_auth_tries=") { max_auth_tries = v.trim().parse().ok(); }
        else if let Some(v) = line.strip_prefix("x11_forwarding=") { x11_forwarding = match v.trim() { "yes" => Some(true), "no" => Some(false), _ => None }; }
        else if let Some(v) = line.strip_prefix("ufw=") { ufw_active = match v.trim() { "ACTIVE" => Some(true), "INACTIVE" => Some(false), _ => None }; }
        else if let Some(v) = line.strip_prefix("fail2ban=") { fail2ban_active = match v.trim() { "ACTIVE" => Some(true), "INACTIVE" => Some(false), _ => None }; }
        else if let Some(v) = line.strip_prefix("external=") { external_listening_ports = v.trim().parse().unwrap_or(0); }
        else if network_mode {
            if let Some(v) = line.strip_prefix("listener=") {
                let parts: Vec<&str> = v.split('\t').collect();
                if parts.len() >= 10 {
                    let protocol = parts[0].to_string();
                    let address = parts[1].to_string();
                    let port = parts[2].parse::<u16>().unwrap_or(0);
                    let process = parts[3].to_string();
                    let pid = if parts[4] == "-" { None } else { parts[4].parse::<u32>().ok() };
                    let scope = parts[5].to_string();
                    let service = parts[6].to_string();
                    let firewall = parts[7].replace('_', " ");
                    let exposure = parts[8].to_string();
                    let unit_raw = parts[9].to_string();
                    let unit = if unit_raw == "-" || unit_raw.is_empty() { None } else { Some(unit_raw) };
                    let status = match parts[8] {
                        "LOCAL" => "SAFE",
                        "PROTECTED" => "PROTECTED",
                        "EXPOSED" => "EXPOSED",
                        _ => "REVIEW",
                    }.to_string();
                    match parts[8] {
                        "EXPOSED" => exposed_listener_ports += 1,
                        "PROTECTED" => protected_listener_ports += 1,
                        "REVIEW" => review_listener_ports += 1,
                        _ => {}
                    }
                    listeners.push(SecurityListener{ protocol, address, port, process, pid, scope, service, status, firewall, exposure, unit });
                }
            }
        }
    }
    if external_listening_ports == 0 { external_listening_ports = listeners.iter().filter(|l| l.scope != "LOCAL ONLY").count(); }
    let mut score: i32 = 100;
    let mut findings = Vec::new();
    let mut checks = Vec::new();
    let push_check = |checks: &mut Vec<SecurityCheck>, key: &str, label: &str, state: &str, value: String, detail: &str| {
        checks.push(SecurityCheck{ key:key.into(), label:label.into(), state:state.into(), value, detail:detail.into() });
    };

    match password_auth {
        Some(false) => push_check(&mut checks, "password_auth", "Password authentication", "PASS", "disabled".into(), "Password-based SSH authentication is disabled."),
        Some(true) => { score -= 25; push_check(&mut checks, "password_auth", "Password authentication", "FAIL", "enabled".into(), "Password authentication increases SSH attack surface."); findings.push(SecurityFinding{severity:"HIGH".into(), title:"SSH password authentication is enabled".into(), detail:"The daemon accepts password authentication in addition to key-based access.".into(), recommendation:"Disable PasswordAuthentication after confirming key-based login works.".into()}); },
        None => push_check(&mut checks, "password_auth", "Password authentication", "UNKNOWN", "unknown".into(), "The effective SSH daemon configuration could not be read."),
    }
    match pubkey_auth {
        Some(true) => push_check(&mut checks, "pubkey_auth", "Public-key authentication", "PASS", "enabled".into(), "Public-key authentication is enabled."),
        Some(false) => { score -= 20; push_check(&mut checks, "pubkey_auth", "Public-key authentication", "FAIL", "disabled".into(), "Key-based SSH authentication is disabled."); findings.push(SecurityFinding{severity:"HIGH".into(), title:"SSH public-key authentication is disabled".into(), detail:"The server is not configured to accept SSH public keys.".into(), recommendation:"Enable public-key authentication before disabling password authentication.".into()}); },
        None => push_check(&mut checks, "pubkey_auth", "Public-key authentication", "UNKNOWN", "unknown".into(), "The effective SSH daemon configuration could not be read."),
    }
    match permit_root.as_str() {
        "no" => push_check(&mut checks, "root_login", "Root login", "PASS", permit_root.clone(), "Direct SSH root login is disabled."),
        "prohibit-password" | "without-password" => { score -= 5; push_check(&mut checks, "root_login", "Root login", "WARN", permit_root.clone(), "Root login is restricted to public-key authentication." ); findings.push(SecurityFinding{severity:"MEDIUM".into(), title:"Direct root SSH login is restricted, not disabled".into(), detail:format!("PermitRootLogin is configured as {}.", permit_root), recommendation:"Prefer PermitRootLogin no and use sudo from a normal administrator account.".into()}); },
        "yes" => { score -= 25; push_check(&mut checks, "root_login", "Root login", "FAIL", permit_root.clone(), "Direct SSH root login is enabled." ); findings.push(SecurityFinding{severity:"CRITICAL".into(), title:"Direct root SSH login is enabled".into(), detail:"Remote root login is directly permitted by the SSH daemon.".into(), recommendation:"Set PermitRootLogin no and use a normal account with sudo.".into()}); },
        _ => push_check(&mut checks, "root_login", "Root login", "UNKNOWN", permit_root.clone(), "The SSH root-login policy could not be determined."),
    }
    match max_auth_tries {
        Some(v) if v <= 6 => push_check(&mut checks, "max_auth_tries", "MaxAuthTries", "PASS", v.to_string(), "Authentication attempts are bounded."),
        Some(v) => { score -= 5; push_check(&mut checks, "max_auth_tries", "MaxAuthTries", "WARN", v.to_string(), "The authentication attempt limit is higher than recommended for a small server." ); findings.push(SecurityFinding{severity:"LOW".into(), title:"MaxAuthTries is relatively high".into(), detail:format!("MaxAuthTries is {}.", v), recommendation:"Consider lowering MaxAuthTries to 6 or below.".into()}); },
        None => push_check(&mut checks, "max_auth_tries", "MaxAuthTries", "UNKNOWN", "unknown".into(), "Could not determine MaxAuthTries."),
    }
    match x11_forwarding {
        Some(false) => push_check(&mut checks, "x11_forwarding", "X11 forwarding", "PASS", "disabled".into(), "X11 forwarding is disabled."),
        Some(true) => { score -= 3; push_check(&mut checks, "x11_forwarding", "X11 forwarding", "WARN", "enabled".into(), "X11 forwarding is enabled." ); findings.push(SecurityFinding{severity:"LOW".into(), title:"X11 forwarding is enabled".into(), detail:"X11 forwarding increases the set of features available through SSH.".into(), recommendation:"Disable X11Forwarding unless you explicitly need it.".into()}); },
        None => push_check(&mut checks, "x11_forwarding", "X11 forwarding", "UNKNOWN", "unknown".into(), "Could not determine X11Forwarding."),
    }
    match ufw_active {
        Some(true) => push_check(&mut checks, "ufw_active", "UFW firewall", "PASS", "active".into(), "UFW is active."),
        Some(false) => { score -= 25; push_check(&mut checks, "ufw_active", "UFW firewall", "FAIL", "inactive".into(), "UFW is not active." ); findings.push(SecurityFinding{severity:"HIGH".into(), title:"UFW firewall is inactive".into(), detail:"The local firewall is not active according to the audit.".to_string(), recommendation:"Enable UFW after verifying that SSH access on the intended interface remains allowed.".into()}); },
        None => { score -= 8; push_check(&mut checks, "ufw_active", "UFW firewall", "UNKNOWN", "unknown".into(), "Firewall state could not be determined." ); findings.push(SecurityFinding{severity:"MEDIUM".into(), title:"UFW status could not be fully verified".into(), detail:"The audit could not reliably determine the firewall state.".to_string(), recommendation:"Review UFW status in the Remote Access page with appropriate privileges.".into()}); },
    }
    match fail2ban_active {
        Some(true) => push_check(&mut checks, "f2b_active", "Fail2Ban service", "PASS", "active".into(), "Fail2Ban is active."),
        Some(false) => { score -= 15; push_check(&mut checks, "f2b_active", "Fail2Ban service", "FAIL", "inactive".into(), "Fail2Ban is not active." ); findings.push(SecurityFinding{severity:"MEDIUM".into(), title:"Fail2Ban is inactive".into(), detail:"The intrusion-prevention service is not active.".to_string(), recommendation:"Enable and monitor Fail2Ban for SSH and other exposed services.".into()}); },
        None => { score -= 5; push_check(&mut checks, "f2b_active", "Fail2Ban service", "UNKNOWN", "unknown".into(), "Fail2Ban state could not be determined." ); },
    }
    push_check(&mut checks, "ssh_port", "SSH port", "INFO", ssh_port.to_string(), "Changing the SSH port is not a substitute for firewall and authentication controls.");
    if review_listener_ports > 0 {
        score -= ((review_listener_ports as i32) * 8).min(30);
        push_check(&mut checks, "external_listeners", "External listeners", "WARN", external_listening_ports.to_string(), "Some non-local listeners still need service or exposure review.");
        findings.push(SecurityFinding{severity:"MEDIUM".into(), title:"Listening services require review".into(), detail:format!("{} listener(s) require review; {} are directly exposed and {} are protected by the host firewall policy.", review_listener_ports, exposed_listener_ports, protected_listener_ports), recommendation:"Open the Listening Surface and review service ownership, bind scope and UFW policy before creating any blocking rule.".into()});
    } else if exposed_listener_ports > 0 {
        score -= ((exposed_listener_ports as i32) * 12).min(35);
        push_check(&mut checks, "external_listeners", "External listeners", "INFO", external_listening_ports.to_string(), "Non-local listeners are present but no unclassified listener requires review.");
    } else if protected_listener_ports > 0 {
        push_check(&mut checks, "external_listeners", "External listeners", "PASS", external_listening_ports.to_string(), "Non-local listeners are protected by the detected UFW/default firewall policy or are otherwise classified.");
    } else {
        push_check(&mut checks, "external_listeners", "External listeners", "PASS", "0".into(), "No non-local listeners were detected.");
    }
    if ssh_port == 22 { findings.push(SecurityFinding{severity:"INFO".into(), title:"SSH is listening on port 22".into(), detail:"Port 22 is the standard SSH port and is not itself a security failure.".into(), recommendation:"Keep port 22 if appropriate; prioritize key-based authentication, firewalling, and rate limiting.".into()}); }

    let unknown_checks = checks.iter().filter(|c| c.state == "UNKNOWN").count();
    if unknown_checks > 0 {
        let uncertainty_penalty = (unknown_checks as i32 * 5).min(25);
        score -= uncertainty_penalty;
        findings.push(SecurityFinding{
            severity: "INFO".into(),
            title: "Security audit has incomplete checks".into(),
            detail: format!("{} security control(s) could not be evaluated from the current SSH session.", unknown_checks),
            recommendation: "Review the UNKNOWN controls and provide read access or a safe passwordless helper if deeper auditing is required.".into(),
        });
    }

    score = score.clamp(0, 100);
    let grade = match score { 90..=100 => "A", 80..=89 => "B", 70..=79 => "C", 60..=69 => "D", _ => "F" }.to_string();
    Ok(SecurityAudit{ score: score as u8, grade, ssh_port, password_authentication: password_auth, pubkey_authentication: pubkey_auth, permit_root_login: permit_root, max_auth_tries, x11_forwarding, ufw_active, fail2ban_active, external_listening_ports, exposed_listener_ports, protected_listener_ports, review_listener_ports, listeners, findings, checks, generated_at: chrono_like_now() })
}



#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct SecurityRemediationResult {
    id: String,
    backup_path: String,
    action: String,
    message: String,
}

fn validate_backup_path(path: &str) -> Result<(), String> {
    let prefix = "/var/lib/jarvis-server-manager/jarvis-ssh-";
    let suffix = path
        .strip_prefix(prefix)
        .ok_or_else(|| "Geçersiz J.A.R.V.I.S SSH yedek yolu.".to_string())?;
    if suffix.len() == 6
        && suffix
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return Ok(());
    }
    Err("Geçersiz J.A.R.V.I.S SSH yedek yolu.".into())
}

fn remediation_action(fix_id: &str) -> Result<(&'static str, &'static str), String> {
    match fix_id {
        "disable_password_auth" => Ok(("disable-password-auth", "disable_password_auth")),
        "disable_root_login" => Ok(("disable-root-login", "disable_root_login")),
        "disable_x11_forwarding" => Ok(("disable-x11-forwarding", "disable_x11_forwarding")),
        _ => Err("Bu güvenlik düzeltmesi desteklenmiyor.".into()),
    }
}

#[tauri::command]
fn security_apply_fix(
    host: String,
    port: String,
    username: String,
    key_path: String,
    fix_id: String,
) -> Result<SecurityRemediationResult, String> {
    let (action, expected_id) = remediation_action(&fix_id)?;
    let helper_check = "sudo -n /usr/local/sbin/jarvis-remediation --check";
    run_ssh_exec(&host, &port, &username, &key_path, helper_check)
        .map_err(|_| "Güvenli Fix için J.A.R.V.I.S remediation helper ve passwordless sudo gereklidir. Sunucuda server-setup/install-jarvis-remediation.sh kurulumunu tamamlayın.".to_string())?;

    let command = format!("sudo -n /usr/local/sbin/jarvis-remediation {action}");
    let (stdout, stderr) = run_ssh_exec(&host, &port, &username, &key_path, &command)?;
    if !stderr.trim().is_empty() && stdout.trim().is_empty() {
        return Err(stderr.trim().to_string());
    }
    let mut result_id = String::new();
    let mut backup = String::new();
    let mut action_done = String::new();
    for line in stdout.lines() {
        if let Some(v) = line.strip_prefix("id=") { result_id = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("backup=") { backup = v.trim().to_string(); }
        if let Some(v) = line.strip_prefix("action=") { action_done = v.trim().to_string(); }
    }
    if result_id != expected_id || action_done.is_empty() {
        return Err(format!("Remediation helper beklenen sonucu döndürmedi. Beklenen id={expected_id}, gelen id={result_id}, action={action_done}"));
    }
    validate_backup_path(&backup)?;
    Ok(SecurityRemediationResult {
        id: fix_id,
        backup_path: backup.clone(),
        action: action_done.clone(),
        message: format!("{action_done} uygulandı. SSH yapılandırması doğrulandı ve servis reload edildi."),
    })
}

#[tauri::command]
fn security_rollback(
    host: String,
    port: String,
    username: String,
    key_path: String,
    backup_path: String,
) -> Result<String, String> {
    validate_backup_path(&backup_path)?;
    let helper_check = "sudo -n /usr/local/sbin/jarvis-remediation --check";
    run_ssh_exec(&host, &port, &username, &key_path, helper_check).map_err(|_| {
        "Rollback için J.A.R.V.I.S remediation helper ve passwordless sudo gereklidir.".to_string()
    })?;
    let command = format!(
        "sudo -n /usr/local/sbin/jarvis-remediation rollback {}",
        shell_single_quote(&backup_path)
    );
    let (stdout, stderr) = run_ssh_exec(&host, &port, &username, &key_path, &command)?;
    if stdout.trim().is_empty() && !stderr.trim().is_empty() {
        return Err(stderr.trim().to_string());
    }
    Ok(if !stdout.trim().is_empty() { stdout.trim().to_string() } else { "Rollback completed.".to_string() })
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    format!("unix:{}", secs)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(SshManager::default())
        .manage(LogStreamManager::default())
        .manage(MonitorStreamManager::default())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            start_ssh,
            write_ssh,
            resize_ssh,
            close_ssh,
            remote_exec,
            wake_on_lan,
            probe_server,
            file_list,
            file_read,
            file_write,
            file_mkdir,
            file_touch,
            file_rename,
            file_delete,
            file_upload,
            file_download,
            service_list,
            service_action,
            service_logs,
            logs_query,
            start_log_stream,
            stop_log_stream,
            update_inspect,
            update_history,
            monitor_snapshot,
            start_monitor_stream,
            stop_monitor_stream,
            remote_access_snapshot,
            security_audit,
            security_apply_fix,
            security_rollback,
        ])
        .run(tauri::generate_context!())
        .expect("error while running J.A.R.V.I.S Server Manager");
}
