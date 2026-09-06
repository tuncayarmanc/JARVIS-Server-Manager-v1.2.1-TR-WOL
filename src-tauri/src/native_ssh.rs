use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;

const CONNECT_TIMEOUT_SECONDS: &str = "10";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClientKind {
    Ssh,
    Scp,
}

#[derive(Clone, Debug)]
pub(crate) struct OpenSshClients {
    pub(crate) ssh: PathBuf,
    pub(crate) scp: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct SshConfig {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) key_path: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NativeErrorCode {
    MissingClient,
    InvalidSettings,
    AuthenticationFailed,
    HostKeyMismatch,
    Timeout,
    LaunchFailed,
    IoFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NativeError {
    pub(crate) code: NativeErrorCode,
    pub(crate) message_tr: String,
    pub(crate) retryable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ExecOutcome {
    pub(crate) exit_code: i32,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) timed_out: bool,
}

pub(crate) struct ParseChunk {
    pub(crate) output: Vec<u8>,
    pub(crate) authenticated: bool,
}

pub(crate) struct SentinelParser {
    sentinel: Vec<u8>,
    pending: Vec<u8>,
    authenticated: bool,
}

impl NativeError {
    pub(crate) fn invalid_settings(message: impl Into<String>) -> Self {
        Self { code: NativeErrorCode::InvalidSettings, message_tr: message.into(), retryable: false }
    }

    pub(crate) fn message(&self) -> String {
        self.message_tr.clone()
    }
}

impl SshConfig {
    pub(crate) fn parse(host: &str, port: &str, username: &str, key_path: &str) -> Result<Self, NativeError> {
        let host = host.trim();
        if host.is_empty() || host.len() > 253 || host.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | ':' | '[' | ']'))
        }) {
            return Err(NativeError::invalid_settings("Geçersiz sunucu adresi."));
        }
        let port = port.trim().parse::<u16>()
            .map_err(|_| NativeError::invalid_settings("Geçersiz port."))?;
        if port == 0 {
            return Err(NativeError::invalid_settings("Port 0 olamaz."));
        }
        if username.is_empty() || username.len() > 64 || !username.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        }) {
            return Err(NativeError::invalid_settings("Geçersiz kullanıcı adı."));
        }
        let key_path = PathBuf::from(key_path.trim());
        if !key_path.is_file() {
            return Err(NativeError::invalid_settings("SSH özel anahtar dosyası bulunamadı."));
        }
        Ok(Self { host: host.to_owned(), port, username: username.to_owned(), key_path })
    }

    pub(crate) fn target(&self) -> String {
        format!("{}@{}", self.username, self.host)
    }

    pub(crate) fn common_args(&self, batch_mode: bool) -> Vec<OsString> {
        let mut args = vec![
            OsString::from("-o"), OsString::from("StrictHostKeyChecking=yes"),
            OsString::from("-o"), OsString::from(format!("ConnectTimeout={CONNECT_TIMEOUT_SECONDS}")),
            OsString::from("-o"), OsString::from("ServerAliveInterval=15"),
            OsString::from("-o"), OsString::from("ServerAliveCountMax=2"),
        ];
        if batch_mode {
            args.extend([OsString::from("-o"), OsString::from("BatchMode=yes")]);
        }
        args.extend([
            OsString::from("-p"), OsString::from(self.port.to_string()),
            OsString::from("-i"), self.key_path.as_os_str().to_owned(),
            OsString::from(self.target()),
        ]);
        args
    }

    pub(crate) fn scp_args(&self) -> Vec<OsString> {
        vec![
            OsString::from("-q"), OsString::from("-o"), OsString::from("BatchMode=yes"),
            OsString::from("-o"), OsString::from("StrictHostKeyChecking=yes"),
            OsString::from("-o"), OsString::from(format!("ConnectTimeout={CONNECT_TIMEOUT_SECONDS}")),
            OsString::from("-P"), OsString::from(self.port.to_string()),
            OsString::from("-i"), self.key_path.as_os_str().to_owned(),
        ]
    }
}

pub(crate) fn system_client_path(root: &Path, kind: ClientKind) -> PathBuf {
    match kind {
        ClientKind::Ssh => root.join(r"System32\OpenSSH\ssh.exe"),
        ClientKind::Scp => root.join(r"System32\OpenSSH\scp.exe"),
    }
}

impl OpenSshClients {
    pub(crate) fn resolve() -> Result<Self, NativeError> {
        let root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .map(PathBuf::from)
            .ok_or_else(|| NativeError { code: NativeErrorCode::MissingClient, message_tr: "Windows sistem dizini bulunamadı.".into(), retryable: false })?;
        if !root.is_absolute() {
            return Err(NativeError { code: NativeErrorCode::MissingClient, message_tr: "Windows sistem dizini doğrulanamadı.".into(), retryable: false });
        }
        let ssh = Self::validated_client(&root, ClientKind::Ssh)?;
        let scp = Self::validated_client(&root, ClientKind::Scp)?;
        Ok(Self { ssh, scp })
    }

    fn validated_client(root: &Path, kind: ClientKind) -> Result<PathBuf, NativeError> {
        let expected = system_client_path(root, kind);
        let actual = fs::canonicalize(&expected).map_err(|_| NativeError {
            code: NativeErrorCode::MissingClient,
            message_tr: format!("Windows System32 OpenSSH istemcisi bulunamadı: {}", expected.display()),
            retryable: false,
        })?;
        let expected_dir = fs::canonicalize(root.join(r"System32\OpenSSH")).map_err(|_| NativeError {
            code: NativeErrorCode::MissingClient,
            message_tr: "Windows System32 OpenSSH dizini doğrulanamadı.".into(),
            retryable: false,
        })?;
        if actual.parent() != Some(expected_dir.as_path()) || !actual.is_file() {
            return Err(NativeError { code: NativeErrorCode::MissingClient, message_tr: "OpenSSH istemci yolu System32 dışında çözümlendi.".into(), retryable: false });
        }
        Ok(actual)
    }
}

pub(crate) fn run_process(program: &Path, args: &[OsString], timeout: Duration) -> Result<ExecOutcome, NativeError> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| NativeError {
            code: if error.kind() == std::io::ErrorKind::NotFound { NativeErrorCode::MissingClient } else { NativeErrorCode::LaunchFailed },
            message_tr: format!("OpenSSH işlemi başlatılamadı: {error}"),
            retryable: false,
        })?;
    let stdout = child.stdout.take().ok_or_else(|| NativeError { code: NativeErrorCode::IoFailed, message_tr: "OpenSSH standart çıktısı açılamadı.".into(), retryable: false })?;
    let stderr = child.stderr.take().ok_or_else(|| NativeError { code: NativeErrorCode::IoFailed, message_tr: "OpenSSH hata çıktısı açılamadı.".into(), retryable: false })?;
    let stdout_reader = thread::spawn(move || read_all(stdout));
    let stderr_reader = thread::spawn(move || read_all(stderr));
    let deadline = Instant::now() + timeout;
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (status, false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                child.kill().map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("Zaman aşımındaki OpenSSH işlemi durdurulamadı: {error}"), retryable: true })?;
                let status = child.wait().map_err(|error| NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("OpenSSH işlemi beklenemedi: {error}"), retryable: true })?;
                break (status, true);
            }
            Err(error) => return Err(NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("OpenSSH işlem durumu okunamadı: {error}"), retryable: true }),
        }
    };
    let stdout = join_reader(stdout_reader)?;
    let stderr = join_reader(stderr_reader)?;
    let exit_code = match status.code() { Some(code) => code, None => -1 };
    Ok(ExecOutcome {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        timed_out,
    })
}

fn read_all(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn join_reader(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>) -> Result<Vec<u8>, NativeError> {
    match handle.join() {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => Err(NativeError { code: NativeErrorCode::IoFailed, message_tr: format!("OpenSSH çıktısı okunamadı: {error}"), retryable: true }),
        Err(_) => Err(NativeError { code: NativeErrorCode::IoFailed, message_tr: "OpenSSH çıktı okuyucusu beklenmedik biçimde sonlandı.".into(), retryable: true }),
    }
}

pub(crate) fn classify_ssh_failure(stderr: &str, timed_out: bool) -> NativeError {
    let lower = stderr.to_ascii_lowercase();
    if timed_out || lower.contains("timed out") || lower.contains("connection timeout") {
        return NativeError { code: NativeErrorCode::Timeout, message_tr: "SSH bağlantısı zaman aşımına uğradı.".into(), retryable: true };
    }
    if lower.contains("remote host identification has changed") || lower.contains("host key verification failed") {
        return NativeError { code: NativeErrorCode::HostKeyMismatch, message_tr: "SSH sunucu anahtarı doğrulanamadı veya değişti.".into(), retryable: false };
    }
    if lower.contains("permission denied") || lower.contains("authentication failed") {
        return NativeError { code: NativeErrorCode::AuthenticationFailed, message_tr: "SSH anahtarıyla kimlik doğrulama başarısız oldu.".into(), retryable: false };
    }
    NativeError { code: NativeErrorCode::IoFailed, message_tr: if stderr.trim().is_empty() { "SSH işlemi başarısız oldu.".into() } else { stderr.trim().into() }, retryable: true }
}

impl SentinelParser {
    pub(crate) fn new(sentinel: Vec<u8>) -> Self {
        Self { sentinel, pending: Vec::new(), authenticated: false }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> ParseChunk {
        if self.authenticated {
            return ParseChunk { output: bytes.to_vec(), authenticated: false };
        }
        self.pending.extend_from_slice(bytes);
        if let Some(index) = find_bytes(&self.pending, &self.sentinel) {
            let mut output = self.pending[..index].to_vec();
            let mut suffix = self.pending[index + self.sentinel.len()..].to_vec();
            if suffix.starts_with(b"\r\n") { suffix.drain(..2); }
            else if suffix.starts_with(b"\n") { suffix.drain(..1); }
            output.extend(suffix);
            self.pending.clear();
            self.authenticated = true;
            return ParseChunk { output, authenticated: true };
        }
        let keep = self.sentinel.len().saturating_sub(1).min(self.pending.len());
        let split = self.pending.len() - keep;
        let output = self.pending[..split].to_vec();
        self.pending.drain(..split);
        ParseChunk { output, authenticated: false }
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() { return Some(0); }
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_client_path_when_windows_root_is_valid() {
        // Given a Windows installation root
        let root = std::path::Path::new(r"C:\Windows");

        // When the SSH client path is derived
        let path = system_client_path(root, ClientKind::Ssh);

        // Then PATH lookup is impossible
        assert_eq!(path, root.join(r"System32\OpenSSH\ssh.exe"));
    }

    #[test]
    fn authentication_error_when_openssh_reports_permission_denied() {
        // Given OpenSSH authentication failure output
        let stderr = "user@host: Permission denied (publickey).";

        // When the failure is classified
        let error = classify_ssh_failure(stderr, false);

        // Then the machine code is stable and typed
        assert_eq!(error.code, NativeErrorCode::AuthenticationFailed);
    }

    #[test]
    fn sentinel_is_removed_when_split_between_reads() {
        // Given an authentication sentinel split across PTY reads
        let mut parser = SentinelParser::new(b"__AUTH_7__".to_vec());

        // When both fragments arrive
        let first = parser.push(b"banner\r\n__AU");
        let second = parser.push(b"TH_7__\r\nprompt$ ");

        // Then normal output is preserved and authentication is signalled once
        assert!(!first.authenticated);
        let output = [first.output, second.output].concat();
        assert_eq!(output, b"banner\r\nprompt$ ");
        assert!(second.authenticated);
    }
}
