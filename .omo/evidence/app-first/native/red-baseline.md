# Native failing baseline (red)

Captured: 2026-09-06 after explicit GO and independently confirmed T1 backup.

Source under test: `src-tauri/src/lib.rs` SHA-256 `C7FA355C38EFD7C15BED1C6CD168C59AF5E934D9367FFCD2A4E1284D2BD3A62A`.

## Client provenance/authentication contrast

Invocation: fixed Windows client and Git Bash client each ran `-o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 jarvis-server` with a print-only remote command.

Binary observables:

```text
NATIVE_VERSION
OpenSSH_for_Windows_9.5p2, LibreSSL 3.8.2
NATIVE_ALIAS_CONFIG
user armanc
hostname 192.168.1.10
port 22
NATIVE_ALIAS_AUTH
__JARVIS_NATIVE_OK__NATIVE_EXIT=0
GIT_VERSION
OpenSSH_10.3p1, OpenSSL 3.5.7 9 Jun 2026
GIT_ALIAS_AUTH
armanc@192.168.1.10: Permission denied (publickey).
GIT_EXIT=255
```

Interpretation: native System32 OpenSSH authenticates through alias `jarvis-server`; Git Bash OpenSSH does not. Current production uses PATH-relative `ssh.exe`/`scp.exe`, so launcher provenance is not encoded and can select the failing client.

## Controlled symlink escape

Fixture: task-owned `$HOME/.jarvis-native-t3-20260906-native-red/link` pointed to task-owned `/tmp/jarvis-native-t3-20260906-native-red`. The probe reproduced the current `normalize_remote_path` + `stat` + `cat` behavior. A trap removed both exact fixture roots; a second SSH invocation verified absence.

Binary observables:

```text
CONTROLLED_SYMLINK_BASELINE
__LEXICAL_ESCAPE_READ__OUTSIDE_SENTINEL__OUTSIDE_UNCHANGED__OUTSIDE_SENTINEL
SYMLINK_EXIT=0
__FIXTURES_CLEAN__CLEAN_EXIT=0
```

Interpretation: the lexically in-home path followed an intermediate symlink and read the outside sentinel. The outside fixture remained unchanged and both fixture roots were removed.

## Red conclusions

- H1 confirmed: environment/client selection changes authentication while current production does not fix launcher provenance.
- H2 confirmed: lexical path validation permits an intermediate-link escape.
- H3 confirmed by source/runtime seam pending test lock: current rollback maps empty stdout/stderr to `Rollback completed.` and audit parsing defaults malformed/missing numeric fields toward zero/port 22.
