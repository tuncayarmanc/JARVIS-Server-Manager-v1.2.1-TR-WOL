# Native T2/T3/T5/T6 debug journal

Owner: `/root/native_hardening`

State: pre-GO, read-only inspection only. Product/runtime mutations are blocked until T1 backup verification and explicit GO from `/root`.

## Safety boundary

- Product ownership: `src-tauri/src/lib.rs` and focused new native modules only.
- No Cargo/version/TypeScript/helper edits without explicit coordination.
- No live apply, update, reboot, poweroff, Wake-on-LAN, firewall, SSH daemon, Nginx, or remote configuration mutation.
- Never record private-key/password contents.
- Controlled symlink fixtures may only be created after GO, in a task-owned scratch root, and must not target real user data.

## Initial hypotheses (orthogonal)

1. Launcher provenance/lifecycle: PATH-selected `ssh.exe` plus PTY-spawn success causes a false connected state; a validated fixed System32 client and authenticated in-band proof should toggle the outcome.
2. Remote path identity: lexical `/home/<user>` normalization accepts intermediate symlink escapes; checking the actual target/existing parent chain should toggle the escape while preserving final-link rename/delete semantics.
3. Result interpretation: permissive legacy/helper parsing and non-empty/empty-output heuristics manufacture verified or successful states; strict tagged/schema parsing plus explicit verification evidence should toggle misleading successes to unknown/failure.

## Planned red-green evidence

Each scenario will record exact invocation, binary observable, stdout/stderr/exit code, source hash, and artifact path before any completion claim.

- Fixed launcher seam: native behavioral harness proves alias/PATH client cannot win and missing System32 binary is typed `missing_client`.
- Lifecycle: repeated connect/close with generation-tagged events; late old output is rejected; owned child exits.
- SSH failures: wrong key, malformed settings, host-key mismatch, timeout.
- File matrix: normal read/write/create/list/upload/download/rename/delete; intermediate/final symlinks; outside target unchanged; home deletion denied; Turkish/spaces; real-followed read size boundary.
- Network consumer: valid current JSON, malformed JSON, incomplete status, nullable score, legacy helper output.
- Operations: apply/rollback empty or misleading output rejected; follow-up verification required; reboot boot-ID evidence represented without invoking reboot.

## Artifact registry

| Artifact | Created | Cleanup | Status |
|---|---:|---|---|
| `.omo/evidence/app-first/native/debug-journal.md` | 2026-09-06 | preserve as evidence | active |
| Remote `$HOME/.jarvis-native-t3-*` fixture and sibling `/tmp/jarvis-native-t3-*` target | before runtime probe | one-command trap removes both exact task-owned paths | planned |
| Local Cargo test/build outputs under existing `src-tauri/target` | before red tests/build | preserve build evidence; generated tree excluded from product backup | planned |

## Cleanup ledger

No runtime fixtures, child processes, remote files, or external state were created or changed in pre-GO inspection.

After GO: controlled remote symlink fixtures were created and removed by a trap. A separate fixed-client SSH check returned `__FIXTURES_CLEAN__` with exit 0. No fixture remains.
