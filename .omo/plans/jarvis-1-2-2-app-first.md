# J.A.R.V.I.S. 1.2.2 — approved application-first implementation

Approved by the user's explicit `PLEASE IMPLEMENT THIS PLAN` request on 2026-09-06. This is the execution copy of that request; the older paused `jarvis-security-v1-2-2.md` is retained as history, not selected for execution. The pasted planning-only sentence is superseded by the explicit implementation instruction.

## Outcome and boundaries

Deliver a reliable Turkish Windows 1.2.2 application, canonical transactional server helper, correct source-aware network/security reporting, verified local packages and controlled live transition with rollback. The server JARVIS development environment is secondary.

- Project: `C:/JARVIS-Server-Manager-v1.2.1-TR-WOL`; non-Git direct delivery. Never initialize Git or push/create a repository.
- Preserve current application identity, settings, 1.2.1 package and LAN SSH. No public TCP/22; no changes to Nginx or 80/443 firewall policy.
- No WOL/remote-open implementation or invocation. No unattended real update, reboot, poweroff or firmware tests.
- Never receive/replay chat passwords or copy private key/token contents into source, reports or commands. Human-only interactive authentication is a live deployment gate, not a local development blocker.
- No broad passwordless sudo, no Docker socket permission for agent. Keep the intentional full SSH terminal; file-manager guards are not OS isolation.
- Keep npm/Vite/Tauri and existing dependencies; no new test framework or sweeping redesign/identifier renames. Controlled temporary harnesses and existing toolchains are the verification route.
- Inspect current state and record rollback before each mutation. Existing user changes and historical artifacts are preserved.

## Waves and ownership

1. Verified baseline/restore point. Read-only live prerequisite inventory may run concurrently.
2. Native SSH/file safety (one Rust writer) and canonical helper/network producer (separate Bash/Python ownership) run concurrently. Frontend consumer starts once typed contracts are agreed.
3. Native security consumer and Turkish UI/operation states, coordinated with the native owner and no concurrent edits to the same file.
4. Version/package/build and real desktop acceptance after integration.
5. Live prerequisites, transactional helper deployment, then Windows upgrade with rollback. Authentication and disruptive-operation gates remain.
6. Secondary JARVIS environment and final independent verification.

## TODOs

- [x] T1: Preserve and verify 1.2.1 recovery baseline.
  - Timestamped non-overwriting source archive with locks; exclude generated build/cache trees and secrets. Preserve installed application, existing installer and settings separately with appropriate local protection.
  - Record versions, paths, SHA-256 and backup manifest. Restore archive to a controlled temporary path and compare every included source hash; verify installed package recovery and settings restore procedure.
  - Evidence: `.omo/evidence/app-first/t1-backup/`; independent verifier must confirm restore, dirty source preservation and no misleading hash claims.
- [ ] T2: Reliable shared native SSH/SCP and authenticated connection lifecycle.
  - Resolve the validated Windows System32 OpenSSH binaries, not changing PATH order. Apply one host/port/user/key validation at terminal, exec, stream and transfer boundaries.
  - BAĞLI only after authenticated confirmation; typed Turkish missing-client, wrong-key, timeout, host-key mismatch outcomes. On disconnect clear stale live data and terminate owned stream processes; reconnect must not duplicate them.
  - Verify successful and failed authentication, malformed settings, host mismatch, timeout, repeated connect/disconnect; record a failing baseline first.
- [ ] T3: Complete file-manager root and symlink guardrails.
  - Check actual target and existing parents for read/write/upload/download/create; reject escape from `/home/<user>`. Rename/delete of a final symlink must operate on the link, not its target. Preserve home-root deletion ban and apply size limits to the actual read file.
  - Verify normal operations, intermediate/final links, outside target unchanged, root deletion, spaces/Turkish names, size boundary. Do not claim full OS confinement.
- [ ] T4: Canonical helper and transactional installer.
  - Edit only standalone helper source, generate embedded copy and assert equality. Precise help/version/read-only readiness, exact command arity, rollback only genuine helper-created safe backup.
  - Remove update autoremove/autoclean. Fixed command allowlist and minimal sudoers only.
  - Back up existing helper/sudoers bytes and metadata; stage and validate both before replace. Any failure must restore the pair, including originally absent paths. Probe interruption/failure recovery in isolated fixtures, not by damaging live configuration.
- [ ] T5: Correct JSON network intelligence and security unknown handling.
  - Add additive `--network-intel-json` with `schemaVersion`, overall query status, firewall status/details, listeners and diagnostics. Each listener includes address family/protocol/port/process/service/source permissions/evidence. Preserve legacy protocol for rollback; old data is never silently verified JSON.
  - Fix AWK warning/socket column; recognize Cockpit via socket/service and XRDP via process/service; label port-only guesses.
  - Distinguish bind address from allowed source. Evaluate IPv4/IPv6, exact port, protocol, ordered allow/deny rules, source range/interface. Represent simultaneous LAN/private/public permissions and uncertain rules truthfully.
  - Unreadable/malformed is DOĞRULANAMADI, not zero risk/listeners. Nullable score with completeness and last successful timestamp, effective SSH policy vs config fallback distinguished.
  - Fixture acceptance: Cockpit/XRDP, IPv4/IPv6, LAN+Tailscale, allow/deny precedence, 22 vs 2222, malformed vs genuinely empty. Real read-only server query when available.
- [ ] T6: Verify operations and complete Turkish user-facing states.
  - Apply/rollback must reread effective configuration; failed follow-up clears safe/applied claims. No empty-output success.
  - Show update package preview and reboot requirement; real update separately confirmed. No live update execution in unattended QA.
  - Reboot verifies a changed boot ID after authenticated SSH returns, capped at 180 seconds. Shutdown distinguishes command sent/unreachable from electrical poweroff; do not modify or test offline WOL branch.
  - Translate menus/files/security/errors/confirmations; typed outcomes drive logic rather than English text matching. Preserve existing visual design.
- [ ] T7: Build and locally verify 1.2.2 packages.
  - Align npm/Cargo/Tauri/helper/docs versions and preserve application identity/settings. Use a separate release output and actual `jarvis_server_manager.exe`.
  - NSIS current-user primary, MSI admin requirement documented. Record SHA-256 and unsigned status.
  - Gates: TypeScript check, npm build, locked Cargo check/build, Bash syntax, generated helper equality and sudoers validation.
  - Real executable QA: Dashboard, Terminal, Files, Monitor, Logs, Security, Updates. Screenshots + process/build metadata; no test-only delivery claim.
- [ ] T8: Live prerequisite correction and controlled deployment.
  - Reinspect clock/time-sync/timers and consequences before any time correction; wrong clock previously prevented Tailscale TLS. Recheck Tailscale and use owner's direct authentication if needed.
  - Reevaluate fwupd-refresh without hiding failure or performing firmware upgrade. Authorized read-only UFW/Fail2Ban verification, maintain LAN access.
  - After local gates, back up and upgrade helper transactionally with 1.2.1 compatibility, then upgrade Windows app and confirm settings/real connection. On failure restore helper/sudoers or 1.2.1 app/settings as appropriate.
  - If secure elevation/login is unavailable, finish local deliverables and provide the exact staged action and blocker, not a false live-completion claim.
- [ ] T9: Secondary JARVIS workspace inventory and least-privilege access.
  - Inventory repo/env/service state in JARVIS/JARVIS_WORKSPACE without secret content; preserve local changes and produce backup/health report.
  - Inspect jarvis-agent access and constrain designated workspace access without general sudo/Docker socket. Existing account/repository GitHub auth verification only; missing owner choice remains explicit and does not block app delivery.

## Final Verification Wave

- [ ] F1: Independent artifact-backed correctness/security/QA review.
  - Verify changed files against approved constraints and baseline hashes; reproduce native/file/helper/network/UI negative paths and real desktop behavior.
  - Include stale_state, dirty_worktree, misleading_success_output and each other applicable adversarial class; record non-applicable reasons.
  - No Git exists: bind reviews to exact SHA-256 source/release manifest, not an invented commit SHA. No PR lifecycle requested.
- [ ] F2: Cleanup and delivery receipt.
  - Stop task-owned QA processes, close temporary resources and remove only resolved task-owned scratch paths when safe. Keep useful evidence, validated backups and release packages.
  - Record completed/unverified/blocked acceptance criteria, package links/checksums, unsigned limitation, rollback paths and any required direct user action. Never mark blocked live stages complete.

## Progress and evidence

Current phase: Wave 2 in progress — T2/T3 native hardening and T4/T5 helper/network producer. T1 independently confirmed; source implementation may begin.

All implementation, tests and QA are worker-owned. Root owns this plan, Boulder state, ledger and independent verdict orchestration. A worker DoneClaim requires independent AdversarialVerify before its checkbox is marked. Durable ledger: `.omo/start-work/ledger.jsonl`. Each lane records exact commands, immutable evidence, current file hashes and cleanup.
