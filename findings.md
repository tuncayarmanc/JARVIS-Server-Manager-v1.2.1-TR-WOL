# Findings & Decisions: J.A.R.V.I.S Security v1.2.2

> Historical planning findings. The active approved implementation authority is [`.omo/plans/jarvis-1-2-2-app-first.md`](.omo/plans/jarvis-1-2-2-app-first.md); this record remains for provenance and is not a STOPPED execution instruction.

## Requirements
- Reconstruct where the security-review work stopped and what the user intended.
- Verify current app/server state before changing anything.
- Continue through a plan and begin safe, reversible implementation.
- Never expose secrets, open public SSH, or grant broad passwordless sudo.
- Keep live update/reboot/poweroff tests gated because they can disrupt the server; exclude remote-open/WOL work for now.

## Research Findings
- Historical conversation confirms completed SSH hardening and LAN-only firewall intent, but those claims must be reverified live.
- Historical conversation proposed v1.2.2 for Cockpit detection, UFW/listener parsing, Turkish UI, safe power/update actions, and real-state verification.
- Restricted helper architecture is the intended privilege boundary: fixed subcommands via /usr/local/sbin/jarvis-remediation, not arbitrary sudo or shell.
- A final S5 WOL roundtrip is unresolved: earlier UE300 LEDs were off after shutdown, later the user reported they were on, but no subsequent shutdown -> magic packet -> SSH proof was recorded.
- The current local application was rebuilt and installed as v1.2.1, opens successfully, and connects to 192.168.1.10; this is current evidence from the preceding goal turn.
- Parallel read-only audits completed against source, live server, packaging state, conversation history, and primary-source security guidance.
- Live server verification: helper 1.2.1 is ready; effective SSH is port 22, PasswordAuthentication no, PubkeyAuthentication yes, PermitRootLogin no, MaxAuthTries 3, X11Forwarding no.
- Live network-intel still emits the historical AWK regexp warning and misclassifies source-restricted listeners: Cockpit 9090 remains Unknown/EXPOSED and XRDP 3389 remains Unknown/EXPOSED.
- Live sudo policy intentionally exposes only fixed passwordless helper actions for update/power/security plus wildcard rollback; `armanc` retains ordinary password-protected administrator sudo, while `jarvis-agent` has no sudo.
- Live health is operational (`failures=0`, `warnings=2`); warnings are preserved repository changes and missing GitHub SSH authentication.
- Source file-manager confinement is lexical only; symlink targets can escape `/home/<user>` for UI file operations even though the same SSH account already has an unrestricted terminal.
- The installer script and root `helper.sh` have drifted: installer includes update/power actions and strict six-character rollback validation, while the standalone helper snapshot is older.
- WOL validates a parseable IPv4 destination but does not prove it is a broadcast address; full S5 success must remain unclaimed until SSH returns after a real shutdown/wake cycle.
- Tauri CSP and fixed SSH argument capability are present; CSP still permits inline styles. This is a lower-priority hardening item, not a current script-execution bypass.
- Release v1.2.1 exists as NSIS/MSI, and per-user NSIS installation is registered and visually connected. Packages and installed binary are unsigned; the source is not a Git repository and no permanent test/lint workflow exists.
- Independent verifier refined exposure language: 3389 and 9090 are reachable from the Windows LAN client, but this does not prove Internet exposure. `network-intel` must report source scope instead of equating any UFW ALLOW with public exposure.
- Independent verifier identified 9090 definitively as `cockpit.socket` activating `cockpit.service`; 3389 is `xrdp.service`.
- User scope update on 2026-09-05: remote-open/WOL is not wanted now; leave its implementation untouched and do not invoke or test it.
- General `sudo -n true` fails, proving the human admin's `(ALL:ALL) ALL` is password-protected; it is not a broad NOPASSWD grant.
- The installed-versus-release EXE hash difference is legitimate Tauri bundle-type patching (`UNK` to `NSS`, exactly three bytes), not corruption.
- No JARVIS process is currently running; the v1.2.1 screenshots are historical point-in-time QA evidence, so v1.2.2 must capture fresh process/window evidence.
- Source remediation success UI trusts helper stdout and can retain a stale “APPLIED · SECURE” state without an independent postcondition query; v1.2.2 must refresh effective state after apply/rollback.
- Shell capability's final remote-command argument intentionally permits arbitrary remote shell text because the product exposes an interactive SSH terminal; this is not a local shell bypass, but the renderer remains equivalent to the SSH user's authority.

## Technical Decisions
| Decision | Rationale |
|----------|-----------|
| v1.2.2 is a hardening/reconciliation release, not a feature expansion | It matches the conversation's explicit next-version proposal and current unfinished security work. |
| Read-only live audit precedes any mutation | Historical evidence is stale and server actions can lock out access or interrupt services. |
| Remote-open/WOL is deferred and left byte-identical | The user explicitly does not want the remote-open operation now. |
| Keep ordinary password-protected sudo for the human administrator | It is not the same as broad NOPASSWD and removing it would impair legitimate administration. |
| Keep fixed helper update/power actions but tighten parser/rollback boundaries | These actions are explicitly required by the product; arbitrary command forwarding remains forbidden. |
| Do not change public 80/443 in this release | The historical safety boundary requires inspecting the deployed Nginx service before any firewall change. |
| Treat code signing as a documented release limitation | No certificate or signing authority was supplied; purchasing or provisioning one is outside scope. |
| Describe remote symlink hardening as a UI confinement fix, not privilege escalation | The same authenticated user already has a full SSH terminal; accuracy matters for threat modeling. |
| Verify LAN reachability separately from public exposure | Bind-all plus LAN UFW rules is not the same as WAN reachability. |

## Issues Encountered
| Issue | Resolution |
|-------|------------|
| Referenced thread pages were too large and tool output truncated | Paginated all turns and extracted only requirements/status facts; delegated an independent conversation reconstruction. |
| Initial .omo scaffold failed in the empty Codex workspace | Re-ran the official scaffold in the actual application project root. |
| First consolidated planning patch had an ordering-context mismatch | Split planning-artifact updates into smaller ordered patches. |

## Resources
- ChatGPT conversation: 6a98634f-3eb8-83eb-8115-520a22485309
- Project: C:\JARVIS-Server-Manager-v1.2.1-TR-WOL
- Ubuntu: armanc@192.168.1.10
- Agent path: jarvis-agent@100.105.31.70
- Tauri CSP: https://v2.tauri.app/security/csp/
- Tauri permissions: https://v2.tauri.app/security/permissions/
- sudoers argument matching: https://www.man7.org/linux/man-pages/man5/sudoers.5.html
- Linux path-confinement concepts: https://www.man7.org/linux/man-pages/man2/openat2.2.html
- Tailscale SSH/network policy: https://tailscale.com/docs/features/tailscale-ssh
- Dell USB Ethernet WOL limitation: https://www.dell.com/support/kbdoc/en-kw/000179586/
