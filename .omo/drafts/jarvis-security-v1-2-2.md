---
slug: jarvis-security-v1-2-2
status: paused-by-user
execution_authorized: false
intent: unclear
review_required: true
plan_path: .omo/plans/jarvis-security-v1-2-2.md
plan_sha256: 8590CEFFF19F57A0043ED0C85F51CB4D8B042CBBF7554F040783A70DC2825AB6
last_submitted_plan_sha256: DB91F5A13E752929B4C7E556B50DD11BCF11FEFCC646E39A9246C2AC74F6A835
closure_record: .omo/evidence/plan-session-closed.json
review_round_id: review-20260906005951-f5dc9dfb
pending-action: none; user requested stopping after closing the current operation
review:
  momus:
    status: failed-usage-limit
    workspace_root: C:\JARVIS-Server-Manager-v1.2.1-TR-WOL
    runtime_home: null
    target: .omo/plans/jarvis-security-v1-2-2.md
    round_id: review-20260906005951-f5dc9dfb
    plan_sha256: DB91F5A13E752929B4C7E556B50DD11BCF11FEFCC646E39A9246C2AC74F6A835
    launch_id: momus-137ecfbf
    session: /root/momus_plan_review_v6
    result: "No verdict: the final reviewer returned a usage-limit error; no active reviewer remains."
  independent:
    status: inconclusive-no-deliverable
    workspace_root: C:\JARVIS-Server-Manager-v1.2.1-TR-WOL
    runtime_home: null
    target: .omo/plans/jarvis-security-v1-2-2.md
    round_id: review-20260906005951-f5dc9dfb
    plan_sha256: DB91F5A13E752929B4C7E556B50DD11BCF11FEFCC646E39A9246C2AC74F6A835
    launch_id: independent-82366c52
    session: /root/independent_plan_review_v6
    result: "No final verdict received; current agent inventory contains only /root. This is not approval."
approach: Reconcile current source and live-server truth, establish rollback/provenance, then harden five independent security and operations components in dependency-ordered waves before packaging and real desktop/server QA.
---

# Draft: jarvis-security-v1-2-2

## Components (topology ledger)
<!-- Lock the SHAPE before depth. One row per top-level component that can succeed or fail independently. -->
<!-- id | outcome (one line) | status: active|deferred | evidence path -->
C1 | Remote file UI remains confined to the SSH user's home even through symlinks | active | src-tauri/src/lib.rs:300-478
C2 | Restricted helper has one canonical source, warning-free structured parsing, immutable rollback IDs, and exact sudo argument policy | active | helper.sh; server-setup/install-jarvis-remediation.sh
C3 | Security Center accurately distinguishes LAN/tailnet/public exposure and recognizes Cockpit/XRDP without changing 80/443 | active | src-tauri/src/lib.rs:1295-1450; live `--network-intel`
C4 | Update, shutdown, and reboot actions use fixed helper commands and report success only after observable state checks; remote-open/WOL is deferred | active | src/main.ts:1040-1160
C5 | v1.2.2 has synchronized versions, rollback/provenance, reproducible checksums, install/uninstall evidence, and real UI/server QA | active | package.json; Cargo.toml; tauri.conf.json; target-install-v121

## Open assumptions (announced defaults)
<!-- Intent is UNCLEAR: research resolves ambiguity, defaults are adopted (not asked), and each is surfaced in the plan's human TL;DR for veto. -->
<!-- assumption | adopted default | rationale | reversible? -->
No public SSH | Preserve LAN-only port 22 and Tailscale private access; never open 22 to the Internet | explicit historical boundary | yes
Human admin sudo | Preserve password-protected `(ALL) ALL`; only app helper actions remain NOPASSWD | avoids breaking administration while keeping app least-privileged | yes
Public web | Do not alter ports 80/443 or Nginx in v1.2.2 | purpose/config needs separate service-owner review | yes
Remote open/WOL | Leave existing feature byte-identical and do not invoke/test it in v1.2.2 | user explicitly deferred remote opening | yes
GitHub | Establish local provenance only; do not create/push a remote without repository owner choice | external write/identity is unavailable | yes
Signing | Publish SHA-256 checksums and disclose unsigned packages; do not invent a certificate | no signing identity supplied | yes

## Findings (cited - path:lines)
- Current helper and SSH policy verified live on 2026-09-05; network-intel reproduces AWK warning and Unknown classifications for 3389/9090.
- Lexical-only path normalization is at `src-tauri/src/lib.rs:300-319`; file/SCP consumers are at `:371-478`.
- Fixed update/power actions exist in installer `server-setup/install-jarvis-remediation.sh:96-115` and UI `src/main.ts:1073,1155`.
- Standalone `helper.sh` and installer-generated helper are not behaviorally identical.
- Tauri CSP is present at `src-tauri/tauri.conf.json:20-31`; SSH capability is fixed-argument scoped at `src-tauri/capabilities/default.json:11-29`.
- Installed v1.2.1 passed real UI connection; build artifacts are unsigned and project has no Git provenance/test scripts.
- Independent server verification proves 9090 is Cockpit and 3389 is XRDP; both are LAN-reachable, but WAN exposure is unproven.
- `sudo -n true` fails while fixed helper actions pass, proving general admin sudo remains password-protected.
- Independent release verification proves the installed EXE differs from the release EXE only by Tauri's expected three-byte NSIS bundle marker; raw hash equality is the wrong gate.
- No app process is currently running; fresh v1.2.2 process/window/registry evidence is required.
- Apply/rollback/update success paths trust helper exit/stdout and need independent postcondition refresh to prevent stale success.

## Decisions (with rationale)
- Use the user's explicit “plan yapıp yapmaya başla” as the narrow `$start-work` bootstrap approval.
- Prioritize verified defects: parser/classification, helper drift/rollback boundary, and remote symlink escape before cosmetic CSP/style cleanup.
- Do not perform disruptive update/reboot/poweroff/firewall tests; remote-open/WOL is explicitly outside this release.
- Use temporary, agent-executed failing/manual reproductions rather than introducing a new permanent test framework into this testless codebase.
- Treat symlink confinement as a predictable file-manager boundary, not privilege escalation, because the product intentionally includes a full SSH terminal.
- Never label a LAN-reachable bind-all listener as Internet-exposed without source-policy or WAN-path evidence.

## Scope IN
- v1.2.2 source, helper installer, capabilities/CSP, Turkish UI/state messages, version/package artifacts.
- Read-only and later explicitly gated deployment/QA against `armanc@192.168.1.10` and Tailscale private access.
- Local rollback snapshots, local Git provenance where configuration permits, checksums, install/upgrade/uninstall rollback evidence.

## Scope OUT (Must NOT have)
- No public TCP/22, no arbitrary passwordless sudo/bash/apt/systemctl, no secrets in files/logs.
- No changes to Nginx or public 80/443, no automatic deletion/disable of CUPS/XRDP/Cockpit.
- No remote-open/WOL code change or test; no claim that S5 WOL works.
- No GitHub remote creation/push, code-signing certificate purchase, or OS/package updates without separate observable gate.

## Open questions
None blocking plan generation. Destructive live tests remain explicit gated todos and are not assumed safe during early waves.

## Approval gate
status: paused-by-user
approval-evidence: latest user instruction is “mevcut işlemi bitirtikten sonra burda duralım”; it supersedes the previous start-work instruction. Current planning is closed and implementation must not start automatically.
<!-- When exploration is exhausted and unknowns are answered, set status: awaiting-approval. -->
<!-- That durable record is the loop guard: on a later turn read it and resume at the gate instead of re-running exploration. -->
