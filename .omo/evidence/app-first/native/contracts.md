# Native contracts for frontend and helper integration

Status: T2 lifecycle direction approved by `/root` on 2026-09-06; exact Rust/TypeScript field spelling remains additive until integration.

## SSH lifecycle contract

`start_ssh` returns only a start receipt:

```json
{"generation":7,"phase":"starting"}
```

The frontend must register/buffer listeners before invoking `start_ssh`, so an authenticated event emitted before the invoke receipt resolves cannot be lost. A start receipt never means `BAĞLI`.

Native emits `ssh-lifecycle`:

```json
{
  "generation": 7,
  "phase": "authenticated",
  "error": null
}
```

Allowed phases are `authenticated`, `failed`, and `closed`. Failure carries:

```json
{
  "code": "authentication_failed",
  "messageTr": "SSH anahtarıyla kimlik doğrulama başarısız oldu.",
  "retryable": false
}
```

Closed/failed events and all output are generation-tagged. The frontend ignores a payload whose generation is not its current receipt/buffered generation. `write_ssh` and `resize_ssh` accept the generation and reject stale handles. `close_ssh` returns the closed generation/phase and terminates the owned child. Rapid restart closes the previous child before installing the new generation.

Error codes are a closed native set: `missing_client`, `invalid_settings`, `authentication_failed`, `host_key_mismatch`, `timeout`, `launch_failed`, and `io_failed`. UI logic must use the code, not English/Turkish text matching.

Authentication is proved in-band: the fixed System32 OpenSSH client runs a remote command that writes a per-start sentinel only after remote command acceptance, then replaces itself with a login shell. Native strips the sentinel even when split across PTY read chunks and emits `authenticated` exactly once. It sets `TERM=xterm-256color`. Launch and authentication have distinct bounded deadlines. `StrictHostKeyChecking=yes` is mandatory; the terminal remains legitimately interactive while noninteractive exec/SCP also use `BatchMode=yes`.

`ssh-output` payload:

```json
{"generation":7,"data":"normal terminal bytes"}
```

## Network intelligence consumer contract

Pending the helper worker's producer schema. Until an exact supported `schemaVersion` parses successfully with complete status fields, the native result is `DOĞRULANAMADI`, its score is null, and legacy helper output is explicitly marked `requiresUpdate`; absence/malformed input never means zero listeners or verified safety.

## Operation verification contract

Mutation results must encode at least `sent`, `run`, and `verified` as distinct outcomes. Apply/rollback success requires a nonempty machine-readable helper result plus a successful effective-configuration reread. Reboot verification additionally carries pre/post boot IDs and elapsed/attempt details; shutdown can prove only command sent and later SSH-unreachable, never electrical poweroff. Empty helper output cannot produce success.
