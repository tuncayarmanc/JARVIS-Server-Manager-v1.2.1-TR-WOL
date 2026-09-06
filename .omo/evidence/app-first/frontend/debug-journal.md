# Frontend integration journal

## Hypotheses

1. The renderer marks the native `start_ssh` receipt as authenticated because it calls `setConnectionStatus("online")` immediately after `invoke`; expected evidence: the controlled harness identifies that source branch.
2. Stale terminal/lifecycle payloads update the current session because listeners receive untagged values and the renderer retains no active generation; expected evidence: the controlled harness identifies the untagged `ssh-output` listener.
3. Mutation UI displays success without proof because empty output has a positive fallback and effective rereads do not gate success; expected evidence: the controlled harness identifies the update/apply/rollback branches.

## Artifacts to retain

- `baseline-red.mjs`: controlled pre-change harness retained as evidence.
- Command output logs in this directory: immutable red/green/build captures.
