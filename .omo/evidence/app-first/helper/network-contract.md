# Network intelligence JSON contract (v1)

The canonical `helper.sh --network-intel-json` command writes one compact JSON
document to stdout. It does not create directories, change firewall rules,
reload services, or otherwise mutate host state. Successful collection exits
zero; unavailable, denied, or malformed collection exits nonzero while still
emitting a valid JSON document whose `status` is `partial` or `error`.

```json
{
  "schemaVersion": 1,
  "status": "ok|partial|error",
  "generatedAt": "UTC ISO-8601 timestamp",
  "firewall": {
    "status": "active|inactive|unknown",
    "queryStatus": "ok|denied|unavailable|malformed",
    "defaultIncoming": "allow|deny|reject|unknown",
    "rules": [{
      "action": "allow|deny|reject|unknown",
      "protocol": "tcp|udp|any|unknown",
      "ports": "non-empty UFW port selector or any",
      "source": "non-empty UFW source selector or any",
      "interface": "optional interface name",
      "direction": "in|out|unknown",
      "raw": "non-empty original rule text"
    }]
  },
  "listeners": [{
    "family": "ipv4|ipv6",
    "protocol": "tcp|udp",
    "address": "non-empty bind address",
    "port": 1,
    "pid": "optional integer or null",
    "process": "optional string or null",
    "service": "optional string or null",
    "serviceEvidence": "process|unit|socket|port_guess|unknown",
    "bindScope": "loopback|link_local|private|public|any|unknown",
    "sourcePermissions": [{
      "action": "allow|deny|reject|unknown",
      "scope": "loopback|lan|tailnet|private|public|any|unknown",
      "source": "non-empty UFW source or default marker",
      "interface": "optional string or null",
      "evidence": "non-empty source evidence"
    }],
    "authorization": "verified|partial|unknown"
  }],
  "diagnostics": [{
    "code": "stable_machine_code",
    "severity": "info|warning|error",
    "messageTr": "Turkish operator message"
  }],
  "securityConfig": {
    "queryStatus": "ok|denied|unavailable|malformed",
    "effective": true,
    "source": "helper_effective|file_fallback|unknown"
  }
}
```

Rules are retained in their reported order. A listener can contain simultaneous
LAN, tailnet, private, public, allow, deny, and reject entries; bind scope is
not treated as source authorization. Empty `listeners` is trustworthy only
when listener collection succeeded. Unknown, denied, unavailable, and malformed
states are explicitly represented and never converted to an empty-safe result.
`pid`, `process`, `service`, and `interface` are present with a JSON `null`
when unavailable, never a fabricated value. Consumers must parse stdout even
when the command exits nonzero: on `partial` or `error`, stdout is still one
valid contract document and stderr carries only human diagnostics. The older
`--network-intel` output remains additive/backward compatible.
