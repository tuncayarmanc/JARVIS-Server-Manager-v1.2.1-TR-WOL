#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
PYTHON=/c/Users/arman/AppData/Local/Programs/Python/Launcher/py.exe
[[ -x "$PYTHON" ]] || { echo 'Python launcher unavailable for fixture test' >&2; exit 77; }
source "$ROOT/helper.sh"
python3() { "$PYTHON" -3 "$@"; }
network_ufw_verbose() { cat <<'EOF'; }
Status: active
Default: deny (incoming), allow (outgoing), disabled (routed)
EOF
network_ufw_numbered() { cat <<'EOF'; }
[ 1] 22/tcp ALLOW IN 192.168.1.0/24
[ 2] 22/tcp DENY IN Anywhere
[ 3] 2222/tcp ALLOW IN 100.64.0.0/10
[ 4] 9090/tcp ALLOW IN 192.168.1.0/24
[ 5] 3389/tcp ALLOW IN 100.64.0.0/10
[ 6] 3389/tcp REJECT IN Anywhere
EOF
network_ss() { cat <<'EOF'; }
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=101,fd=3))
tcp LISTEN 0 4096 [::]:2222 [::]:* users:(("sshd",pid=102,fd=3))
tcp LISTEN 0 128 0.0.0.0:9090 0.0.0.0:* users:(("systemd",pid=1,fd=3))
tcp LISTEN 0 128 [fe80::1%eth0]:3389 [::]:* users:(("xrdp",pid=103,fd=3))
EOF
network_sockets() { printf 'cockpit.socket loaded active listening 9090\n'; }
network_units() { printf 'xrdp.service loaded active running\n'; }
json=$(network_intel_json)
"$PYTHON" -3 - "$json" <<'PY'
import json
import sys
p = json.loads(sys.argv[1])
assert p['schemaVersion'] == 1 and p['status'] == 'ok'
by_port = {item['port']: item for item in p['listeners']}
assert by_port[22]['service'] == 'SSH'
assert [x['action'] for x in by_port[22]['sourcePermissions']] == ['allow', 'deny']
assert by_port[2222]['family'] == 'ipv6' and by_port[2222]['sourcePermissions'][0]['scope'] == 'tailnet'
assert by_port[9090]['service'] == 'Cockpit' and by_port[9090]['serviceEvidence'] == 'socket'
assert by_port[3389]['service'] == 'XRDP' and by_port[3389]['bindScope'] == 'link_local'
assert [x['action'] for x in by_port[3389]['sourcePermissions']] == ['allow', 'reject']
PY
network_ufw_verbose() { printf 'Status: nonsense\n'; }
network_ufw_numbered() { printf 'broken\n'; }
set +e
malformed=$(network_intel_json)
rc=$?
set -e
[[ "$rc" -ne 0 ]]
"$PYTHON" -3 - "$malformed" <<'PY'
import json
import sys
p = json.loads(sys.argv[1])
assert p['status'] == 'partial' and p['firewall']['queryStatus'] == 'malformed'
PY
network_ss() { printf ''; }
network_ufw_verbose() { printf 'Status: inactive\nDefault: deny (incoming)\n'; }
network_ufw_numbered() { printf ''; }
empty=$(network_intel_json)
"$PYTHON" -3 - "$empty" <<'PY'
import json
import sys
p = json.loads(sys.argv[1])
assert p['status'] == 'ok' and p['listeners'] == [] and p['firewall']['status'] == 'inactive'
PY
printf 'network-intel fixture scenarios passed\n'
