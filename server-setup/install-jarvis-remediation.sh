#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

readonly INSTALLER_VERSION=2
HELPER=${JARVIS_HELPER_PATH:-/usr/local/sbin/jarvis-remediation}
SUDOERS=${JARVIS_SUDOERS_PATH:-/etc/sudoers.d/jarvis-server-manager}
STATE_DIR=${JARVIS_STATE_DIR:-/var/lib/jarvis-server-manager}
TARGET_USER=${SUDO_USER:-${JARVIS_TARGET_USER:-}}
TRANSACTION_DIR=''
COMMITTED=0
ROLLBACK_REASON=''

fail() { printf '%s\n' "$1" >&2; return 1; }
receipt() { printf 'JARVIS_DEPLOY\t2\t%s\t%s\t%s\n' "$1" "$2" "$3"; }
regular_or_absent() { [[ ! -e "$1" || ( -f "$1" && ! -L "$1" ) ]]; }
safe_parent() { [[ -d "$1" && ! -L "$1" ]]; }

validate_target_user() {
  [[ "$TARGET_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ && "$TARGET_USER" != root ]] || fail 'SUDO_USER must be a non-root local account.'
}

validate_destination() {
  regular_or_absent "$HELPER" && regular_or_absent "$SUDOERS" || fail 'destination must be regular or absent, never a symlink'
  safe_parent "$(dirname "$HELPER")" && safe_parent "$(dirname "$SUDOERS")" || fail 'destination parent is unsafe'
}

sudoers_text() {
  cat <<EOF
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --check
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --status
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --effective-config
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --listeners
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --network-intel
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --network-intel-json
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --update-preview
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --update
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --poweroff
$TARGET_USER ALL=(root) NOPASSWD: $HELPER --reboot
$TARGET_USER ALL=(root) NOPASSWD: $HELPER disable-password-auth
$TARGET_USER ALL=(root) NOPASSWD: $HELPER disable-root-login
$TARGET_USER ALL=(root) NOPASSWD: $HELPER disable-x11-forwarding
$TARGET_USER ALL=(root) NOPASSWD: $HELPER rollback ^/var/lib/jarvis-server-manager/jarvis-ssh-[A-Za-z0-9]{6}$
EOF
}

validate_sudoers() { /usr/sbin/visudo -cf "$1" >/dev/null; }
capture_previous() {
  local name="$1" destination="$2" meta
  meta="$TRANSACTION_DIR/$name.meta"
  if [[ -e "$destination" ]]; then
    regular_or_absent "$destination" || fail "unsafe existing $name destination"
    stat -c 'present %u %g %a' "$destination" > "$meta"
    cp -a "$destination" "$TRANSACTION_DIR/$name.previous"
  else
    printf 'absent - - -\n' > "$meta"
  fi
}

restore_one() {
  local name="$1" destination="$2" state uid gid mode
  read -r state uid gid mode < "$TRANSACTION_DIR/$name.meta"
  case "$state" in
    present)
      [[ -f "$TRANSACTION_DIR/$name.previous" && ! -L "$TRANSACTION_DIR/$name.previous" ]] || fail "missing $name rollback bytes"
      install -o "$uid" -g "$gid" -m "$mode" "$TRANSACTION_DIR/$name.previous" "$destination"
      ;;
    absent) rm -f -- "$destination" ;;
    *) fail "invalid $name rollback metadata" ;;
  esac
}

rollback_transaction() {
  [[ -n "$TRANSACTION_DIR" && -d "$TRANSACTION_DIR" ]] || return 0
  restore_one helper "$HELPER"
  restore_one sudoers "$SUDOERS"
}

cleanup_transaction() { [[ -n "$TRANSACTION_DIR" ]] && rm -rf -- "$TRANSACTION_DIR"; }
on_exit() {
  local rc=$?
  if [[ "$COMMITTED" -ne 1 ]]; then
    rollback_transaction || true
    [[ -n "${SUPERVISED_SESSION:-}" ]] && receipt "$SUPERVISED_SESSION" ROLLED_BACK "${ROLLBACK_REASON:-exit-$rc}"
  fi
  cleanup_transaction
  exit "$rc"
}
on_signal() { ROLLBACK_REASON="signal-$1"; exit 32; }

test_failpoint() {
  [[ "${JARVIS_INSTALL_TEST_MODE:-}" == 1 && "${JARVIS_INSTALL_FAILPOINT:-}" == "$1" ]] || return 0
  ROLLBACK_REASON="failpoint-$1"
  return 1
}

stage_files() {
  local source="$1"
  TRANSACTION_DIR=$(mktemp -d "${TMPDIR:-/var/tmp}/jarvis-install.XXXXXX")
  chmod 0700 "$TRANSACTION_DIR"
  if [[ "$source" == --embedded ]]; then
    sed -n '/^# JARVIS_HELPER_BEGIN
#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV

readonly HELPER_VERSION=1.2.2
readonly STATE_DIR=/var/lib/jarvis-server-manager
readonly HELPER=/usr/local/sbin/jarvis-remediation
readonly MANAGED=/etc/ssh/sshd_config.d/99-jarvis-security.conf
readonly LAST_BACKUP="$STATE_DIR/last-backup"

fail() { printf '%s\n' "$1" >&2; return 1; }
ensure_root() { [[ "$(id -u)" -eq 0 ]] || fail 'helper must run as root'; }
regular_or_absent() { [[ ! -e "$1" || ( -f "$1" && ! -L "$1" ) ]]; }

usage() {
  cat <<'EOF'
Usage: jarvis-remediation <command>
  --help | --version | --check | --status | --effective-config | --listeners
  --network-intel | --network-intel-json | --update-preview | --update
  --poweroff | --reboot | disable-password-auth | disable-root-login
  disable-x11-forwarding | rollback <backup-id>
EOF
}

validate_common() {
  [[ -x /usr/sbin/sshd ]] || fail 'sshd not found'
  [[ -x /bin/systemctl ]] || fail 'systemctl not found'
  [[ -d /etc/ssh && -f /etc/ssh/sshd_config ]] || fail 'sshd configuration is missing'
  regular_or_absent "$MANAGED" || fail 'managed SSH configuration is a symlink or non-regular file'
}

backup_is_safe() {
  local backup="$1" owner group mode marker target
  [[ "$backup" =~ ^/var/lib/jarvis-server-manager/jarvis-ssh-[A-Za-z0-9]{6}$ ]] || return 1
  [[ -d "$backup" && ! -L "$backup" ]] || return 1
  read -r owner group mode < <(stat -c '%u %g %a' "$backup")
  [[ "$owner" == 0 && "$group" == 0 && "$mode" == 700 ]] || return 1
  marker="$backup/created-by"; target="$backup/target"
  [[ -f "$marker" && ! -L "$marker" && -f "$target" && ! -L "$target" ]] || return 1
  [[ "$(<"$marker")" == "jarvis-remediation-$HELPER_VERSION" ]] || return 1
  [[ "$(<"$target")" == "$MANAGED" ]] || return 1
}

backup_managed() {
  local backup
  install -d -o root -g root -m 0755 "$STATE_DIR"
  backup=$(mktemp -d "$STATE_DIR/jarvis-ssh-XXXXXX")
  chown root:root "$backup"; chmod 0700 "$backup"
  printf 'jarvis-remediation-%s\n' "$HELPER_VERSION" > "$backup/created-by"
  printf '%s\n' "$MANAGED" > "$backup/target"
  if [[ -e "$MANAGED" ]]; then
    regular_or_absent "$MANAGED" || fail 'managed SSH configuration is unsafe'
    cp -a "$MANAGED" "$backup/managed.conf"
    printf 'existing\n' > "$backup/mode"
  else
    printf 'absent\n' > "$backup/mode"
  fi
  printf '%s\n' "$backup" > "$LAST_BACKUP"
  printf '%s\n' "$backup"
}

restore_backup() {
  local backup="$1" mode
  backup_is_safe "$backup" || fail 'Invalid helper-created rollback backup.'
  mode=$(<"$backup/mode")
  case "$mode" in
    existing)
      [[ -f "$backup/managed.conf" && ! -L "$backup/managed.conf" ]] || fail 'Rollback content is missing.'
      install -d -o root -g root -m 0755 "$(dirname "$MANAGED")"
      install -o root -g root -m 0644 "$backup/managed.conf" "$MANAGED"
      ;;
    absent) rm -f -- "$MANAGED" ;;
    *) fail 'Invalid rollback mode.' ;;
  esac
}

write_directive() {
  local key="$1" value="$2" temp
  temp=$(mktemp "$(dirname "$MANAGED")/.jarvis.XXXXXX")
  if [[ -f "$MANAGED" ]]; then
    awk -v key="$key" -v value="$value" '
      BEGIN { done=0 }
      $0 ~ "^[[:space:]]*" key "([[:space:]]+|$)" { if (!done) { print key " " value; done=1 }; next }
      { print }
      END { if (!done) print key " " value }
    ' "$MANAGED" > "$temp"
  else
    printf '# Managed by J.A.R.V.I.S Server Manager\n%s %s\n' "$key" "$value" > "$temp"
  fi
  install -o root -g root -m 0644 "$temp" "$MANAGED"
  rm -f -- "$temp"
}

network_ufw_verbose() { ufw status verbose; }
network_ufw_numbered() { ufw status numbered; }
network_ss() { ss -H -lntup; }
network_sockets() { systemctl list-sockets --all --no-legend --no-pager; }
network_units() { systemctl list-units --all --type=service --no-legend --no-pager; }

network_intel_json() {
  local ufw_verbose ufw_numbered sockets units listeners ufw_rc rules_rc ss_rc sockets_rc units_rc
  set +e
  ufw_verbose=$(network_ufw_verbose 2>&1); ufw_rc=$?
  ufw_numbered=$(network_ufw_numbered 2>&1); rules_rc=$?
  listeners=$(network_ss 2>&1); ss_rc=$?
  sockets=$(network_sockets 2>&1); sockets_rc=$?
  units=$(network_units 2>&1); units_rc=$?
  set -e
  JARVIS_UFW_VERBOSE="$ufw_verbose" JARVIS_UFW_NUMBERED="$ufw_numbered" JARVIS_LISTENERS="$listeners" JARVIS_SOCKETS="$sockets" JARVIS_UNITS="$units" JARVIS_UFW_RC="$ufw_rc" JARVIS_RULES_RC="$rules_rc" JARVIS_SS_RC="$ss_rc" JARVIS_SOCKETS_RC="$sockets_rc" JARVIS_UNITS_RC="$units_rc" python3 - <<'PY'
import datetime
import json
import os
import re
import sys

def source_scope(value):
    value = value.lower().strip().replace('(v6)', '').strip()
    if value in {'anywhere', 'any', '*'}: return 'any'
    if value in {'127.0.0.1', '::1', 'localhost'} or value.startswith('127.'): return 'loopback'
    if value.startswith('100.') and re.match(r'^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.', value): return 'tailnet'
    if value.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.')): return 'lan'
    if value.startswith(('fc', 'fd')): return 'private'
    return 'public'

def bind_scope(address):
    value = address.lower().split('%', 1)[0]
    if value in {'127.0.0.1', '::1'} or value.startswith('127.'): return 'loopback'
    if value in {'0.0.0.0', '::', '*'}: return 'any'
    if value.startswith('fe80:'): return 'link_local'
    if value.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', 'fc', 'fd')): return 'private'
    return 'public'

def endpoint(raw):
    match = re.match(r'^\[([^]]+)\]:(\d+)$', raw)
    if match: return match.group(1), int(match.group(2)), 'ipv6'
    match = re.match(r'^(.*):(\d+)$', raw)
    if not match: raise ValueError('endpoint')
    return match.group(1), int(match.group(2)), 'ipv6' if ':' in match.group(1) else 'ipv4'

def rule_matches(rule, port, protocol):
    match = re.match(r'^(\d+)(?::(\d+))?(?:/(tcp|udp))?$', rule['ports'].lower())
    if not match: return rule['ports'].lower() in {'any', '*'}
    start, end, rule_protocol = match.groups()
    return (not rule_protocol or rule_protocol == protocol) and int(start) <= port <= int(end or start)

verbose = os.environ['JARVIS_UFW_VERBOSE']; numbered = os.environ['JARVIS_UFW_NUMBERED']; ss_text = os.environ['JARVIS_LISTENERS']
sockets = os.environ['JARVIS_SOCKETS']; units = os.environ['JARVIS_UNITS']; ufw_rc = int(os.environ['JARVIS_UFW_RC']); rules_rc = int(os.environ['JARVIS_RULES_RC']); ss_rc = int(os.environ['JARVIS_SS_RC'])
diagnostics = []
status_match = re.search(r'^Status:\s*(active|inactive)\s*$', verbose, re.MULTILINE | re.I)
if ufw_rc or rules_rc:
    query_status = 'denied' if 'permission denied' in (verbose + numbered).lower() else 'unavailable'; firewall_status = 'unknown'; default = 'unknown'
    diagnostics.append({'code': 'FIREWALL_QUERY_' + query_status.upper(), 'severity': 'warning', 'messageTr': 'UFW durumu doğrulanamadı.'})
elif not status_match:
    query_status = 'malformed'; firewall_status = 'unknown'; default = 'unknown'
    diagnostics.append({'code': 'FIREWALL_MALFORMED', 'severity': 'error', 'messageTr': 'UFW çıktısı çözümlenemedi.'})
else:
    query_status = 'ok'; firewall_status = status_match.group(1).lower()
    default_match = re.search(r'^Default:\s*(allow|deny|reject)\b', verbose, re.MULTILINE | re.I); default = default_match.group(1).lower() if default_match else 'unknown'
rules = []
for raw in numbered.splitlines():
    text = re.sub(r'^\s*\[\s*\d+\]\s*', '', raw).strip()
    match = re.match(r'^(\S+)(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)(?:\s+on\s+(\S+))?\s+(.+)$', text, re.I)
    if not match: continue
    ports, action, direction, interface, source = match.groups(); protocol = ports.rsplit('/', 1)[1].lower() if '/' in ports and ports.rsplit('/', 1)[1].lower() in {'tcp', 'udp'} else 'any'
    rules.append({'action': action.lower(), 'protocol': protocol, 'ports': ports, 'source': source.strip(), 'interface': interface, 'direction': direction.lower(), 'raw': raw})
if ss_rc: diagnostics.append({'code': 'LISTENER_QUERY_UNAVAILABLE', 'severity': 'error', 'messageTr': 'Dinleyen soketler okunamadı.'})
listeners = []
for raw in ss_text.splitlines() if not ss_rc else []:
    parts = raw.split()
    if len(parts) < 5 or parts[0].lower() not in {'tcp', 'udp'}: continue
    try: address, port, family = endpoint(parts[4])
    except ValueError:
        diagnostics.append({'code': 'LISTENER_MALFORMED', 'severity': 'warning', 'messageTr': 'Bir soket satırı çözümlenemedi.'}); continue
    process_match = re.search(r'users:\(\("([^"\\]+)"(?:,pid=(\d+))?', raw); process = process_match.group(1) if process_match else None; pid = int(process_match.group(2)) if process_match and process_match.group(2) else None
    discovery = (process or '').lower() + '\n' + sockets.lower() + '\n' + units.lower()
    if 'cockpit' in (process or '').lower(): service, evidence = 'Cockpit', 'process'
    elif 'xrdp' in (process or '').lower(): service, evidence = 'XRDP', 'process'
    elif port == 9090 and 'cockpit.socket' in discovery: service, evidence = 'Cockpit', 'socket'
    elif port == 3389 and 'xrdp.service' in discovery: service, evidence = 'XRDP', 'unit'
    elif port == 22: service, evidence = 'SSH', 'port_guess'
    elif port == 9090: service, evidence = 'Cockpit', 'port_guess'
    elif port == 3389: service, evidence = 'XRDP', 'port_guess'
    else: service, evidence = None, 'unknown'
    permissions = [{'action': rule['action'], 'scope': source_scope(rule['source']), 'source': rule['source'], 'interface': rule['interface'], 'evidence': rule['raw']} for rule in rules if rule_matches(rule, port, parts[0].lower())]
    if not permissions and default != 'unknown': permissions = [{'action': default, 'scope': 'any', 'source': 'default incoming policy', 'interface': None, 'evidence': 'UFW Default: ' + default}]
    authorization = 'verified' if query_status == 'ok' and permissions else ('partial' if query_status == 'ok' else 'unknown')
    listeners.append({'family': family, 'protocol': parts[0].lower(), 'address': address, 'port': port, 'pid': pid, 'process': process, 'service': service, 'serviceEvidence': evidence, 'bindScope': bind_scope(address), 'sourcePermissions': permissions, 'authorization': authorization})
overall = 'error' if ss_rc else ('partial' if query_status != 'ok' or any(item['authorization'] != 'verified' for item in listeners) else 'ok')
payload = {'schemaVersion': 1, 'status': overall, 'generatedAt': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'), 'firewall': {'status': firewall_status, 'queryStatus': query_status, 'defaultIncoming': default, 'rules': rules}, 'listeners': listeners, 'diagnostics': diagnostics, 'securityConfig': {'queryStatus': 'unavailable', 'effective': False, 'source': 'unknown'}}
print(json.dumps(payload, separators=(',', ':'), ensure_ascii=False)); sys.exit(0 if overall == 'ok' else 2)
PY
}

network_intel_legacy() { local json; json=$(network_intel_json) || true; printf '__JARVIS_NETWORK_INTEL__\n%s\n__END_JARVIS_NETWORK_INTEL__\n' "$json"; }

run_remediation() {
  local key="$1" value="$2" backup restore_needed=1
  ensure_root; validate_common; backup=$(backup_managed)
  restore() { [[ "$restore_needed" -eq 1 ]] && restore_backup "$backup"; }
  trap 'restore' EXIT HUP INT TERM
  write_directive "$key" "$value"; /usr/sbin/sshd -t || fail 'sshd validation failed'; /bin/systemctl reload ssh.service || fail 'SSH reload failed'
  [[ "$(/bin/systemctl is-active ssh.service 2>/dev/null || true)" == active ]] || fail 'SSH service is not active'
  restore_needed=0; trap - EXIT HUP INT TERM
  printf '__JARVIS_REMEDIATION__\naction=%s %s\nbackup=%s\nservice=active\nconfig=valid\n__END_JARVIS_REMEDIATION__\n' "$key" "$value" "$backup"
}

main() {
  [[ $# -ge 1 ]] || { usage >&2; return 64; }
  case "$1" in
    --help) [[ $# -eq 1 ]] || { usage >&2; return 64; }; usage ;;
    --version) [[ $# -eq 1 ]] || { usage >&2; return 64; }; printf 'J.A.R.V.I.S remediation helper %s\n' "$HELPER_VERSION" ;;
    --check) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; [[ -f "$HELPER" && ! -L "$HELPER" ]] || fail 'helper is not installed'; printf 'JARVIS_REMEDIATION_READY\n' ;;
    --status) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; [[ -f "$MANAGED" ]] && printf 'managed_file=present\n' || printf 'managed_file=absent\n' ;;
    --effective-config) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; /usr/sbin/sshd -T | awk '$1 ~ /^(port|passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|x11forwarding)$/ {print}' ;;
    --listeners) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_ss ;;
    --network-intel) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_intel_legacy ;;
    --network-intel-json) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_intel_json ;;
    --update-preview) [[ $# -eq 1 ]] || return 64; ensure_root; /usr/bin/apt-get -s upgrade ;;
    --update) [[ $# -eq 1 ]] || return 64; ensure_root; DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -o DPkg::Lock::Timeout=60 update; DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -o DPkg::Lock::Timeout=60 upgrade -y ;;
    --poweroff) [[ $# -eq 1 ]] || return 64; ensure_root; /bin/systemctl poweroff ;;
    --reboot) [[ $# -eq 1 ]] || return 64; ensure_root; /bin/systemctl reboot ;;
    disable-password-auth) [[ $# -eq 1 ]] || return 64; run_remediation PasswordAuthentication no ;;
    disable-root-login) [[ $# -eq 1 ]] || return 64; run_remediation PermitRootLogin no ;;
    disable-x11-forwarding) [[ $# -eq 1 ]] || return 64; run_remediation X11Forwarding no ;;
    rollback) [[ $# -eq 2 ]] || return 64; ensure_root; validate_common; restore_backup "$2"; /usr/sbin/sshd -t; /bin/systemctl reload ssh.service; printf 'Rollback completed.\nbackup=%s\n' "$2" ;;
    *) fail 'Unsupported remediation action.' ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
# JARVIS_HELPER_END$/p' "$0" | sed '1d;$d' > "$TRANSACTION_DIR/helper.stage"
  else
    cp -- "$source" "$TRANSACTION_DIR/helper.stage"
  fi
  chmod 0755 "$TRANSACTION_DIR/helper.stage"
  sudoers_text > "$TRANSACTION_DIR/sudoers.stage"
  chmod 0440 "$TRANSACTION_DIR/sudoers.stage"
  bash -n "$TRANSACTION_DIR/helper.stage"
  validate_sudoers "$TRANSACTION_DIR/sudoers.stage"
}

replace_staged() {
  local staged="$1" destination="$2" mode="$3" parent temporary
  parent=$(dirname "$destination")
  temporary=$(mktemp "$parent/.jarvis-install.XXXXXX")
  install -o root -g root -m "$mode" "$staged" "$temporary"
  mv -f -- "$temporary" "$destination"
}

transaction_install() {
  local source="$1"
  validate_target_user; validate_destination; stage_files "$source"
  capture_previous helper "$HELPER"; capture_previous sudoers "$SUDOERS"
  trap on_exit EXIT; trap 'on_signal HUP' HUP; trap 'on_signal INT' INT; trap 'on_signal TERM' TERM
  replace_staged "$TRANSACTION_DIR/helper.stage" "$HELPER" 0755
  test_failpoint after_helper
  replace_staged "$TRANSACTION_DIR/sudoers.stage" "$SUDOERS" 0440
  test_failpoint after_sudoers
  [[ -f "$HELPER" && ! -L "$HELPER" && -f "$SUDOERS" && ! -L "$SUDOERS" ]] || fail 'final destinations are unsafe'
  bash -n "$HELPER"; validate_sudoers "$SUDOERS"
  test_failpoint after_final_validation
  COMMITTED=1
  trap - EXIT HUP INT TERM
  cleanup_transaction
}

supervised_deploy() {
  local session="$1" expected_sha="$2" timeout="$3" actual deadline token evidence
  [[ "$session" =~ ^[a-f0-9]{16}$ ]] || return 20
  [[ "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || return 20
  [[ "$timeout" =~ ^[0-9]+$ && "$timeout" -ge 300 && "$timeout" -le 1800 ]] || return 20
  [[ -t 0 && -t 1 ]] || return 20
  actual=$(sha256sum "$0" | awk '{print $1}')
  [[ "$actual" == "$expected_sha" ]] || return 20
  SUPERVISED_SESSION="$session"
  transaction_install --embedded
  deadline=$(( $(date +%s) + timeout ))
  receipt "$session" ROLLBACK_ARMED "$deadline"
  COMMITTED=0
  trap on_exit EXIT; trap 'on_signal HUP' HUP; trap 'on_signal INT' INT; trap 'on_signal TERM' TERM
  if ! IFS= read -r -t "$timeout" token; then ROLLBACK_REASON=timeout; exit 31; fi
  if [[ "$token" == "ABORT $session" ]]; then ROLLBACK_REASON=abort; exit 30; fi
  if [[ "$token" =~ ^COMMIT\ $session\ ([a-f0-9]{64})$ ]]; then
    evidence=${BASH_REMATCH[1]}; COMMITTED=1; receipt "$session" COMMITTED "$evidence"; trap - EXIT HUP INT TERM; cleanup_transaction; return 0
  fi
  ROLLBACK_REASON=invalid-token; exit 30
}

main() {
  [[ "$(id -u)" -eq 0 ]] || { fail 'Run this installer with sudo.'; return 10; }
  case "${1:-}" in
    --supervised-deploy) [[ $# -eq 4 ]] || return 20; supervised_deploy "$2" "$3" "$4" ;;
    '') [[ $# -eq 0 ]] || return 20; transaction_install "$0"; printf 'J.A.R.V.I.S remediation helper installed for user: %s\n' "$TARGET_USER" ;;
    *) return 20 ;;
  esac
}

cat >/dev/null <<'JARVIS_HELPER_EOF'
# JARVIS_HELPER_BEGIN
#!/usr/bin/env bash
set -euo pipefail
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV

readonly HELPER_VERSION=1.2.2
readonly STATE_DIR=/var/lib/jarvis-server-manager
readonly HELPER=/usr/local/sbin/jarvis-remediation
readonly MANAGED=/etc/ssh/sshd_config.d/99-jarvis-security.conf
readonly LAST_BACKUP="$STATE_DIR/last-backup"

fail() { printf '%s\n' "$1" >&2; return 1; }
ensure_root() { [[ "$(id -u)" -eq 0 ]] || fail 'helper must run as root'; }
regular_or_absent() { [[ ! -e "$1" || ( -f "$1" && ! -L "$1" ) ]]; }

usage() {
  cat <<'EOF'
Usage: jarvis-remediation <command>
  --help | --version | --check | --status | --effective-config | --listeners
  --network-intel | --network-intel-json | --update-preview | --update
  --poweroff | --reboot | disable-password-auth | disable-root-login
  disable-x11-forwarding | rollback <backup-id>
EOF
}

validate_common() {
  [[ -x /usr/sbin/sshd ]] || fail 'sshd not found'
  [[ -x /bin/systemctl ]] || fail 'systemctl not found'
  [[ -d /etc/ssh && -f /etc/ssh/sshd_config ]] || fail 'sshd configuration is missing'
  regular_or_absent "$MANAGED" || fail 'managed SSH configuration is a symlink or non-regular file'
}

backup_is_safe() {
  local backup="$1" owner group mode marker target
  [[ "$backup" =~ ^/var/lib/jarvis-server-manager/jarvis-ssh-[A-Za-z0-9]{6}$ ]] || return 1
  [[ -d "$backup" && ! -L "$backup" ]] || return 1
  read -r owner group mode < <(stat -c '%u %g %a' "$backup")
  [[ "$owner" == 0 && "$group" == 0 && "$mode" == 700 ]] || return 1
  marker="$backup/created-by"; target="$backup/target"
  [[ -f "$marker" && ! -L "$marker" && -f "$target" && ! -L "$target" ]] || return 1
  [[ "$(<"$marker")" == "jarvis-remediation-$HELPER_VERSION" ]] || return 1
  [[ "$(<"$target")" == "$MANAGED" ]] || return 1
}

backup_managed() {
  local backup
  install -d -o root -g root -m 0755 "$STATE_DIR"
  backup=$(mktemp -d "$STATE_DIR/jarvis-ssh-XXXXXX")
  chown root:root "$backup"; chmod 0700 "$backup"
  printf 'jarvis-remediation-%s\n' "$HELPER_VERSION" > "$backup/created-by"
  printf '%s\n' "$MANAGED" > "$backup/target"
  if [[ -e "$MANAGED" ]]; then
    regular_or_absent "$MANAGED" || fail 'managed SSH configuration is unsafe'
    cp -a "$MANAGED" "$backup/managed.conf"
    printf 'existing\n' > "$backup/mode"
  else
    printf 'absent\n' > "$backup/mode"
  fi
  printf '%s\n' "$backup" > "$LAST_BACKUP"
  printf '%s\n' "$backup"
}

restore_backup() {
  local backup="$1" mode
  backup_is_safe "$backup" || fail 'Invalid helper-created rollback backup.'
  mode=$(<"$backup/mode")
  case "$mode" in
    existing)
      [[ -f "$backup/managed.conf" && ! -L "$backup/managed.conf" ]] || fail 'Rollback content is missing.'
      install -d -o root -g root -m 0755 "$(dirname "$MANAGED")"
      install -o root -g root -m 0644 "$backup/managed.conf" "$MANAGED"
      ;;
    absent) rm -f -- "$MANAGED" ;;
    *) fail 'Invalid rollback mode.' ;;
  esac
}

write_directive() {
  local key="$1" value="$2" temp
  temp=$(mktemp "$(dirname "$MANAGED")/.jarvis.XXXXXX")
  if [[ -f "$MANAGED" ]]; then
    awk -v key="$key" -v value="$value" '
      BEGIN { done=0 }
      $0 ~ "^[[:space:]]*" key "([[:space:]]+|$)" { if (!done) { print key " " value; done=1 }; next }
      { print }
      END { if (!done) print key " " value }
    ' "$MANAGED" > "$temp"
  else
    printf '# Managed by J.A.R.V.I.S Server Manager\n%s %s\n' "$key" "$value" > "$temp"
  fi
  install -o root -g root -m 0644 "$temp" "$MANAGED"
  rm -f -- "$temp"
}

network_ufw_verbose() { ufw status verbose; }
network_ufw_numbered() { ufw status numbered; }
network_ss() { ss -H -lntup; }
network_sockets() { systemctl list-sockets --all --no-legend --no-pager; }
network_units() { systemctl list-units --all --type=service --no-legend --no-pager; }

network_intel_json() {
  local ufw_verbose ufw_numbered sockets units listeners ufw_rc rules_rc ss_rc sockets_rc units_rc
  set +e
  ufw_verbose=$(network_ufw_verbose 2>&1); ufw_rc=$?
  ufw_numbered=$(network_ufw_numbered 2>&1); rules_rc=$?
  listeners=$(network_ss 2>&1); ss_rc=$?
  sockets=$(network_sockets 2>&1); sockets_rc=$?
  units=$(network_units 2>&1); units_rc=$?
  set -e
  JARVIS_UFW_VERBOSE="$ufw_verbose" JARVIS_UFW_NUMBERED="$ufw_numbered" JARVIS_LISTENERS="$listeners" JARVIS_SOCKETS="$sockets" JARVIS_UNITS="$units" JARVIS_UFW_RC="$ufw_rc" JARVIS_RULES_RC="$rules_rc" JARVIS_SS_RC="$ss_rc" JARVIS_SOCKETS_RC="$sockets_rc" JARVIS_UNITS_RC="$units_rc" python3 - <<'PY'
import datetime
import json
import os
import re
import sys

def source_scope(value):
    value = value.lower().strip().replace('(v6)', '').strip()
    if value in {'anywhere', 'any', '*'}: return 'any'
    if value in {'127.0.0.1', '::1', 'localhost'} or value.startswith('127.'): return 'loopback'
    if value.startswith('100.') and re.match(r'^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.', value): return 'tailnet'
    if value.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.')): return 'lan'
    if value.startswith(('fc', 'fd')): return 'private'
    return 'public'

def bind_scope(address):
    value = address.lower().split('%', 1)[0]
    if value in {'127.0.0.1', '::1'} or value.startswith('127.'): return 'loopback'
    if value in {'0.0.0.0', '::', '*'}: return 'any'
    if value.startswith('fe80:'): return 'link_local'
    if value.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.', '172.2', '172.30.', '172.31.', 'fc', 'fd')): return 'private'
    return 'public'

def endpoint(raw):
    match = re.match(r'^\[([^]]+)\]:(\d+)$', raw)
    if match: return match.group(1), int(match.group(2)), 'ipv6'
    match = re.match(r'^(.*):(\d+)$', raw)
    if not match: raise ValueError('endpoint')
    return match.group(1), int(match.group(2)), 'ipv6' if ':' in match.group(1) else 'ipv4'

def rule_matches(rule, port, protocol):
    match = re.match(r'^(\d+)(?::(\d+))?(?:/(tcp|udp))?$', rule['ports'].lower())
    if not match: return rule['ports'].lower() in {'any', '*'}
    start, end, rule_protocol = match.groups()
    return (not rule_protocol or rule_protocol == protocol) and int(start) <= port <= int(end or start)

verbose = os.environ['JARVIS_UFW_VERBOSE']; numbered = os.environ['JARVIS_UFW_NUMBERED']; ss_text = os.environ['JARVIS_LISTENERS']
sockets = os.environ['JARVIS_SOCKETS']; units = os.environ['JARVIS_UNITS']; ufw_rc = int(os.environ['JARVIS_UFW_RC']); rules_rc = int(os.environ['JARVIS_RULES_RC']); ss_rc = int(os.environ['JARVIS_SS_RC'])
diagnostics = []
status_match = re.search(r'^Status:\s*(active|inactive)\s*$', verbose, re.MULTILINE | re.I)
if ufw_rc or rules_rc:
    query_status = 'denied' if 'permission denied' in (verbose + numbered).lower() else 'unavailable'; firewall_status = 'unknown'; default = 'unknown'
    diagnostics.append({'code': 'FIREWALL_QUERY_' + query_status.upper(), 'severity': 'warning', 'messageTr': 'UFW durumu doğrulanamadı.'})
elif not status_match:
    query_status = 'malformed'; firewall_status = 'unknown'; default = 'unknown'
    diagnostics.append({'code': 'FIREWALL_MALFORMED', 'severity': 'error', 'messageTr': 'UFW çıktısı çözümlenemedi.'})
else:
    query_status = 'ok'; firewall_status = status_match.group(1).lower()
    default_match = re.search(r'^Default:\s*(allow|deny|reject)\b', verbose, re.MULTILINE | re.I); default = default_match.group(1).lower() if default_match else 'unknown'
rules = []
for raw in numbered.splitlines():
    text = re.sub(r'^\s*\[\s*\d+\]\s*', '', raw).strip()
    match = re.match(r'^(\S+)(?:\s+\(v6\))?\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)(?:\s+on\s+(\S+))?\s+(.+)$', text, re.I)
    if not match: continue
    ports, action, direction, interface, source = match.groups(); protocol = ports.rsplit('/', 1)[1].lower() if '/' in ports and ports.rsplit('/', 1)[1].lower() in {'tcp', 'udp'} else 'any'
    rules.append({'action': action.lower(), 'protocol': protocol, 'ports': ports, 'source': source.strip(), 'interface': interface, 'direction': direction.lower(), 'raw': raw})
if ss_rc: diagnostics.append({'code': 'LISTENER_QUERY_UNAVAILABLE', 'severity': 'error', 'messageTr': 'Dinleyen soketler okunamadı.'})
listeners = []
for raw in ss_text.splitlines() if not ss_rc else []:
    parts = raw.split()
    if len(parts) < 5 or parts[0].lower() not in {'tcp', 'udp'}: continue
    try: address, port, family = endpoint(parts[4])
    except ValueError:
        diagnostics.append({'code': 'LISTENER_MALFORMED', 'severity': 'warning', 'messageTr': 'Bir soket satırı çözümlenemedi.'}); continue
    process_match = re.search(r'users:\(\("([^"\\]+)"(?:,pid=(\d+))?', raw); process = process_match.group(1) if process_match else None; pid = int(process_match.group(2)) if process_match and process_match.group(2) else None
    discovery = (process or '').lower() + '\n' + sockets.lower() + '\n' + units.lower()
    if 'cockpit' in (process or '').lower(): service, evidence = 'Cockpit', 'process'
    elif 'xrdp' in (process or '').lower(): service, evidence = 'XRDP', 'process'
    elif port == 9090 and 'cockpit.socket' in discovery: service, evidence = 'Cockpit', 'socket'
    elif port == 3389 and 'xrdp.service' in discovery: service, evidence = 'XRDP', 'unit'
    elif port == 22: service, evidence = 'SSH', 'port_guess'
    elif port == 9090: service, evidence = 'Cockpit', 'port_guess'
    elif port == 3389: service, evidence = 'XRDP', 'port_guess'
    else: service, evidence = None, 'unknown'
    permissions = [{'action': rule['action'], 'scope': source_scope(rule['source']), 'source': rule['source'], 'interface': rule['interface'], 'evidence': rule['raw']} for rule in rules if rule_matches(rule, port, parts[0].lower())]
    if not permissions and default != 'unknown': permissions = [{'action': default, 'scope': 'any', 'source': 'default incoming policy', 'interface': None, 'evidence': 'UFW Default: ' + default}]
    authorization = 'verified' if query_status == 'ok' and permissions else ('partial' if query_status == 'ok' else 'unknown')
    listeners.append({'family': family, 'protocol': parts[0].lower(), 'address': address, 'port': port, 'pid': pid, 'process': process, 'service': service, 'serviceEvidence': evidence, 'bindScope': bind_scope(address), 'sourcePermissions': permissions, 'authorization': authorization})
overall = 'error' if ss_rc else ('partial' if query_status != 'ok' or any(item['authorization'] != 'verified' for item in listeners) else 'ok')
payload = {'schemaVersion': 1, 'status': overall, 'generatedAt': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z'), 'firewall': {'status': firewall_status, 'queryStatus': query_status, 'defaultIncoming': default, 'rules': rules}, 'listeners': listeners, 'diagnostics': diagnostics, 'securityConfig': {'queryStatus': 'unavailable', 'effective': False, 'source': 'unknown'}}
print(json.dumps(payload, separators=(',', ':'), ensure_ascii=False)); sys.exit(0 if overall == 'ok' else 2)
PY
}

network_intel_legacy() { local json; json=$(network_intel_json) || true; printf '__JARVIS_NETWORK_INTEL__\n%s\n__END_JARVIS_NETWORK_INTEL__\n' "$json"; }

run_remediation() {
  local key="$1" value="$2" backup restore_needed=1
  ensure_root; validate_common; backup=$(backup_managed)
  restore() { [[ "$restore_needed" -eq 1 ]] && restore_backup "$backup"; }
  trap 'restore' EXIT HUP INT TERM
  write_directive "$key" "$value"; /usr/sbin/sshd -t || fail 'sshd validation failed'; /bin/systemctl reload ssh.service || fail 'SSH reload failed'
  [[ "$(/bin/systemctl is-active ssh.service 2>/dev/null || true)" == active ]] || fail 'SSH service is not active'
  restore_needed=0; trap - EXIT HUP INT TERM
  printf '__JARVIS_REMEDIATION__\naction=%s %s\nbackup=%s\nservice=active\nconfig=valid\n__END_JARVIS_REMEDIATION__\n' "$key" "$value" "$backup"
}

main() {
  [[ $# -ge 1 ]] || { usage >&2; return 64; }
  case "$1" in
    --help) [[ $# -eq 1 ]] || { usage >&2; return 64; }; usage ;;
    --version) [[ $# -eq 1 ]] || { usage >&2; return 64; }; printf 'J.A.R.V.I.S remediation helper %s\n' "$HELPER_VERSION" ;;
    --check) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; [[ -f "$HELPER" && ! -L "$HELPER" ]] || fail 'helper is not installed'; printf 'JARVIS_REMEDIATION_READY\n' ;;
    --status) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; [[ -f "$MANAGED" ]] && printf 'managed_file=present\n' || printf 'managed_file=absent\n' ;;
    --effective-config) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; /usr/sbin/sshd -T | awk '$1 ~ /^(port|passwordauthentication|pubkeyauthentication|permitrootlogin|maxauthtries|x11forwarding)$/ {print}' ;;
    --listeners) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_ss ;;
    --network-intel) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_intel_legacy ;;
    --network-intel-json) [[ $# -eq 1 ]] || return 64; ensure_root; validate_common; network_intel_json ;;
    --update-preview) [[ $# -eq 1 ]] || return 64; ensure_root; /usr/bin/apt-get -s upgrade ;;
    --update) [[ $# -eq 1 ]] || return 64; ensure_root; DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -o DPkg::Lock::Timeout=60 update; DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -o DPkg::Lock::Timeout=60 upgrade -y ;;
    --poweroff) [[ $# -eq 1 ]] || return 64; ensure_root; /bin/systemctl poweroff ;;
    --reboot) [[ $# -eq 1 ]] || return 64; ensure_root; /bin/systemctl reboot ;;
    disable-password-auth) [[ $# -eq 1 ]] || return 64; run_remediation PasswordAuthentication no ;;
    disable-root-login) [[ $# -eq 1 ]] || return 64; run_remediation PermitRootLogin no ;;
    disable-x11-forwarding) [[ $# -eq 1 ]] || return 64; run_remediation X11Forwarding no ;;
    rollback) [[ $# -eq 2 ]] || return 64; ensure_root; validate_common; restore_backup "$2"; /usr/sbin/sshd -t; /bin/systemctl reload ssh.service; printf 'Rollback completed.\nbackup=%s\n' "$2" ;;
    *) fail 'Unsupported remediation action.' ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
# JARVIS_HELPER_END
JARVIS_HELPER_EOF

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
