# J.A.R.V.I.S Server Manager v1.1.0

Network Exposure Intelligence release.

## v1.1.0
- Listening Surface correlates listening sockets with process/PID, systemd unit when discoverable, bind scope, service hint, UFW policy and exposure state.
- Restricted read-only helper action: `--network-intel`.
- Exposure states: LOCAL, PROTECTED, EXPOSED, REVIEW.
- Assessment states are derived from bind scope plus detected UFW policy; the app does not automatically change firewall rules.
- UFW rule correlation and default incoming policy are read-only.
- Existing SSH remediation (`--check`, `--status`, `--effective-config`, `--listeners`, remediation actions and `rollback`) remains available.

## Installation
Install `server-setup/install-jarvis-remediation.sh` with sudo from the administrator account on Ubuntu. The installer does not create or modify the managed SSH security file.

### Network assessment
The audit separates non-local listeners into exposed, protected and review states. Protected listeners are not treated as the same risk as an intentionally allowed public/LAN service. Firewall correlation is informational and read-only.
