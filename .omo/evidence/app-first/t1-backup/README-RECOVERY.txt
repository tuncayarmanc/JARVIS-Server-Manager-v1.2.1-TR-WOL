J.A.R.V.I.S 1.2.1 RECOVERY INSTRUCTIONS
Created: current timestamped rollback baseline

1. Stop only a verified J.A.R.V.I.S Server Manager process before restoring settings.
2. Verify source-v1.2.1-prechange.tar against source-manifest.json by extracting to a new empty temporary directory and comparing every SHA-256 entry. Do not restore from a directory lacking capture-complete.json.
3. The verified 1.2.1 NSIS installer is under v1.2.1-packages. Verify its SHA-256 against recovery-manifest.json before use. The MSI is retained for recovery reference; it may require administrative installation.
4. Preserve any current install directory by moving it to a new timestamped quarantine outside this backup, then install the retained NSIS package. Never overwrite this backup.
5. Restore installed-app only as an emergency byte-preserving reference. Prefer the retained NSIS package for installation.
6. Restore settings-local-only only after backing up the current settings directory to a new timestamped location. Copy bytes back while the application is stopped. Its ACL is deliberately restricted to the current user and SYSTEM.
7. Relaunch the app and confirm version 1.2.1 and the expected connection configuration. This baseline does not execute the installer or alter live settings.