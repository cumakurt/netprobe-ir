# NetProbe IR v0.7.0 — Authentication, RBAC and SOC Operations

[Türkçe](AUTH_SECURITY_TR.md) · **English** · [Documentation index](README.md)

NetProbe IR v0.5.0 enables web authentication by default. The default administrator username is `admin`, but the project deliberately does **not** ship a universal default password. `install.sh` runs `netprobe-ir auth bootstrap` before the service starts and prints a cryptographically generated initial password once. The account is marked `must_change_password`, so the telemetry console remains unavailable until the bootstrap password is replaced.

## Bootstrap and recovery

Normal installation:

```bash
sudo ./install.sh
```

The installer prints the initial administrator credentials at the end. They are not stored in plaintext. If the password is lost, reset it locally on the sensor:

```bash
sudo netprobe-ir auth reset --data-dir /var/lib/netprobe-ir --username admin
```

The reset command produces a new temporary password and forces a password change on the next login.

## Password storage

Passwords are stored as PBKDF2-HMAC-SHA256 derived values using a unique random salt per account. The default iteration count is 600,000 and is configurable through `auth.password_iterations`. NetProbe never stores a recoverable plaintext password in the user store.

Password policy defaults:

- minimum 12 characters,
- uppercase letter,
- lowercase letter,
- decimal digit,
- special character.

Changing a password revokes existing local sessions for that account.

## Sessions

Browser authentication uses an `HttpOnly`, `SameSite=Strict` session cookie. Session IDs are cryptographically random. Default limits are:

- idle lifetime: 30 minutes,
- absolute lifetime: 12 hours.

Sessions can be listed and revoked from **My Account**. Long-lived WebSocket telemetry is continuously revalidated: session expiry, logout, password change, user disablement or token revocation closes authorization instead of allowing the existing socket to continue receiving telemetry.

Mutating requests made with a browser session are protected by same-origin checks. Scoped API bearer tokens remain suitable for automation and are authorized by explicit scopes rather than browser CSRF state.

## Brute-force protection

Failed logins are tracked by normalized username + source IP. The default policy locks that tuple after five failures for five minutes. Both thresholds are configurable. Password verification and MFA failure use the same protection path.

## Roles

Built-in roles are:

| Role | Intended use |
|---|---|
| `viewer` | read-only dashboards and evidence visibility |
| `analyst` | investigation, Hunt, cases and tuning workflows |
| `responder` | analyst capabilities plus approved response execution |
| `admin` | identity, tokens, audit, backup, configuration and full console administration |

The backend enforces authorization. Hidden or disabled UI buttons are only usability controls and are never the security boundary. NetProbe prevents disabling or demoting the final enabled administrator.

## API tokens

Administrators can create scoped API tokens with an optional TTL. The raw token is returned once; the persistent store keeps only its SHA-256 hash. Tokens can be revoked at any time. Examples of scopes include read-only telemetry, case operations and response permissions.

## TOTP MFA

Accounts can enable TOTP MFA from **My Account**. Enrollment provides a Base32 secret/URI and requires a valid current TOTP before activation. Ten single-use recovery codes are generated; only SHA-256 hashes of recovery codes are persisted. A consumed recovery code is removed immediately.

## OIDC / SSO

Optional OIDC uses Authorization Code + PKCE. The OIDC client validates issuer metadata, RS256 signatures using JWKS, state and PKCE flow data. OIDC users receive the configured default role unless the deployment extends mapping policy. Configure the `oidc` section of `config.json`; keep client secrets outside world-readable locations.

## Audit trail

Security-sensitive actions are written to a tamper-evident HMAC-SHA256 chained audit log. The Operations page can verify the chain. Authentication, identity administration, response requests/approvals, backup operations and other privileged activity should be treated as audit evidence.

## Two-person response approval

High-impact response workflows support requester/approver separation. A requester cannot approve their own pending action. Identity and approval state are validated before the action executes.

## Encrypted backup

The Operations workspace can create integrity-checked backup archives. Encrypted `.npbackup` envelopes use separate PBKDF2-derived encryption and MAC keys, AES-256-CTR confidentiality and HMAC-SHA256 encrypt-then-MAC authentication. Restore rejects a wrong password, corrupted envelope or internal manifest mismatch.

Backups include security/operations state such as authentication, audit, baseline, cases, tuning and evidence data. Store the backup passphrase separately from the backup file.

## Console lockdown

`security.console_allowed_cidrs` restricts the management plane to approved address ranges. The default configuration allows only loopback. NetProbe also refuses an unauthenticated non-loopback bind unless the operator explicitly overrides that protection.

## Signed configuration and forensic immutable mode

`security.require_signed_config` can require trusted configuration signatures. `security.forensic_immutable` protects locked case evidence from destructive workflow changes. These controls complement, rather than replace, filesystem permissions and operating-system hardening.

## SOC operations added in v0.5.0

The authenticated console adds:

- Attack Stories correlation,
- MITRE ATT&CK aggregation,
- Asset Identity views,
- Time Machine/history snapshots,
- network-baseline diff,
- detection suppression/tuning,
- CEF/LEEF syslog and webhook integrations,
- scoped API tokens,
- encrypted backup/restore,
- Health/Self-Diagnostics,
- two-person response approvals,
- local and OIDC account workflows.

All v0.4 capture, process attribution, DPI, IDS, Hunt, Replay, Incident Case, Investigation Graph, Detection Lab, Threat Intelligence, evidence signing, response guardrails and sensor federation features remain available behind the v0.5 authorization layer.
