# Security design and threat model

## 1. Not discoverable (Shodan, Censys, FOFA)

Scanners index whatever answers on a public IP. The control here is architectural: nothing answers.

| Control | Implementation |
|---|---|
| No public listener | Caddy (8443/tcp) and WebRTC (8189/udp) bind only to `VMS_BIND_IP` (loopback, LAN or Tailscale). No other service publishes a port. |
| No port forwarding / UPnP | Remote access is outbound-only: Tailscale (WireGuard) or Cloudflare Tunnel. Disable UPnP on the router. |
| Cameras isolated | Camera VLAN has no internet route. Only MediaMTX reaches it, so camera web UIs and firmware are never exposed. |
| No fingerprints | `Server` headers are stripped, `X-Robots-Tag: noindex` and `robots.txt` deny all, API docs are disabled in production, errors are generic. |
| Identity before reachability | Cloudflare Access (SSO + device posture) or Tailscale ACLs reject unauthenticated traffic before it reaches the app. |

Verify after deployment: from outside your network, `nmap -Pn -p- <public-ip>` should show nothing. Search Shodan for your IP and organisation, and repeat this every quarter.

## 2. Authentication and session

- **No built-in accounts or secrets.** The first super admin registers with a one-time 80-bit setup code written to a
  0600 file on the server and shown only on its terminal; setup closes permanently after the first registration,
  wrong codes are rate limited and ten failures rotate the code. Everyone else joins through single-use invitation
  links (256-bit, SHA-256 at rest, 24 h to 7 days); only super admins can invite or manage admins and super admins.
  Password resets are single-use links too, so no administrator ever knows another person's password.
- Password policy: 12+ characters, no username, not common, not repetitive, three character classes below 16 characters.

- Argon2id password hashing. Lockout after 5 failures (15 min) and per-IP rate limiting on login and MFA enrolment.
- TOTP MFA is mandatory for every user. No session exists until MFA is enrolled. Codes are replay-protected.
- The session JWT is in an `HttpOnly; Secure; SameSite=Strict` cookie. Idle timeout is 30 min, absolute timeout is 12 h, and every state-changing request needs an `X-CSRF-Token` matching the token claim.
- Password change, role change, disabling a user or resetting MFA bumps `pw_version`, which revokes all existing sessions.
- RBAC: viewer → operator (PTZ, IR, alarm, acknowledge, re-ID search) → admin (configuration, users, watchlists, audit).

## 3. Video plane

- MediaMTX authorises **every** request through `/internal/mediamtx-auth`, including its own API (`authHTTPExclude: []`).
- Viewers get a stream token valid for 10 minutes and scoped to one camera path and one action (`read` or `playback`). A live token cannot open recordings, and no token can publish.
- WebRTC media is DTLS-SRTP encrypted, and HLS and playback go over TLS through Caddy.
- The worker and MediaMTX use a shared internal secret. They sit on an `internal: true` Docker network with no internet route.

## 4. Data protection

- Camera RTSP URLs, ONVIF passwords and TOTP secrets are encrypted at rest (Fernet) and masked in API responses.
- Face enrolment requires a consent or lawful-basis reference and an expiry. The enrolment photo is not kept, and embeddings of unmatched people are dropped at ingest.
- Retention: events and snapshots are purged after `VMS_EVENT_RETENTION_DAYS`, and recordings after `recordDeleteAfter`.
- Every privileged action is written to the audit log: login, config, PTZ/IR/alarm, playback, re-ID search, watchlist changes.

## 5. Hardening

- Containers run as non-root with read-only root filesystems where possible, `no-new-privileges` and `cap_drop: ALL`.
- Strict CSP (no inline script or style), HSTS, `X-Frame-Options: DENY` and COOP. All dynamic UI text is HTML-escaped.
- Snapshot paths are resolved and confined to the snapshot directory, which blocks path traversal.

## 6. Privacy guardrails (campus edition)

- **Data flow:** camera → MediaMTX (raw, internal only) → privacy processor (face blur) → `cam<N>_priv` → viewers, AI worker, recorder. The raw stream is read only by the privacy processor and the recorder's sealed pipeline.
- **Keys:**
  - *Media key* (AES-256-GCM, server-held): blurred media and face templates.
  - *Vault key pair* (X25519): the public key is server-held; the private key is wrapped by Argon2id (256 MiB, t=3, p=4) of the super admin passphrase, and separately by a 160-bit recovery code that is never stored.
  - *Unseal* requires a super admin TOTP (replay-protected, rate-limited) **and** the passphrase or recovery code.
- **Unblur render:** the vault key is unlocked in memory for one render job and the reference is then dropped. CPython cannot guarantee memory wiping, so run the API on a host you trust. The output is re-encrypted with the media key, watermarked, and deleted after 15 minutes.
- **Separation of duties:** admins cannot create, modify, reset or delete super admin accounts, and the last super admin cannot be removed.
- **Anti-spoofing:** texture model (MiniFASNetV2-SE) on every scored frame plus the active challenge (12 sequences, intermediate-pose continuity). Model files are integrity-pinned, and liveness fails closed without them.
- **Input hardening:**
  - Image dimensions are checked from the header before decoding (decompression bombs).
  - Requests are capped at 64 MiB.
  - MFA codes must be ASCII-only and single-use per time step (RFC 6238).
  - CSV cells are formula-neutralised.
- **Templates:** only 128-d SFace embeddings are stored (encrypted). Enrolment photos are discarded. Duplicate-face enrolment is blocked and alerted.

## 7. Threats and residual risk

| Threat | Mitigation | Residual |
|---|---|---|
| Credential stuffing | MFA, lockout, rate limit, Access/Tailscale in front | Phishing of TOTP codes: add WebAuthn/OIDC |
| First-visitor takeover of a fresh install | One-time local setup code; setup closes after first registration | Someone with shell access before setup completes (already controls the host) |
| Leaked invitation link | Single use, expiry, revocation, hashed at rest, MFA enrolment required, privileged redemptions alerted | Link intercepted and used before the invitee: send over a trusted channel |
| Stolen session cookie | HttpOnly, SameSite, short TTL, revocation on change | A compromised operator PC still sees what the operator sees |
| Camera firmware exploits | VLAN isolation, no egress, never exposed | Lateral movement if the VMS host is compromised: keep it patched and monitored |
| Enrichment endpoint abuse | Bearer token, IP allow-list, no storage | Add mTLS or private connectivity for production |
| Insider misuse of face/re-ID | Role gating, consent refs, audit of every search | Needs periodic audit review |
| Video tampering / evidence integrity | AES-GCM authenticated chunks; read-only playback; audit trail | Add signed exports for court evidence |
| Photo / screen / replay at kiosk | Random active challenge, planar-geometry check, continuity + identity checks | Silicone masks, live deepfake via virtual camera: use IR/depth + certified PAD |
| Insider unblurring | Two-party flow (request + super admin TOTP + passphrase), reason, watermark, expiry, alerts | A super admin acting alone; require a second super admin for four-eyes if policy demands |
| Server compromise | Raw footage sealed to an offline-protected key | An attacker on the live host sees live raw video and blurred media |
| DoS on alert channels | Per-rule cooldowns | Add global send quotas |
