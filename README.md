# Scried Backend (Rust + Axum)

A backend foundation for Scried, an initiative of Bouwnce. It follows the supplied **Scried Backend Brief (28 October 2026)** and prioritises the first release: accounts/consent, opportunities/applications, program/event check-ins, private proof upload and verification, auditability, and impact reporting.

> **Implementation status:** this is a source starter and not a deployed or audited production service. The local filesystem is a development storage adapter. A transactional email outbox worker supports Resend delivery with SMTP fallback for explicit rate/quota rejections. Configure provider credentials and the frontend URL before verification and password-reset emails can be delivered. CSV export is implemented; PDF/XLSX report rendering and several Phase 2/3 modules are not yet implemented. Review the checklist below before production.

## Technology and operating model

- **Axum / Tokio:** async HTTP API, with modules split by business capability.
- **PostgreSQL + SQLx:** primary store, migrations, transactions, foreign keys, checks, uniqueness constraints, and query-oriented indexes.
- **Redis:** shared rate-limit counters across API replicas; the rate-limit increment/expiry operation is atomic.
- **Argon2id:** adaptive password hashing. Passwords are never stored in plaintext.
- **Signed access tokens + rotating opaque refresh tokens:** 15-minute default access token; refresh tokens stored as SHA-256 digests in a server-side session table, rotated on use, and revoked on logout/password reset. The API checks session revocation and `auth_version` on authenticated requests.
- **RBAC:** roles are separate assignments, so a staff member can have multiple roles. Role checks are performed in handlers as well as authentication middleware.
- **Audit records:** verification decisions, role changes, application events, profile/data exports, deletion requests and staff exports create audit rows.
- **Private proof files:** upload size/type checks and per-request ownership/staff authorisation. No public URL is returned for a proof.
- **Observability and hardening:** structured tracing, timeouts, concurrency limit, gzip, restrictive CORS allow-list, request body caps and defensive response headers.

## Run locally

Requirements: a recent stable Rust toolchain, Docker with Compose, and `openssl` (or another cryptographically secure secret generator).

1. Start dependencies:

   ```bash
   docker compose up -d postgres redis
   ```

2. Configure environment:

   ```bash
   cp .env.example .env
   ```

   Generate a real local signing key and replace `JWT_SECRET`:

   ```bash
   openssl rand -base64 48
   ```

   In `.env`, the local Redis URL should be `redis://:scried_dev_redis_password@127.0.0.1:6379/`. The compose credentials are development-only.

3. Run the API (migrations run automatically on startup):

   ```bash
   cargo run
   ```

   Leave this API process running in **terminal 1**. Migrations run automatically at startup.

   Liveness: `GET http://localhost:8080/api/v1/health/live`

   Readiness checks both PostgreSQL and Redis: `GET http://localhost:8080/api/v1/health/ready`.

   Interactive API documentation is available at `http://localhost:8080/docs`; the OpenAPI
   document is at `http://localhost:8080/api-docs/openapi.json`. In Swagger UI, use **Authorize**
   to enter a bearer access token for protected endpoints. Never put real credentials or tokens
   into the API documentation or commit them to the repository.

4. In **terminal 2**, bootstrap the first administrator after the migration has run. Set these environment variables in that shell (do not commit them): `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_NAME`, `BOOTSTRAP_ADMIN_PASSWORD` (12–128 bytes), then run:

   ```bash
   cargo run --bin bootstrap_admin
   ```

   The bootstrap command creates an email-verified admin and writes an audit event. Run it once; do not expose it as an HTTP endpoint.

   Then publish the privacy notice and terms approved by your legal adviser. Sign in as the admin and call `POST /api/v1/admin/consent-documents`:

   ```json
   {
     "version": "2026-10-28-v1",
     "privacy_notice_text": "Paste the approved privacy notice text here (at least 20 characters).",
     "terms_text": "Paste the approved terms of use here (at least 20 characters)."
   }
   ```

   These exact server-side documents are returned by `GET /api/v1/consent-documents/current`. Registration and guest applications must submit `consent_accepted: true` and the current `consent_version`; they cannot supply or replace the consent wording.

5. Build a release binary:

   ```bash
   cargo build --release
   ```

A container image can be built with `docker build -t scried-backend .`. Supply production secrets at runtime from a secret manager; do not embed them in the image.

For Render, configure the service's environment variables in the Render dashboard. To store private proof uploads in Cloudinary instead of the container filesystem, set `STORAGE_BACKEND=cloudinary` and add `CLOUDINARY_URL` using the connection URL from your Cloudinary console. The service uploads proof assets as **authenticated** assets and proxies authorized downloads through the API; do not change them to public assets. Keep `CLOUDINARY_URL` secret and never commit it. The default `local` backend is intended for development; container-local files can disappear when an instance is replaced or redeployed.

## Configuration

| Variable | Purpose |
|---|---|
| `APP_ENV` | Environment label; use `production` in production |
| `HOST`, `PORT` | Listener address |
| `DATABASE_URL` | PostgreSQL URL |
| `REDIS_URL` | Redis URL, including credentials in production |
| `JWT_SECRET` | HMAC signing secret, minimum 32 bytes; generate randomly |
| `JWT_ISSUER`, `JWT_AUDIENCE` | Token validation boundaries; set to real service/client identifiers |
| `ACCESS_TOKEN_TTL_SECONDS` | Access token lifetime; capped at one hour in code |
| `REFRESH_TOKEN_TTL_DAYS` | Refresh session expiry; capped at 90 days in code |
| `DATABASE_MAX_CONNECTIONS` | Pool maximum; clamped to 5–100 |
| `CORS_ALLOWED_ORIGINS` | Comma-separated exact browser origins, no wildcard |
| `PRIVATE_STORAGE_DIR` | Private local storage root; development only |
| `STORAGE_BACKEND` | Proof storage: `local` (default) or `cloudinary` |
| `CLOUDINARY_URL` | Required when `STORAGE_BACKEND=cloudinary`; Cloudinary connection URL, configure as a deployment secret |
| `MAX_UPLOAD_BYTES` | Upload limit; code caps at 5 MiB |
| `TRUST_PROXY_HEADERS` | Set `true` only if a trusted ingress **overwrites** `X-Forwarded-For`; otherwise leave `false` |

## API outline

All application routes are under `/api/v1`. Responses use JSON except CSV downloads. Authenticated endpoints require `Authorization: Bearer <access_token>`.

| Method | Endpoint | Access / purpose |
|---|---|---|
| `GET` | `/consent-documents/current` | Public; returns the exact currently published privacy notice and terms text/version |
| `POST` | `/admin/consent-documents` | Admin; atomically publishes immutable, versioned privacy notice and terms wording |
| `POST` | `/auth/register` | Public; requires `consent_accepted: true` and the current `consent_version`; server stores wording snapshots |
| `POST` | `/auth/login` | Public; creates session |
| `POST` | `/auth/refresh` | Public; rotates refresh token; replay revokes the session |
| `POST` | `/auth/logout` | Authenticated; revokes current session |
| `GET/PATCH/DELETE` | `/auth/me` | Authenticated; current account, profile correction, or password-confirmed anonymisation/deletion workflow |
| `GET` | `/auth/me/export` | Authenticated; personal-data export as JSON, audited |
| `POST` | `/auth/verify-email` | Public one-time verification token; links guest applications only after verification |
| `POST` | `/auth/request-password-reset` | Public; generic response to avoid account enumeration; queues email |
| `POST` | `/auth/reset-password` | Public one-time token; changes password, increments auth version and revokes sessions |
| `POST` | `/auth/claim-guest-applications` | Verified, authenticated email; links eligible guest applications |
| `GET` | `/opportunities` | Public published opportunities, paginated/filterable |
| `GET` | `/opportunities/{slug}` | Public opportunity details |
| `GET/POST` | `/admin/opportunities` | Program manager/admin list and create |
| `PATCH` | `/admin/opportunities/{id}` | Program manager/admin update |
| `POST` | `/applications` | Authenticated student; one-tap application with point-in-time profile snapshot |
| `POST` | `/applications/guest` | Guest application; requires consent, returns one-time guest continuation token |
| `POST` | `/applications/guest/{id}/continue` | Guest; checks token, records click-through, returns official URL |
| `GET` | `/applications/me` | Authenticated student's application list |
| `GET` | `/applications/{id}` | Owner or authorised staff; stage, snapshot, and proof status/notes |
| `POST` | `/applications/{id}/continue` | Application owner; records click-through then returns official URL |
| `POST` | `/applications/{id}/proofs` | Application owner; multipart file upload, PDF/PNG/JPEG, max 5 MiB |
| `GET` | `/proofs/queue` | Verifier/admin review queue |
| `GET` | `/proofs/{id}/download` | Owner or verifier/program manager/admin; authenticated private file response |
| `POST` | `/proofs/{id}/decision` | Verifier/admin approve or reject; rejection requires a note |
| `POST` | `/programs` | Program manager/admin create program |
| `POST` | `/programs/{id}/events` | Program manager/admin create event and one-time QR token |
| `POST` | `/programs/{id}/opportunities/{opportunity_id}` | Program manager/admin link an opportunity to a program |
| `POST` | `/events/{id}/check-in` | Authenticated student with event QR token; idempotent per event/student |
| `POST` | `/events/{id}/paper-check-ins` | Verifier/program manager/admin record attendance from paper sheet |
| `GET` | `/reports/opportunities/{id}/funnel` | Program manager/admin funnel and school score/percentile breakdown |
| `GET` | `/reports/opportunities/{id}/applications.csv` | Program manager/admin participant export; audited, formula-injection mitigated and private/no-store |
| `POST` | `/admin/users/{id}/roles` | Admin assign an additional role |
| `GET` | `/admin/audit-logs` | Admin paginated audit log |
| `POST` | `/admin/users/{id}/anonymise` | Admin-requested anonymisation with a required reason and audit record |

For create/update requests, consult the Rust request structs in `src/` for the exact JSON shape. Registration requires `consent_accepted` and a `consent_version` returned by `GET /consent-documents/current`; **never accept consent text from the browser as the legal record**. Dates should be RFC 3339 timestamps. Store and compare timestamps in UTC; display and schedule user-facing reminders in `Africa/Lagos` (WAT).

## Important behaviours from the brief

- The application stores `registration_snapshot` JSON at application time so later profile edits do not rewrite historical impact reports.
- Guest continuation uses a high-entropy one-time-returned token whose digest is stored. Guest records are only linked to an account after email verification—not solely because an unverified email string matches.
- Event attendance is unique per `(event_id, user_id)` and accepts QR or staff-entered paper-sheet records.
- Proofs are saved under generated object keys, not user-provided paths. File content is checked against PDF/PNG/JPEG signatures; a DB row holds digest, size, MIME, decision and retention timestamp.
- Approved activation screenshots are scheduled for deletion 30 days after review by a periodic cleanup worker. Legal counsel should confirm the retention periods from the brief before launch.
- Partner-facing anonymised dashboards are not exposed yet; do not grant partners the staff reporting endpoints. A separate aggregate-only partner API should be added before issuing `partner_viewer` accounts.
- User-requested deletion scrubs account identifiers, anonymises application snapshots while retaining aggregate dimensions, removes proof files, removes activity-day rows, strips check-in identity, and revokes sessions. Confirm the final retention policy with a Nigerian privacy adviser before production.

## Security and scale checklist before public launch

1. **Email delivery:** implement an email-outbox consumer using the chosen transactional email provider. The API currently writes verification/reset messages to `email_outbox`; without a consumer, tokens are not delivered. Keep reset and verification tokens short-lived and never log them in production.
2. **Object storage:** replace local filesystem storage with a private S3-compatible bucket (or another private object store) before horizontally scaling. Enforce server-side encryption, block public access, emit short-lived signed download URLs only after authorisation, and keep only object keys in PostgreSQL. The bundled local adapter is not a multi-node storage solution.
3. **Report exports:** CSV is the working spreadsheet-compatible export. Add queued export jobs and PDF/XLSX renderers for large data sets rather than holding all rows in a web request. Restrict downloads and set expiry on generated export files.
4. **Integration modules:** connect WhatsApp Business messaging only after the provider and opt-in/opt-out workflow are selected; add retries/idempotency and delivery receipts. Add survey scheduling (30/90/180 days), engagement streak rules, challenges, certificates/PDF, content, enquiry/partner APIs, and a separate anonymised partner portal.
5. **NDPA compliance:** have a qualified adviser confirm the lawful bases, consent wording, retention schedule, data-subject request SLAs, breach plan, cross-border storage, processor agreements and NDPC obligations. Code controls do not themselves certify legal compliance.
6. **Production deployment:** terminate TLS at a trusted ingress; set exact CORS origins; store secrets in a vault/secret manager; secure Postgres/Redis on private networks; configure encrypted automated backups and regularly test restores; enable metrics/alerts; configure a trusted client-IP strategy; add WAF/DDoS controls; run dependency/security scans and load tests.
7. **Administration:** bootstrap one initial admin securely, then assign roles via authenticated admin workflow. Consider requiring MFA for all staff (the brief calls for optional two-step sign-in); a TOTP/WebAuthn implementation is not included in this starter.
8. **Testing:** run unit/integration tests against a disposable PostgreSQL and Redis environment, test refresh-token replay/concurrency, authorization on every route, upload polyglots/oversized payloads, export privacy, backup restore, and account deletion/retention paths. This environment did not contain `rustc`/`cargo`, so the generated source has not been compiled here.

## File layout

```text
src/
  main.rs                 startup, migrations, health server, retention worker
  lib.rs                  router and middleware composition
  config.rs               validated environment configuration
  state.rs                shared pool/client state
  security.rs             Argon2id, opaque tokens, JWT validation
  middleware.rs           authentication + shared Redis rate limiter
  auth.rs                 accounts, consent, email verification/reset outbox, roles, privacy requests
  opportunities.rs        public listing and staff opportunity management
  applications.rs         authenticated/guest application and continuation flows
  events.rs               programs, events, QR/paper check-ins, program/opportunity linking
  proofs.rs               upload, private download, verification, retention cleanup
  reports.rs              funnel and audited CSV export
  rbac.rs                 central role helper
migrations/0001_initial.sql
src/bin/bootstrap_admin.rs
```

## Render deployment

The API applies SQLx migrations at startup, but it does **not** create an administrator automatically. This repository does not currently include a Render Blueprint (`render.yaml`) or an automatic admin-creation deploy hook. The Docker image runs only the API binary; the bootstrap binary is not included in that image.

After the API has deployed successfully and its migrations have run, create the initial administrator once from a local checkout. In PowerShell, set the following variables for the current terminal session, using the same Render database URL configured on the API service:

```powershell
$env:DATABASE_URL = "your Render PostgreSQL connection URL"
$env:BOOTSTRAP_ADMIN_EMAIL = "admin@example.com"
$env:BOOTSTRAP_ADMIN_NAME = "Initial Administrator"
$env:BOOTSTRAP_ADMIN_PASSWORD = "use a unique password of 12-128 bytes"
cargo run --bin bootstrap_admin
```

The command inserts an email-verified account, gives it the `admin` role, and writes an audit event. Run it only once against the intended database. After it reports success, clear the temporary variables from that terminal:

```powershell
Remove-Item Env:DATABASE_URL, Env:BOOTSTRAP_ADMIN_EMAIL, Env:BOOTSTRAP_ADMIN_NAME, Env:BOOTSTRAP_ADMIN_PASSWORD
```

Then sign in using `POST /api/v1/auth/login` and publish the approved privacy notice and terms using `POST /api/v1/admin/consent-documents`. Configure `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `STORAGE_BACKEND`, and other runtime settings in the Render service environment; never commit or share their secret values.

### Testing notes

- `/api/v1/health/live` checks that the process is up; `/api/v1/health/ready` also probes Postgres and Key Value.
- The API reference is hosted at `/docs`; the raw schema is `/openapi.json`. The docs are a manually maintained starter contract, so keep it in sync when routes or request structs change.
- Email verification and password-reset messages are queued in `email_outbox`. The worker sends through Resend when `RESEND_API_KEY` is configured, using SMTP only when Resend clearly rejects for a rate/quota limit. If Resend is not configured, SMTP is the primary sender. Failed messages are retried with exponential backoff; successful outbox payloads are cleared.
- To enable email delivery, set `RESEND_API_KEY`, `EMAIL_FROM`, `FRONTEND_BASE_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, and `SMTP_PASSWORD` in the deployment environment. The frontend must handle `/verify-email?token=...` and `/reset-password?token=...` and submit the token to the corresponding API endpoint. SMTP uses STARTTLS.
- `cargo test` and a Render build must pass before treating the deployment as working. This environment cannot run Rust/Cargo or Docker, so compilation is not verified here.
- Don't run load or security tests against production data. Use disposable staging resources and synthetic student records.

Frontend reference: see [`docs/FRONTEND_INTEGRATION.md`](docs/FRONTEND_INTEGRATION.md).
