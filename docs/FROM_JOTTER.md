# Jotter Recon and Reuse Record

Read-only review of the reference project at `../Jotter-ref`, commit
`3215256` (`32152564bf48254d15959829682b8bf8e9ebf64a`). No Jotter file was
modified. This document records what Parley reuses, changes, or drops, and why.

Parley is a 1:1 messaging app, so most of Jotter's note-taking surface is out of
scope. The valuable part of the reference is its client-side encryption flow,
auth plumbing, FastAPI layout, and container setup. The encryption flow also
contains a weakness that Parley must not copy.

---

## (a) Key derivation, master-key wrapping, and recovery

### Key derivation

- Jotter derives exactly one AES key from the password:
  - KDF: PBKDF2-HMAC-SHA-256.
  - Iterations: 310,000.
  - Output: 256-bit AES-GCM key.
  - Salt: 32 random bytes, generated per signup.
  - Source: `frontend/src/crypto/encryption.ts:4-5` and `:34-59`.
- The password is imported as raw PBKDF2 key material with
  `crypto.subtle.importKey`, then run through `crypto.subtle.deriveKey`.
  The resulting AES-GCM `CryptoKey` is non-extractable and may encrypt/decrypt.
- The same password is independently hashed with bcrypt for authentication
  (`backend/app/core/security.py:28-34`). Bcrypt truncates input at 72 bytes.
- There is no domain separation and no second derived secret. The password is
  both the authentication credential and the source of the data-encryption key,
  with one salt.

### Master-key generation and wrapping

- On signup, the client generates a random 256-bit AES-GCM master key
  (`frontend/src/crypto/encryption.ts:61-67`). This key is made extractable so
  its raw bytes can be wrapped.
- The raw master key is encrypted with the password-derived wrap key using
  AES-256-GCM and a random 12-byte IV
  (`frontend/src/crypto/encryption.ts:158-175`).
- The wrapped object has these exact fields:
  - `wrapped` — base64 AES-GCM ciphertext of the raw master key.
  - `salt` — base64 32-byte PBKDF2 salt.
  - `iv` — base64 12-byte AES-GCM IV.
  - `algorithm` — `"AES-GCM"`.
  - `kdf_iterations` — `310000`.
  - `kdf_algorithm` — `"PBKDF2"`.
- `JSON.stringify(wrapped)` is stored on the server in
  `users.encrypted_master_key`, and the same salt is stored again in
  `users.kdf_salt` (`backend/app/models/models.py:27-28`,
  `backend/app/api/v1/auth.py:69-79`). The client also stores the wrapped blob in
  IndexedDB (`frontend/src/hooks/useAuth.ts:44-54`).
- On login the server returns `encrypted_master_key`; the client parses it,
  re-derives the wrap key from the entered password and the stored salt, and
  unwraps the master key locally
  (`frontend/src/hooks/useAuth.ts:74-79`,
  `frontend/src/crypto/encryption.ts:177-189`).
- The unwrapped master key is kept in a module-level variable, not in Zustand or
  localStorage (`frontend/src/db/vault.ts:36-49`). It is cleared on logout.
- Notes, notebooks, tags, and attachments are encrypted with that master key
  before being stored in IndexedDB or synced to the server
  (`frontend/src/db/vault.ts:82-143`, `:300-342`).

### Recovery flow

- A recovery key is 32 random bytes rendered as uppercase hex with dash
  separators (`frontend/src/crypto/encryption.ts:198-219`). It is shown once at
  signup.
- The recovery key is imported directly as an AES-GCM key (no KDF) and is used
  to encrypt the raw master key with a random IV. The result is placed in a
  `WrappedMasterKey`-shaped object with an unused random `salt`,
  `kdf_iterations: 1`, and `kdf_algorithm: "NONE"`.
- This object is sent to the server as `recovery_bundle` at signup and stored in
  `users.recovery_bundle` (`backend/app/api/v1/auth.py:75`,
  `backend/app/models/models.py:29`). The recovery key itself is not stored or
  sent at signup.
- A `recoverMasterKey()` helper exists but is not called anywhere in the
  frontend. The password-reset page sends `recovery_key` to the server
  (`frontend/src/pages/auth/ResetPasswordPage.tsx:20-32`), but the backend
  `ResetPasswordRequest` accepts the field and then ignores it
  (`backend/app/schemas/auth.py:47-58`,
  `backend/app/api/v1/auth.py:263-292`).
- The reset endpoint only replaces the bcrypt password hash, marks the reset
  token used, and deactivates sessions. It does not re-wrap the master key, does
  not update `encrypted_master_key` or `kdf_salt`, and does not use the recovery
  bundle. The same is true of `change-password`
  (`backend/app/api/v1/auth.py:295-305`).
- Consequence: after a password reset or password change, the stored
  `encrypted_master_key` is still wrapped with the old password. The client
  tries to unwrap it with the new password and AES-GCM authentication fails, so
  existing notes cannot be decrypted. The recovery key cannot fix this because
  the client never runs the recovery path. Recovery is present in the data model
  but is not functional end to end.
- The unused `PUT /auth/master-key` endpoint could in principle support
  re-wrapping (`backend/app/api/v1/auth.py:352-361`), but no client flow calls
  it.

---

## (b) Exactly what the client sends at signup and login

### Signup

The client calls `POST /api/v1/auth/signup` with this JSON body
(`frontend/src/hooks/useAuth.ts:20-39`, `frontend/src/services/api.ts:49-51`,
`backend/app/schemas/auth.py:5-19`):

```json
{
  "full_name": "<free text>",
  "email": "<email>",
  "password": "<THE RAW PASSWORD>",
  "encrypted_master_key": "<JSON string of the WrappedMasterKey object>",
  "kdf_salt": "<base64 32-byte PBKDF2 salt>",
  "recovery_bundle": "<JSON string of the recovery-wrapped master key>"
}
```

The request is sent over HTTPS with `withCredentials: true` so the server can set
auth cookies. The server then:

1. bcrypt-hashes `password` and stores the hash;
2. stores `encrypted_master_key`, `kdf_salt`, and `recovery_bundle`;
3. returns the user object and the stored `encrypted_master_key`.

### Login

The client calls `POST /api/v1/auth/login` with this JSON body
(`frontend/src/hooks/useAuth.ts:70-79`, `frontend/src/services/api.ts:53-54`,
`backend/app/schemas/auth.py:21-24`):

```json
{
  "email": "<email>",
  "password": "<THE RAW PASSWORD>"
}
```

The server bcrypt-checks the raw password and returns:

```json
{
  "user": { "id": "...", "email": "...", "full_name": "...", "is_active": true },
  "encrypted_master_key": "<the stored JSON string>"
}
```

The client then derives the wrap key from the same raw password and the salt
inside `encrypted_master_key`, and unwraps the master key locally.

### Reset password (also relevant)

`POST /api/v1/auth/reset-password` receives
`{"token": "...", "new_password": "<RAW NEW PASSWORD>", "recovery_key": "..."}`
(`frontend/src/pages/auth/ResetPasswordPage.tsx:20-32`,
`frontend/src/services/api.ts:64-65`). The server uses the raw new password to
replace the bcrypt hash and ignores `recovery_key`.

### Verdict: yes, the server receives the raw password

Jotter's server receives the raw password at signup and at login. At signup it
also receives, in the same request, the wrapped master key and the PBKDF2 salt
needed to unwrap it. At login it stores the wrapped key and salt permanently and
sees the password again.

That means a server which logs request bodies, a reverse proxy which logs them,
or any server operator who inspects a live request can run

```
wrapKey  = PBKDF2-SHA-256(raw password, kdf_salt, 310000)
masterKey = AES-256-GCM-open(encrypted_master_key.wrapped,
                             encrypted_master_key.iv,
                             wrapKey)
```

and then decrypt every synced note, notebook title, tag name, and attachment
that is encrypted under that master key. Even if the server does not log the
password, it stores `encrypted_master_key` plus the salt and KDF parameters, so a
later database compromise permits an offline password-guessing attack; a weak
password is recoverable and the master key follows.

Jotter's zero-knowledge claim therefore holds only if the server is trusted to
discard the password immediately, never log it, and never be compromised. It is
not enforced by the protocol. **This is a weakness Parley must not inherit.**

Parley's contrast, specified in `docs/PROTOCOL.md`:

- The server never receives the raw password or `wrapKey`.
- The client derives two independent secrets with domain-separated inputs:
  `wrapKey` (stays local, random `wrapSalt`) and `authSecret` (sent for bcrypt
  hashing, public username-derived salt).
- The private key is wrapped with `wrapKey` and stored only in IndexedDB. The
  server never receives the wrapped private key, so a server-database compromise
  alone cannot decrypt message content.
- Residual risk: offline password guessing needs only the server's stored
  `bcrypt(authSecret)` hash plus the public username-derived salt. An attacker
  derives `authSecret` from each guess and bcrypt-compares it, recovering a weak
  password and `authSecret`. That does not decrypt messages. Decrypting
  additionally requires the device-only IndexedDB wrapped-key record, because
  the server never has it. Mitigation: the client enforces zxcvbn score >= 3 and
  the KDF uses 600,000 PBKDF2-HMAC-SHA-256 iterations. This is inherent to
  password-wrapped keys and is called out in `docs/THREAT_MODEL.md`.

---

## (c) Authentication, cookies, and JWT setup

- JWT library: `python-jose[cryptography]`, algorithm `HS256`, signed with the
  application `SECRET_KEY` (`backend/app/core/security.py:37-54`).
- Access token lifetime: 60 minutes by default.
- Refresh token lifetime: 30 days by default.
- Token claims: `sub` (user id), `exp`, and `type` (`"access"` or `"refresh"`).
  No issuer, audience, `jti`, or key id.
- Tokens are set as cookies, not returned in a JSON token body
  (`backend/app/api/v1/auth.py:42-60`):
  - `access_token`, `HttpOnly`, `SameSite=Lax`, `Secure=True`, `Path=/`,
    `Max-Age=3600`.
  - `refresh_token`, `HttpOnly`, `SameSite=Lax`, `Secure=True`, `Path=/`,
    `Max-Age=2592000`.
- The access dependency accepts either an `Authorization: Bearer` header or the
  `access_token` cookie (`backend/app/api/v1/deps.py:10-40`). The SPA uses the
  cookie path with Axios `withCredentials: true`.
- Refresh rotation: the refresh token is decoded, its SHA-256 hash is looked up
  in `user_sessions`, a new access/refresh pair is issued, and the stored hash is
  replaced (`backend/app/api/v1/auth.py:189-224`). There is no reuse detection
  beyond the hash lookup.
- Logout deactivates the session only if the caller sends the refresh token in
  the body; it always deletes both cookies
  (`backend/app/api/v1/auth.py:227-239`).
- Sessions store `device_name` from `X-Device-Name`, `ip_address`, `user_agent`,
  `last_active_at`, and `expires_at` (`backend/app/models/models.py:43-58`).
  A code comment says to keep the last five sessions, but no cleanup query is
  implemented.
- Password reset uses `itsdangerous.URLSafeTimedSerializer` with salt
  `"password-reset"` and a one-hour max age
  (`backend/app/core/security.py:57-65`). The token hash is stored in
  `password_reset_tokens`; the raw token is emailed. A development fallback
  prints the reset link to stdout when SMTP is not configured
  (`backend/app/services/email.py:8-12`).
- Google Sign-In is supported by verifying a Google ID token
  (`backend/app/api/v1/auth.py:99-152`). Google Drive tokens are encrypted with
  Fernet using a key derived as `SHA-256(SECRET_KEY)`
  (`backend/app/core/security.py:15-25`).
- CSRF: there is no CSRF token. Protection relies on `SameSite=Lax` plus the
  CORS allowlist. `allow_credentials=True` is set with an explicit origin list
  (`backend/app/main.py:28-34`).
- Key management weaknesses to avoid:
  - `SECRET_KEY` is reused for JWT signing, `itsdangerous` reset tokens, and
    Fernet key derivation.
  - The default `.env.example` value `REPLACE_THIS_MIN_32_CHARS` is accepted by
    the app because only non-empty is checked, so a known placeholder can be
    deployed (`backend/app/core/config.py:37-45`).
  - Bcrypt silently truncates passwords at 72 bytes
    (`backend/app/core/security.py:28-34`).
  - No access-token revocation before expiry; only refresh sessions are
    revocable.
  - `Secure=True` is hardcoded on cookies, which complicates plain-HTTP local
    development and is not configurable.

---

## (d) FastAPI layout and configuration handling

### Layout

```
backend/
├── app/
│   ├── main.py                  FastAPI app, CORS, GZip, lifespan, routers
│   ├── api/v1/
│   │   ├── auth.py              signup/login/refresh/reset/sessions
│   │   ├── deps.py              get_current_user
│   │   ├── notes.py             CRUD for encrypted notes
│   │   ├── sync.py              push/pull sync and conflict handling
│   │   ├── tasks.py             task CRUD
│   │   └── sharing.py           note sharing
│   ├── core/
│   │   ├── config.py            pydantic-settings Settings
│   │   └── security.py          bcrypt, JWT, Fernet, reset tokens
│   ├── db/database.py           async engine, session factory, get_db
│   ├── models/models.py         SQLAlchemy 2.0 typed models
│   ├── schemas/                 Pydantic v2 request/response models
│   └── services/email.py        SMTP reset mail
├── migrations/init.sql          MySQL schema for first boot
├── .env.example
└── requirements.txt
```

- `app/main.py` builds the app at import time, registers `CORSMiddleware` and
  `GZipMiddleware`, starts a lifespan that calls `create_tables()`, includes all
  routers under `/api/v1`, and exposes `GET /api/health`
  (`backend/app/main.py:15-46`).
- Configuration is a `pydantic_settings.BaseSettings` subclass with
  `env_file = ".env"` and `case_sensitive = True`
  (`backend/app/core/config.py:5-35`).
- `SECRET_KEY` and `DATABASE_URL` default to empty strings. The custom
  `__init__` collects missing names and raises `ValueError` at import time
  because `settings = Settings()` runs at module scope
  (`backend/app/core/config.py:37-48`). This is the fail-fast pattern Parley
  reuses, with stricter validation.
- `DATABASE_URL` selects SQLite versus other databases by string prefix; SQLite
  skips pool sizing and `pool_pre_ping`
  (`backend/app/db/database.py:6-24`).
- `get_db()` yields an `AsyncSession`, commits on normal exit, and rolls back on
  exception (`backend/app/db/database.py:31-38`).
- `create_tables()` uses `Base.metadata.create_all` and then runs a list of
  `ALTER TABLE` statements inside try/except blocks that swallow every error
  (`backend/app/db/database.py:41-57`). Alembic is installed but not used at
  runtime, and the exception swallowing can hide real migration failures.
- Models use SQLAlchemy 2.0 `Mapped`/`mapped_column`, string UUID primary keys,
  timezone-aware timestamps, and cascade relationships
  (`backend/app/models/models.py`).
- Schemas use Pydantic v2 with `EmailStr` and field validators. Some endpoint
  payload models are declared inline in route modules (`notes.py`) instead of
  the schema package.
- Health is liveness-only: it returns `{"status": "ok", "app": ...}` and does not
  touch the database (`backend/app/main.py:44-46`).
- There are no tests, no lint configuration, and no type-check configuration in
  the reference.

### Observations relevant to Parley

- The config validates presence only, not strength or placeholder values.
- `ALLOWED_ORIGINS` is a hardcoded Python list including localhost, Capacitor,
  and production origins (`backend/app/core/config.py:17-25`), rather than an
  environment-driven value.
- Not all user content is encrypted: `Task.title`, `CalendarEvent.title` and
  `location`, and `SavedSearch.label/query` are plaintext columns
  (`backend/app/models/models.py:227-274`). The zero-knowledge claim applies to
  notes and attachments, not to every field the service stores.
- The schema is created at startup instead of by a reviewed migration.

---

## (e) Docker setup

### Files

- `Dockerfile.backend`: `python:3.11-slim`, installs `backend/requirements.txt`,
  copies `backend/`, exposes 8000, runs
  `uvicorn app.main:app --host 0.0.0.0 --port 8000`.
- `Dockerfile.frontend`: multi-stage. `node:18-alpine` runs `npm ci` and
  `npm run build`; `nginx:alpine` serves `dist/` with `nginx.conf`.
- `nginx.conf`: serves the SPA with `try_files ... /index.html`, proxies `/api/`
  to `http://backend:8000` without rewriting the path, forwards WebSocket
  upgrade headers, caches hashed assets for one year, and marks `/sw.js`
  `no-store`.
- `docker-compose.yml`:
  - `db`: `mysql:8.0`, `env_file: .env.docker`, database `jotter_db`, mounts
    `backend/migrations/init.sql` into `docker-entrypoint-initdb.d`, healthcheck
    with `mysqladmin ping`, named volume `jotter_mysql_data`.
  - `backend`: built from `Dockerfile.backend`, `env_file: .env.docker`,
    depends on the database being healthy, publishes `8000:8000`.
  - `frontend`: built from `Dockerfile.frontend`, publishes `80:80`, depends on
    backend.
- `.dockerignore` exists to keep build contexts small.
- `.env.docker` is committed with placeholder values. Compose reads `env_file`
  literally, so `${VAR}` interpolation does not happen there; the README warns
  that the MySQL password must be written into `MYSQL_ROOT_PASSWORD` and both
  database URLs separately (`README.md:68-83`).

### Observations relevant to Parley

- The setup works for a demo but is not production hardening:
  - No non-root users in either image.
  - No backend or frontend healthcheck in Compose.
  - No resource limits, read-only filesystems, or secret manager integration.
  - MySQL root credentials are used by the application.
  - `backend/migrations/init.sql` contains a literal root password comment
    (`-- Root password: 123456`).
  - `Dockerfile.frontend` pins Node 18 while the frontend dependency tree may
    require a newer runtime.
  - `.env.docker` is a committed file containing placeholders; Parley commits
    only `.env.example`.
- Parley does not need MySQL for the MVP. SQLite is the development default, and
  Docker can be added when the protocol is implemented. This avoids presenting
  an unhardened container stack as production-ready.

---

## Reused

- **pydantic-settings with import-time validation.** Same fail-fast idea: the app refuses to start without `SECRET_KEY` and `DATABASE_URL`; Parley strengthens it with length and placeholder checks.
- **SQLAlchemy async engine + `get_db` session dependency.** A familiar async session lifecycle with commit-on-success and rollback-on-error keeps route code small and testable.
- **FastAPI app factory/lifespan/router layout.** The `app/main.py` + `app/api` + `app/core` + `app/db` split is clear and scales past the scaffold.
- **httpOnly-cookie auth instead of localStorage tokens.** Keeps bearer tokens out of JavaScript-accessible storage; Parley keeps the cookie pattern but changes the credential and adds rotation/reuse handling.
- **Hashed refresh sessions.** Storing only a hash of the refresh token means a database leak does not hand over live sessions.
- **Zustand for UI state.** Small, typed stores fit the project and keep decrypted key material out of global state.
- **Vite + React + TypeScript + Tailwind SPA.** A fast dev loop and a small static deployment surface are appropriate for a portfolio app.
- **Vite dev proxy for `/api`.** Avoids CORS during local development and mirrors the production nginx path.
- **Health endpoint.** A trivial liveness probe is useful for the first deployment and test.
- **`.env.example` + gitignored real env files.** The right default; Parley also refuses blank or placeholder secrets.
- **Multi-stage frontend build with nginx SPA fallback.** A standard, low-cost way to serve a Vite SPA and proxy the API; recorded for a later Docker milestone.
- **pytest + placeholder test.** Parley adds the test harness Jotter lacks so the scaffold is verifiable from day one.

## Changed

- **Password handling: raw password → `authSecret` only.** The client derives an independent authentication secret and never sends the password, which removes Jotter's critical server-side key-derivation path.
- **One PBKDF2 key → two domain-separated keys with independent salts.** `wrapKey` and `authSecret` cannot be substituted for each other, and only `authSecret` leaves the device.
- **Server-stored wrapped master key → device-only wrapped private key.** The private key is wrapped with `wrapKey` and stored only in IndexedDB, so a server breach does not expose a wrapped key to guess against. The server's bcrypt auth hash and the public username-derived salt still permit offline password guessing, but not message decryption.
- **AES-GCM note encryption → libsodium `crypto_box_easy` for messages.** 1:1 messaging needs public-key encryption; the messaging layer does not invent a construction.
- **Random AES master key per account → libsodium box keypair per account.** The keypair is the messaging identity and is generated on the client.
- **Server-stored recovery bundle → no recovery bundle.** Parley explicitly does not offer key recovery, so it does not store a second copy of the key material.
- **Password reset/change without re-wrapping → no reset and no recovery by design.** Verified static trace: Jotter's reset endpoint updates only the bcrypt hash at `backend/app/api/v1/auth.py:284`, and `change-password` does the same at `:295-305`; neither re-wraps the master key or updates `encrypted_master_key`/`kdf_salt`. The recovery key is collected and ignored, and `recoverMasterKey` in `frontend/src/crypto/encryption.ts` has no call sites. As a result, login after a reset still authenticates but the client cannot unwrap the old master key, so synced notes become unreadable. This finding was established by static trace and is tracked in the Jotter issue tracker (https://github.com/pratikpatel3076/Jotter/issues). Parley therefore has no reset and no recovery. A future password change would require re-wrapping the private key locally and issuing a new `authSecret` in one atomic client-driven step.
- **One salt and no context labels → independent salts and versioned domain labels.** `wrapKey` uses a random device-only `wrapSalt`; `authSecret` uses the public `"parley/auth/v1"` label plus the username. This prevents cross-protocol key reuse and makes the KDF inputs explicit.
- **PBKDF2 iterations 310,000 → 600,000.** Current OWASP guidance for PBKDF2-HMAC-SHA-256 is 600,000 iterations; Parley uses that count for both `wrapKey` and `authSecret`.
- **Bcrypt over the password → bcrypt over the base64 text of `authSecret`.** The base64 text is 44 ASCII characters, below bcrypt's 72-byte limit; the server never sees a password, and it never hashes the raw decoded bytes.
- **Hardcoded CORS origin list → environment-driven allowlist.** Deployment origins differ from development origins.
- **`create_all` plus swallowed `ALTER TABLE` errors → explicit migrations when schema work starts.** The scaffold keeps `create_all` for the empty dev database but does not treat it as a migration strategy.
- **SQLite/MySQL split → SQLite-first development.** Removes a database service from the first milestone while keeping the async SQLAlchemy API.
- **Not all content encrypted → protocol covers messages only.** Parley does not claim zero-knowledge for fields it does not encrypt.
- **No tests → pytest and vitest placeholders.** Every later change has a place to add a regression test.
- **JWT/Bearer fallback → cookie-only session transport.** Fewer ways to leak a token; CSRF is handled with same-site cookies plus origin checks.
- **Shared `SECRET_KEY` for JWT/Fernet/reset tokens → purpose-specific configuration later.** Parley's scaffold has only JWT signing, and the docs flag key separation before any other use is added.

## Dropped

- **Raw password in signup/login payloads.** The exact weakness described in (b); never send it.
- **Server-side encrypted master key and KDF salt.** Not needed once the private key stays on the device; keeping it would enable offline guessing after a server breach.
- **Recovery key and recovery bundle.** Out of scope by design; no recovery claims.
- **Password reset that does not re-wrap the key.** It destroys access to history; not shipping a misleading flow.
- **Google Sign-In and Google Drive backup.** Third-party identity and token storage are outside a 1:1 messaging MVP.
- **Notes, notebooks, tags, attachments, rich text, tasks, calendar, sharing, web clipper, PWA, and Android shell.** Not messaging features; keeping them would dilute the security review.
- **Offline-first sync queue and conflict resolution.** A message MVP can use REST plus polling; sync conflict semantics are a separate design problem.
- **Fernet-encrypted third-party tokens and SMTP reset email.** No third-party tokens and no email reset in the MVP.
- **JWT in an `Authorization` header fallback.** Cookie-only keeps the token surface smaller.
- **MySQL, `aiomysql`, and the MySQL init script.** SQLite is enough for development and tests; a production database decision is deferred.
- **Hardcoded CORS origins and permissive dev defaults.** Configuration must be explicit per environment.
- **Placeholder `SECRET_KEY` values accepted at boot.** A known placeholder is a de facto fallback secret; Parley rejects it.
- **`create_all`-driven schema upgrades with swallowed errors.** Schema changes need review and a real migration path.
- **Plaintext task/calendar fields presented under a zero-knowledge banner.** Parley scopes its claims to what it actually encrypts.
- **Silent bcrypt 72-byte truncation.** `authSecret` is fixed-length, and its 44-character base64 text is hashed, not raw variable-length password bytes.
- **Unused recovery helpers and dead `master-key` API surface.** Dead security code is a maintenance and audit liability.
