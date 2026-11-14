# Parley

[![CI](https://github.com/pratikpatel3076/parley/actions/workflows/ci.yml/badge.svg)](https://github.com/pratikpatel3076/parley/actions/workflows/ci.yml)

Parley is a 1:1 end-to-end encrypted messenger built as a portfolio project. The
goal is honest engineering judgment: a small system with a protocol that is
specified, a threat model that says what it does not protect, and code that
matches the claims.

> **Status: Experimental. Not audited. Not for protecting anything that matters.**

**Read the Jotter recon first:** [docs/FROM_JOTTER.md](docs/FROM_JOTTER.md) —
what was reused, what was changed, and the raw-password weakness Parley must not
inherit.

## What it is

Parley lets two people register usernames, generate libsodium box keypairs on
their devices, and exchange messages that the server stores as opaque nonce and
ciphertext. A password is split client-side into a local wrapping key and a
separate authentication secret, so the raw password never goes to the server. A
private key is wrapped with PBKDF2-HMAC-SHA-256 and AES-256-GCM and kept in
IndexedDB; messages are encrypted with `crypto_box_easy`. Contact keys are pinned
on first sight (trust on first use), a changed key blocks sending until the user
compares safety numbers and accepts it, and decrypted messages live only in
memory. It is a working MVP, not a hardened product.

## Security properties

| Property | Status | Notes |
|---|---|---|
| Content end-to-end encrypted | Yes | `crypto_box_easy` with a per-identity keypair. The server stores only nonce and ciphertext. |
| Server stores only ciphertext | Yes, for message bodies | The server also stores account metadata, public keys, timestamps, delivery state, and ciphertext lengths. |
| Password never sent | Yes | The client derives `authSecret` from the password and sends only that to the server, which stores a bcrypt hash. `wrapKey` stays local. |
| Secret key never leaves the device | Yes | The private key is wrapped in IndexedDB and unwrapped only in the session vault. It is never sent to the server or put in browser storage, cookies, URLs, or logs. |
| Key pinning (TOFU) plus safety-number verification | Yes | The first seen key is pinned per owner and contact. A changed key blocks sending and decryption until the user compares both safety numbers and accepts. Verification is a local flag on the pinned contact. |
| Malicious-server powers | Drop, delay, reorder; replays deduplicated | A malicious server can withhold, delay, or reorder messages and can replay rows. The client deduplicates by direction and `client_message_id`, and authenticated envelopes detect swapped or reflected ciphertext. The server cannot read plaintext or forge an authenticated message for a pinned key without the key. |
| Forward secrecy | No | There is one static box keypair per identity. Compromise of the secret key decrypts messages that were encrypted to it. |
| Multi-device | No | There is one wrapped key per username per browser profile. There is no device sync or device list. |
| Recovery | No | Losing the password, the browser profile, or the wrapped key loses the identity. There is no reset that restores history. |
| Metadata visible to the server | Yes | Usernames, public keys, IP addresses, request timing, ciphertext sizes, message timing, and acknowledgement state are visible. |
| Web delivery caveat | Weak | The app host can serve modified JavaScript that reads the unlocked key, and XSS defeats the key-protection model. CSP, security headers, SRI with pinned builds, reproducible builds, and a native client remain roadmap items. |

These are claims about this implementation, not a substitute for review. The
threat model lists the assumptions and residual risks:
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Comparison with Jotter

The reference project and the exact reuse record are in
[docs/FROM_JOTTER.md](docs/FROM_JOTTER.md).

- **Reused:** the browser-side crypto shape (PBKDF2, AES-GCM wrapping, a
  module-level vault), the FastAPI/session layout, and the Docker setup notes.
- **Changed:** Parley separates `authSecret` from `wrapKey` with domain
  separation, never sends the raw password, keeps the wrapped private key on the
  device only, and uses a random device-only KDF salt.
- **Dropped:** Jotter's raw-password signup payload, server-stored wrapped master
  key, non-functional recovery flow, and the entire note-taking domain model.

## Run it locally

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
# .venv\Scripts\activate           # Windows PowerShell
pip install -e ".[dev]"
cp ../.env.example .env            # Windows: Copy-Item ../.env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
# put the generated value in .env as SECRET_KEY
uvicorn app.main:app --reload --port 8000
```

`SECRET_KEY` and `DATABASE_URL` are required. The app raises at startup if either
is missing, blank, or a known placeholder. Only `.env.example` is committed;
`.env` is ignored.

Health check: <http://localhost:8000/health>

The dev database is a SQLite file at `backend/parley.db` (relative to the
directory where `uvicorn` runs). The MVP creates tables with `create_all` and has
no migrations. If you change the schema or want a clean slate, stop the server,
delete that file, and restart.

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

The dev server runs at <http://localhost:5173> and proxies `/api` to
`http://127.0.0.1:8000` while forwarding the browser's `Origin` header
unchanged.

For local development, the backend's `.env` must set `DEBUG=True` and include
`http://localhost:5173` in `ALLOWED_ORIGINS`, for example:

```dotenv
DEBUG=True
ALLOWED_ORIGINS=["http://localhost:5173"]
```

The backend rejects state-changing requests whose `Origin` is missing or not an
exact allowlist match, so a mismatched port or host fails with `403`.

## Testing

Current suites:

- Backend: **151 tests** (`pytest`).
- Frontend: **169 tests** (`vitest`), including crypto, storage, session,
  messaging, auth UI, chat UI, and safety-number verification.

```bash
cd backend && .venv/Scripts/python -m pytest -q   # Windows
cd backend && .venv/bin/python -m pytest -q       # macOS / Linux

cd frontend && npm run typecheck
cd frontend && npm test
cd frontend && npm run build
```

The production build keeps libsodium and the Parley crypto layer in a lazy
chunk, and the password-strength dictionaries in separate lazy chunks. The entry
chunk is under 500 kB; the largest lazy chunk is the zxcvbn word list loaded only
when a password is checked.

## Demo walkthrough

Use two browser profiles (or one normal window and one private window) so each
has its own IndexedDB identity.

1. **Register two users.** In profile A register `alice`, in profile B register
   `bob`. Both passwords stay local; the server sees only the derived
   authentication secret.
2. **Chat both ways.** Open `bob` from alice's conversation box, send a message,
   and open `alice` from bob's side. Polling runs every 5 seconds while the tab is
   visible. Reload a tab to show that no plaintext is cached: history is
   re-fetched and decrypted.
3. **Verify safety numbers.** In alice's header, click **Verify**, read the
   12 groups of 5 digits to bob over a call or in person, and compare. Do the same
   on bob's side; the numbers match. Tick the checkbox and click **Mark as
   verified**. The header badge changes to **Verified**. **Remove verification**
   clears the local flag.
4. **Break the server and retry.** Stop the backend. Send a message; it becomes a
   failed row with a **Retry** button. Start the backend again and click
   **Retry**. The same encrypted payload is sent again, so the server's
   idempotency check cannot create a duplicate.
5. **Force a key change.** In profile B, clear site data and register the same
   username again. Profile A sees a key-change banner with the old and new safety
   numbers, blocks sending, and resets verification. Compare out of band and
   accept only if the new number is expected.

## Limitations and roadmap

Known limits:

- No forward secrecy or post-compromise security.
- No multi-device support, device list, or key recovery.
- No group chat, attachments, disappearing messages, or read receipts.
- No metadata hiding; the server sees who talks to whom and when.
- The server can drop, delay, or reorder messages and can replay rows.
- No protection from a malicious app host serving modified JavaScript.
- Ciphertext sizes leak approximate plaintext sizes.
- No local message cache; a reload re-fetches and decrypts history.
- Delivery ordering can hide a message until the next full sync: pagination uses
  a `(created_at, id)` cursor, so if two sends commit out of order, a message with
  an earlier timestamp can commit after a later row was already fetched and stays
  hidden until a reload.

Roadmap:

- Double ratchet for forward secrecy and post-compromise security.
- Argon2id for password derivation.
- WebSocket delivery with authenticated resume instead of polling.
- CSP and security headers, SRI with pinned builds, and reproducible builds.
- A commit-ordered sequence number as the message cursor instead of
  `(created_at, id)`.
- A native client to remove the web-delivery caveat.
- Database migrations instead of `create_all`.
- Per-user send quotas and abuse controls.
- PostgreSQL validation; SQLite is a development default.
- Key history across key changes so older sent rows remain readable.
- Multi-device support and an explicit recovery design, if either is added.

## Stack

| Layer | Technology |
|---|---|
| Frontend | Vite, React, TypeScript, Tailwind CSS, Zustand |
| Frontend tests | Vitest, Testing Library, jsdom |
| Backend | FastAPI, Python 3.11+, SQLAlchemy async |
| Dev database | SQLite (`sqlite+aiosqlite`) |
| Backend tests | pytest, httpx TestClient |
| Crypto | libsodium-wrappers for messaging; Web Crypto PBKDF2 + AES-256-GCM for private-key wrapping |
| Transport | REST + polling |

## Project layout

```
parley/
├── backend/
│   ├── app/
│   │   ├── api/          HTTP routes
│   │   ├── core/         settings and fail-fast config
│   │   ├── db/           async engine and session dependency
│   │   └── main.py       FastAPI application
│   └── tests/            pytest suite
├── frontend/
│   ├── src/
│   │   ├── api/          typed HTTP client with refresh
│   │   ├── components/   auth screens and chat UI
│   │   ├── crypto/       libsodium/Web Crypto primitives and storage
│   │   ├── messaging/    API shapes, engine, in-memory store
│   │   ├── session/      vault, session store, lazy crypto loader
│   │   ├── App.tsx       auth/chat switching
│   │   └── test/         vitest setup
│   └── vite.config.ts    Vite, Tailwind, and vitest config
├── docs/
│   ├── FROM_JOTTER.md    recon and reuse record
│   ├── PROTOCOL.md       protocol specification
│   └── THREAT_MODEL.md   assets, adversaries, limits
├── .env.example
├── .gitignore
├── CHANGELOG.md
└── README.md
```

## Documentation

- [docs/FROM_JOTTER.md](docs/FROM_JOTTER.md) — exact Jotter key derivation,
  signup/login payloads, auth setup, backend layout, Docker setup, and the
  Reused/Changed/Dropped record.
- [docs/PROTOCOL.md](docs/PROTOCOL.md) — registration, login, private-key
  wrapping, message encryption, key pinning, safety numbers, endpoints, data
  model, and polling transport.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) — assets, adversaries, what the
  server can and cannot see, trust assumptions, and non-goals.

## Security

Parley is experimental and unaudited. Report vulnerabilities through the
private flow described in [SECURITY.md](SECURITY.md); do not open a public issue
for a vulnerability. The known limits are in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## License

Parley is released under the [MIT License](LICENSE).
