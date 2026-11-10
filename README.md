# Parley

Parley is a 1:1 end-to-end encrypted messenger, built as a portfolio project.
The point is honest engineering judgment: a small system with a protocol that is
specified, a threat model that says what it does not protect, and code that
matches the claims.

**Read the Jotter recon first:** [docs/FROM_JOTTER.md](docs/FROM_JOTTER.md) —
what was reused, what was changed, and the raw-password weakness Parley must not
inherit.

> Status: **scaffold + design only.** The backend has a health endpoint, the
> frontend has a blank page, and the protocol in `docs/PROTOCOL.md` is not
> implemented yet. Nothing here is audited or production-ready.

## What it is

Parley is intended to be a browser-based messenger where:

- each identity has a libsodium box keypair generated on the device;
- a password derives two domain-separated secrets: `wrapKey` (stays local, random
  device-only salt) and `authSecret` (sent to the server for bcrypt hashing,
  public username-derived salt);
- the private key is wrapped with `wrapKey` using PBKDF2-HMAC-SHA-256 (600,000
  iterations) and AES-256-GCM, and stored only in IndexedDB;
- messages are encrypted with `crypto_box_easy` and stored by the server as
  opaque base64 nonce + ciphertext;
- contacts' public keys are pinned on first contact, and a changed key blocks
  sending until the user acknowledges it;
- a safety number derived from both public keys can be compared out of band.

## What it guarantees (design target; see status above)

When the protocol is implemented as specified:

- The server never receives the raw password, `wrapKey`, or the private key.
- The server cannot read message plaintext from what it stores.
- A modified ciphertext fails authenticated decryption.
- A changed contact key is surfaced instead of silently trusted.
- The server does not store a wrapped copy of the private key, so a server
  database leak alone does not provide an offline-guessable key file.

These are claims about the design, not a substitute for review. The threat model
lists the assumptions and residual risks.

## What it does NOT do

No forward secrecy. No post-compromise security. No deniability. No metadata
hiding. No multi-device support. No group chat. No key recovery. No password
reset that restores history. No protection from a malicious server that serves
modified JavaScript. Key pinning is trust-on-first-use, not identity
verification. Messages are not padded, so ciphertext sizes leak approximate
plaintext sizes. See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full
list and [docs/PROTOCOL.md](docs/PROTOCOL.md) section 14 for deferred work.

## Stack

| Layer | Technology |
|---|---|
| Frontend | Vite, React, TypeScript, Tailwind CSS, Zustand |
| Frontend tests | Vitest, Testing Library, jsdom |
| Backend | FastAPI, Python 3.11+, SQLAlchemy async |
| Dev database | SQLite (`sqlite+aiosqlite`) |
| Backend tests | pytest, httpx TestClient |
| Crypto (planned) | libsodium-wrappers for messaging; Web Crypto PBKDF2 + AES-256-GCM for private-key wrapping |
| Transport (planned) | REST + polling |

The scaffold does not install crypto libraries it does not use yet. They are
added with the protocol implementation.

## Quickstart

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

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The dev server runs at <http://localhost:5173> and proxies `/api` to
`http://localhost:8000`. The page is a placeholder until the protocol is
implemented.

### Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q   # Windows
cd backend && .venv/bin/python -m pytest -q       # macOS / Linux

cd frontend && npm test
```

## Project layout

```
parley/
├── backend/
│   ├── app/
│   │   ├── api/          HTTP routes (health for now)
│   │   ├── core/         settings and fail-fast config
│   │   ├── db/           async engine and session dependency
│   │   └── main.py       FastAPI application
│   └── tests/            pytest placeholder and config tests
├── frontend/
│   ├── src/
│   │   ├── App.tsx       placeholder page
│   │   ├── stores/       Zustand store
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

## Status

| Milestone | Status |
|---|---|
| Jotter recon and reuse record | Done |
| Threat model and protocol spec | Done |
| Monorepo scaffold with health endpoint and placeholder tests | Done |
| Registration, login, and local key wrapping | Planned |
| 1:1 message send/receive with libsodium | Planned |
| Contact pinning and safety numbers | Planned |
| End-to-end protocol tests | Planned |
| Docker packaging | Deferred until there is something to package |

## License

No license has been chosen yet. This is a portfolio project; do not deploy it
for sensitive communication.
