# Changelog

All notable changes to Parley are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and commits follow
[Conventional Commits](https://www.conventionalcommits.org/).

## [Unreleased]

### Added

- Read-only recon of the Jotter reference project, including exact key
  derivation, signup/login payloads, auth/session setup, FastAPI layout, Docker
  setup, and a Reused/Changed/Dropped record in `docs/FROM_JOTTER.md`.
- Threat model covering assets, adversaries, server visibility, trust
  assumptions, and explicit non-goals in `docs/THREAT_MODEL.md`.
- Protocol specification for registration, key wrapping, login, 1:1 messages,
  key pinning, safety numbers, REST/polling transport, endpoints, and the server
  data model in `docs/PROTOCOL.md`.
- Monorepo scaffold: FastAPI backend with a health endpoint and fail-fast
  settings, Vite/React/TypeScript/Tailwind/Zustand frontend with a placeholder
  page, and pytest/vitest placeholder tests.
- Typed API client with cookie credentials, single-flight refresh across tabs,
  bounded retry, and safe errors in `frontend/src/api/client.ts`.
- In-memory session vault, Zustand session store, test-only KDF work-factor
  override, and lazy libsodium loading in `frontend/src/session/`.
- Register, login, and logout screens with inline username validation, a live
  strength meter, the no-recovery acknowledgement, local key unwrapping before
  login, and safe errors.
- Typed messaging API client for send, inbox, sent, and acknowledgement
  endpoints, including strict response parsing and bounded cursor pagination in
  `frontend/src/messaging/api.ts`.
- Message engine with 5-second visibility-aware polling, exponential backoff to
  60 seconds, decryption and deduplication, at-least-once acknowledgement, and
  retry-safe sends that reuse one encrypted payload per `client_message_id`.
- Chat UI with a conversation list, plain-text message view, composer with a
  60,000-byte limit, failed-send retry, and an explicit key-change banner that
  shows both safety numbers and blocks sending until acknowledged.
- Safety-number verification panel: a 12-group number computed from the locally
  pinned contact key, both usernames, plain instructions, a required
  acknowledgement checkbox, mark/remove actions, and a persisted
  Verified/Unverified header badge.
- Root `.env.example`, `.gitignore`, `README.md`, and this changelog.

### Changed

- The engine acknowledges an inbox row only after it decrypts and is stored.
  Error rows and rows from a blocked peer stay unacknowledged, so accepting a
  changed key can re-sync and process them normally.
- The sync cursor never moves backwards when a poll returns an empty page. The
  client keeps a stored non-null cursor instead of overwriting it with `null`,
  and the backend echoes the supplied cursor on an empty page.
- libsodium and the Parley crypto layer load lazily instead of being pulled into
  the entry chunk. The engine receives crypto functions through `EngineDeps` and
  the existing `cryptoLoader`.
- README now documents the security-properties table, a two-profile demo
  walkthrough, the test commands, and an honest limitations/roadmap list.
- `docs/PROTOCOL.md` and `docs/THREAT_MODEL.md` describe the acknowledgement
  policy, cursor stability, and the local semantics of verification.

### Fixed

- Acknowledging a message before decrypting it could mark tampered, reflected,
  invalid, or blocked-peer rows as delivered and hide them from a later
  re-sync.
- Reaching the end of history could reset the next poll to the start of the
  conversation, causing repeated decryption and acknowledgement work.
- The production build no longer emits an `INEFFECTIVE_DYNAMIC_IMPORT` warning
  for the crypto layer.

### Security

- Decrypted messages are held only in an in-memory store and are cleared on
  lock, logout, and engine stop. There is no local message cache, and message
  bodies are rendered as plain text, never as HTML.
- Safety-number verification reads the pinned contact key from IndexedDB, not
  the server-presented key, and a key change resets the local verified flag.
- Documented the web-delivery trust limit in `docs/THREAT_MODEL.md`: a malicious
  or compromised app host can serve code that reads the unlocked key, XSS
  defeats the key-protection model, and native clients, SRI with pinned builds,
  reproducible builds, and a CSP remain roadmap items.
- The unlocked secret key lives only in a module-level variable in
  `frontend/src/session/vault.ts`; passwords and key material are never kept in
  Zustand, browser storage, cookies, the URL, or logs.
- Parley's design does not send the raw password or a server-stored wrapped
  private key, which removes the critical weakness identified in Jotter.
- Empty, short, or placeholder `SECRET_KEY` values are rejected at startup.
