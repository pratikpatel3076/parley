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
- Root `.env.example`, `.gitignore`, `README.md`, and this changelog.

### Security

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
