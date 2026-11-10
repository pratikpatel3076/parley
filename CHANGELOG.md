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
- Root `.env.example`, `.gitignore`, `README.md`, and this changelog.

### Security

- Parley's design does not send the raw password or a server-stored wrapped
  private key, which removes the critical weakness identified in Jotter.
- Empty, short, or placeholder `SECRET_KEY` values are rejected at startup.
