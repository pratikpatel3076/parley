# Security Policy

Parley is an experimental, unaudited portfolio project. It is not ready to
protect sensitive communication, and no part of it has received an independent
security review.

## Supported versions

Only the latest commit on `main` is supported. There are no maintained release
branches and no backports.

## Reporting a vulnerability

Report vulnerabilities privately with GitHub's "Report a vulnerability" button
on this repository's Security tab (private vulnerability reporting):

<https://github.com/pratikpatel3076/parley/security/advisories/new>

Do not open a public issue for a vulnerability. Public issues are for ordinary
bugs and feature requests only.

This project is maintained on a best-effort basis. There is no response-time
promise, no bug bounty, and no guaranteed fix timeline.

## Known limitations

The threat model documents what Parley does and does not protect:
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). It covers, among other limits, the
absence of forward secrecy, no multi-device support, no recovery, metadata
visible to the server, the malicious-app-host caveat, and the experimental and
unaudited status of the implementation.
