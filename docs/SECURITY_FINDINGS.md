# Security Findings Log

This is a factual record of weaknesses found and fixed while building Parley. It
is not a third-party audit. Each entry states what was wrong, how it was found,
the fix, the commit, and the tests that pin the behavior. Commit hashes were
checked with `git show --stat <hash>` against this repository.

The protocol and its limits are in [PROTOCOL.md](PROTOCOL.md) and
[THREAT_MODEL.md](THREAT_MODEL.md). The Jotter comparison is in
[FROM_JOTTER.md](FROM_JOTTER.md). The unresolved limits are listed at the end.

---

## 1. Jotter's raw-password design, and Parley's split `authSecret` / `wrapKey`

**What was wrong.** The reference project at `../Jotter-ref` sent the raw
password to the server at signup and login, together with the wrapped master key
and the PBKDF2 salt. A server operator, a request-body log, or a reverse proxy
could derive `wrapKey` from the password and salt, unwrap the master key, and
decrypt synced notes. The zero-knowledge claim depended on the server choosing
not to use data it had already received. See `docs/FROM_JOTTER.md`, "Verdict:
yes, the server receives the raw password".

**How it was found.** Read-only code review and trace of the Jotter frontend and
backend, recorded in `docs/FROM_JOTTER.md`. The signup/login payloads, the
server-side storage of `encrypted_master_key` and `kdf_salt`, and the reset flow
were traced to their call sites.

**Fix.** Parley derives two domain-separated values on the device:

- `wrapKey`, from the password and a random device-only `wrapSalt`; it wraps the
  private key and never leaves the device.
- `authSecret`, from the password and a public username-derived salt; only
  `authSecret` is sent to the server, which bcrypt-hashes its base64 text.

The server never receives the password, `wrapKey`, the wrapped private key, or
the device salt. A server-database compromise therefore does not expose a
wrapped key to guess against.

**Commit.** `9d9a2f1` (`feat(crypto): keypair, wrapping, envelope messages,
safety numbers`). The recon is `7cb235e` (`docs: Jotter recon and design docs`);
the residual-risk wording was corrected in `bc9688a`.

**Tests.** `frontend/src/crypto/crypto.test.ts`:
`is deterministic and decodes to exactly 32 bytes`,
`changes with the username and with the password`,
`never stores the password or the auth secret in the blob`,
`unwraps with the right password`, and
`throws WrongPasswordError on a wrong password`.
`backend/tests/test_messages.py::test_database_never_stores_raw_password_or_auth_secret`.

---

## 2. PBKDF2 iteration count: 310,000 to 600,000

**What was wrong.** The initial design material carried Jotter's 310,000
PBKDF2-HMAC-SHA-256 iterations. That was below the current OWASP guidance of
600,000 for PBKDF2-HMAC-SHA-256 and made offline guessing cheaper.

**How it was found.** Code and document review against the OWASP Password
Storage Cheat Sheet while specifying the KDF table.

**Fix.** Both `wrapKey` and `authSecret` use 600,000 iterations. The protocol
table, the derivation pseudocode, the threat model, and the Jotter comparison
were corrected to match the implementation.

**Commit.** `9d9a2f1` implemented 600,000 in
`frontend/src/crypto/constants.ts`; `bc9688a` (`docs: correct residual risk, KDF
cost, username rules, Jotter reset finding`) corrected the documents.

**Tests.** `frontend/src/crypto/crypto.test.ts::uses 600,000 PBKDF2 iterations
by default`.

---

## 3. Corrected residual-risk statement for offline guessing

**What was wrong.** An earlier statement said an attacker needed both the
client's IndexedDB wrapped-key record and the server's bcrypt hash to guess the
password. That understated the server-only risk. Because the `authSecret` salt
is derived from the public username, the stored `bcrypt(authSecret)` hash plus
the username is enough to test password guesses offline. Recovering
`authSecret` lets an attacker authenticate as the user. It does **not** decrypt
messages, which additionally requires the device-only wrapped-key record.

**How it was found.** Review of the threat model against the actual derivation
inputs in `frontend/src/crypto/derive.ts` and the server storage in
`backend/app/api/routes/auth.py`.

**Fix.** `docs/THREAT_MODEL.md`, `docs/FROM_JOTTER.md`, `docs/PROTOCOL.md`, and
the README now state the boundary precisely: server-database compromise permits
offline password guessing but not message decryption; device-blob compromise
plus a guessed password permits decryption. The client enforces zxcvbn score
>= 3 and the KDF cost is 600,000 iterations; neither makes a weak or reused
password safe.

**Commit.** `bc9688a`.

**Tests.** This is a documentation correction, so no test asserts the wording.
The storage claim it relies on is exercised by
`backend/tests/test_messages.py::test_database_never_stores_raw_password_or_auth_secret`,
and the KDF cost by
`frontend/src/crypto/crypto.test.ts::uses 600,000 PBKDF2 iterations by default`.

---

## 4. Sender/recipient reflection attack and envelope binding

**What was wrong.** The authenticated inner envelope originally bound only the
client message id. `crypto_box` is symmetric, so a malicious server could
reflect a message back to its sender or redirect it to a third party. The
client could decrypt it because the box key pair still matched, and the inner id
alone did not prove who the sender or intended recipient was.

**How it was found.** Protocol review of the envelope shape and a trace of the
`sender secret + recipient public` / `recipient secret + sender public` symmetry
in `crypto_box_easy` and `crypto_box_open_easy`.

**Fix.** The envelope now carries `from` and `to` (the sender and recipient
32-byte public keys). After decryption the client requires both to match the
keys it used for the box: `from` must equal the pinned sender key and `to` must
equal the caller's own public key. Comparisons are over decoded bytes, not
strings. `encryptMessage` also verifies that `senderPublicKey` matches the
secret key before encrypting. Any mismatch is `EnvelopeMismatchError`.

**Commit.** `82a6559` (`fix(crypto): bind sender and recipient keys into the
message envelope`).

**Tests.** `frontend/src/crypto/crypto.test.ts`:
`rejects Bob sent message reflected back as received from Alice`,
`rejects Alice message reflected back to Alice as from Bob`,
`throws DecryptionError when redirected to a third user`,
`rejects a wrong envelope recipient`, `rejects a wrong envelope sender`,
`rejects decryptSent on a message that was actually received`,
`rejects a senderPublicKey that does not match the secret key`, and
`throws EnvelopeMismatchError when the inner and outer ids differ`.
`frontend/src/messaging/engine.test.ts::shows an error row for tampered and
reflected ciphertext`.

---

## 5. Refresh/logout: global revocation on replay, and non-atomic rotation

**What was wrong.** Two related problems in the refresh flow:

1. Any revoked refresh token was treated as theft. Replaying a token that had
   been revoked by **logout** therefore revoked every live session for the user,
   including sessions on other devices. A stale tab could log the user out
   everywhere.
2. Rotation was read-then-write: two concurrent refreshes could both observe an
   unrevoked row and both mint replacement sessions, so the single-use property
   was not enforced atomically.

**How it was found.** Trace of the refresh endpoint against the session table,
and a concurrency test with two independent clients. The logout-replay case was
found by replaying a logged-out token while a second session was live.

**Fix.** Sessions now record `revoked_reason` (`rotated`, `logout`,
`reuse_detected`, `expired`, `user_deleted`) and `rotated_at`. Only a `rotated`
token replayed outside the grace window triggers global revocation. A `logout`
or `expired` token is rejected without touching other sessions. Rotation uses a
conditional `UPDATE ... WHERE id = ? AND revoked = false` and checks
`rowcount`; exactly one concurrent request wins, and losers re-read the row and
follow the replay rules. SQLite gets a 5-second busy timeout so the losing
request fails cleanly instead of raising "database is locked". The access-token
dependency already re-checks the session row on every authenticated request, so
a revoked session is rejected immediately; `497d96a` added regression tests for
that property.

**Commit.** `7a3733e` (`fix(backend): distinguish rotation, logout, and reuse in
refresh sessions`); `497d96a` (`fix(backend): require a live session for every
authenticated request`) adds the liveness regression tests; `4673ade` also makes
logout idempotent and revokes a refresh session even when the access cookie is
missing or expired.

**Tests.** `backend/tests/test_session_state.py`:
`test_logout_then_old_refresh_replay_leaves_other_session_alive`,
`test_rotated_replay_after_grace_revokes_every_live_session`,
`test_rotated_replay_within_grace_keeps_the_replacement`,
`test_expired_refresh_does_not_revoke_other_sessions`,
`test_refresh_401_paths_clear_cookies`, and
`test_concurrent_refresh_rotates_exactly_once`.
`backend/tests/test_access_liveness.py`:
`test_access_token_is_rejected_immediately_after_logout`,
`test_access_token_is_rejected_after_global_revocation`,
`test_access_token_is_rejected_after_session_expiry`,
`test_access_token_is_rejected_after_user_deletion`, and
`test_session_removal_invalidates_an_otherwise_valid_access_token`.
`backend/tests/test_auth.py::test_refresh_rotates_and_immediate_reuse_is_rejected`.

---

## 6. Registration deleted the only local key after a possible server success

**What was wrong.** The register form generated and saved the device keypair
before calling the server. On **any** failure after saving, it deleted the local
key. If the request reached the server and the account was created but the
response was lost (network error, timeout, 5xx), the client deleted the only
copy of the private key. The server then held a public key whose private half no
longer existed, and the account could not be used.

**How it was found.** Trace of the register error paths and a test that made
`fetch` reject after the request was sent.

**Fix.** The form distinguishes definitive failures (no request sent, or a
400/409/413/422/429 refusal) from possible success (network error, timeout, 5xx,
or a failure after a response). It deletes the local key only for definitive
failures. On possible success it keeps the key and tells the user to try logging
in. It also refuses to unlock when a 201 reports a different public key or
username. An explicit local-only "remove this device's key" action was added
for the case where the user wants to start over.

**Commit.** `5ff43a8` (`fix(ui): never delete a local key once the server may
have created the account`).

**Tests.** `frontend/src/components/AuthFlow.test.tsx`:
`keeps the local identity after a network error`,
`keeps the local identity when a 201 reports a different key`,
`keeps the local identity when a 201 reports a different username`,
`deletes the local identity it created when registration fails`,
`deletes the local identity after a definitive 422`, and
`refuses to overwrite an existing local identity`.

---

## 7. Acking undecryptable or blocked messages, and ack failure creating an error row

**What was wrong.** Two bugs in inbox ingestion:

1. The engine acknowledged an inbox row even when decryption failed or the peer
   key was blocked. Acknowledging removes the row from the server inbox, so a
   tampered row was lost and a row from a blocked peer could not be re-synced
   after the user accepted the new key.
2. The acknowledgement call sat inside the same `try` block as decryption and
   storage. If the ack failed after its retries, the `catch` created an error row
   for a message that had already decrypted and was displayed, potentially
   replacing the message.

**How it was found.** Trace of `ingestInbox` and tests that injected tampered
ciphertext, a blocked peer key, and a failing ack endpoint.

**Fix.** `ingestInbox` sets `stored = true` only after decryption and storage
succeed, then acknowledges outside the `try`/`catch` and only when `stored` is
true. Error rows and blocked-peer rows stay unacknowledged so a later sync can
process them after the user accepts a changed key. A failed ack is queued in
`pendingAcks` for the next pass and never adds or replaces an error row.

**Commit.** `340c7ec` (`fix(frontend): ack only after a successful decrypt`) and
`7fa9292` (`fix(frontend): an ack failure must never turn a decrypted message
into an error row`).

**Tests.** `frontend/src/messaging/engine.test.ts`:
`shows an error row for tampered and reflected ciphertext`,
`blocks decryption and sending until the new key is acknowledged`, and
`retries a failed ack on the next pass without hiding the message` (strengthened
in `7fa9292` to assert one message row, no error row, and the queued ack).

---

## 8. Origin validation hardened to exact matching; missing and null rejected

**What was wrong.** State-changing requests must be protected against
cross-site requests. A prefix, suffix, substring, or wildcard comparison would
accept look-alike origins such as `https://testserver.evil.test`, and a missing
`Origin` header or the literal `null` must never be treated as allowed. The
allowlist configuration was also under-validated: uppercase hosts and some
malformed entries could be accepted at startup.

**How it was found.** Code review of the middleware and the settings validator,
plus negative tests for missing, `null`, suffix, prefix, different-port, and
trailing-slash origins.

**Fix.** The middleware compares the `Origin` header by exact whole-string
membership in `ALLOWED_ORIGINS`; missing and `null` are not in the list, so both
return `403`. Startup validation now requires an exact lowercase
`scheme://host[:port]` origin, rejects wildcards, the literal `null`,
whitespace, paths, queries, fragments, userinfo, invalid ports, and `http://`
outside `DEBUG=True` on localhost/127.0.0.1. GET requests do not require an
Origin; every state-changing method does.

**Commit.** `62d1334` added the exact-match middleware; `4673ade` (`fix(backend):
strict Origin validation and idempotent logout`) added the regression tests;
`83d8534` (`fix(backend): validate ALLOWED_ORIGINS at startup`) hardened the
allowlist validation.

**Tests.** `backend/tests/test_auth.py`:
`test_disallowed_origin_on_post_returns_403`,
`test_origin_requires_an_exact_allowlist_match` (parametrized with `None`,
`"null"`, `https://testserver.evil.test`, `https://eviltestserver`,
`http://testserver`, `https://testserver:8443`, `https://testserver/`, and
`https://testserver:443`), `test_exact_origin_match_is_accepted`,
`test_get_requests_do_not_require_an_origin`,
`test_origin_is_still_required_for_logout`, and
`test_origin_check_covers_non_auth_state_changes`.
`backend/tests/test_config.py`:
`test_settings_reject_wildcard_origin`,
`test_settings_reject_origin_with_a_path`,
`test_settings_reject_origin_with_trailing_slash`,
`test_settings_reject_malformed_origins`,
`test_settings_reject_http_origins_outside_debug`, and
`test_settings_accept_http_localhost_in_debug`.

---

## 9. Idempotent send via `client_message_id`

**What was wrong.** A send that timed out could be retried by the user or the
client, and the server had no way to tell a retry from a new message. That could
create duplicate rows for one logical send.

**How it was found.** Trace of the retry path after a timeout and a review of
the send endpoint, which had no idempotency key.

**Fix.** The client generates a UUIDv4 `client_message_id` and reuses the exact
same nonce and ciphertext for every retry. The server stores
`(sender_id, client_message_id)` under a unique constraint. A replay with the
same recipient, nonce, and ciphertext returns the original row with `200`
instead of creating a second row; a reused id with a different payload returns
`409`; a concurrent insert that loses the unique constraint re-reads the winner
and applies the same rule. Different senders may reuse the same id.

**Commit.** `56accbe` (`feat(backend): idempotent message send via
client_message_id`).

**Tests.** `backend/tests/test_messages.py`:
`test_retrying_the_same_send_returns_the_original_message`,
`test_reused_client_message_id_with_different_payload_is_409`,
`test_different_senders_may_reuse_the_same_client_message_id`,
`test_invalid_client_message_id_is_rejected`, and
`test_missing_client_message_id_is_rejected`.
`frontend/src/messaging/engine.test.ts`:
`retries with a byte-identical payload and encrypts once`,
`manually retries the same payload after network retries run out`, and
`reconciles a timed-out send with the sent history row`.

---

## 10. The unverified-before-first-contact limitation of key pinning

**What was wrong.** Key pinning is trust on first use. Before the first contact
there is no pin, so the client fetches the key from the server and pins it. A
malicious server can substitute a key at that moment. The client cannot detect
the substitution until the user compares safety numbers out of band. Earlier UI
also had no explicit verification state, so a pinned key could be mistaken for a
verified one.

**How it was found.** Protocol review of the pinning flow and the threat model,
followed by a UI review of how the pinned key and its verification flag were
presented.

**Fix.** The pin now carries an explicit `verified: false` on first sight. The
chat header shows `Unverified` until the user opens the verification panel,
compares the 12-group safety number computed from the **pinned** key (never the
key the server presents on that request), ticks the acknowledgement, and clicks
**Mark as verified**. A key change blocks sending and decryption, shows both
safety numbers, and resets verification when the user accepts the new key.
Verification is a local flag; it is not sent to the server and is not synced.

This fix makes the limitation visible and gives the user a way to authenticate
the key after first contact. It does **not** remove the first-contact risk. TOFU
is change detection, not authentication.

**Commit.** `bfcb147` (`feat(ui): safety number verification`). The limitation
is stated in `931e4b6` (`docs: security properties table, demo walkthrough,
limits`) and in `docs/THREAT_MODEL.md`.

**Tests.** `frontend/src/components/Verification.test.tsx`:
`shows the same number for alice about bob and bob about alice`,
`requires the checkbox before marking a contact verified`,
`persists verification across a messaging store reset`,
`uses the pinned key even when the server presents a different key`,
`resets verification and changes the number after a key change is accepted`, and
`removes verification through the crypto layer`.
`frontend/src/crypto/crypto.test.ts`:
`pins on first sight and accepts the same key again`,
`throws KeyChangedError when the pinned key changes`,
`acknowledgeKeyChange replaces the pin and resets verified`, and
`refuses to verify an unknown contact`.

---

## Known unresolved

These are known limits of the current implementation, not fixed findings. They
are also listed in the README and the threat model.

- **Delivery ordering.** Pagination uses a `(created_at, id)` cursor. If two
  sends commit out of order, a message with an earlier timestamp can commit after
  a later row was fetched and stay hidden until a reload. The planned fix is a
  commit-ordered sequence number. See `README.md`, "Limitations and roadmap".
- **Trust on first use.** First-contact key substitution by a malicious server
  is possible; safety numbers mitigate it only after out-of-band verification.
  See `docs/THREAT_MODEL.md`, "Residual risks and open questions".
- **Web delivery of the client.** The app host can serve modified JavaScript
  that reads the unlocked key, and XSS defeats the key-protection model. CSP,
  security headers, SRI with pinned builds, reproducible builds, and a native
  client remain roadmap items.
- **No forward secrecy.** There is one static box keypair per identity. A
  compromised secret key decrypts messages encrypted to it. A double ratchet is
  a roadmap item.
- **No multi-device support.** There is one wrapped key per username per browser
  profile. There is no device list or sync.
- **No key history.** Accepting a changed key can make sent messages encrypted
  under the old key unreadable; the client shows an error rather than silently
  dropping them.
- **Per-process rate limiting.** Registration and login limiting is in process,
  per worker, and not shared across processes.
- **SQLite only in practice.** SQLite is the development and test database. The
  session-rotation and cursor behavior have not been validated against
  PostgreSQL.
- **No third-party audit.** Parley is an experimental portfolio project. This
  log and the threat model are not a substitute for an external review.
