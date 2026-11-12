# Parley Protocol (MVP)

Status: the backend MVP implements the server side of sections 3.2, 5, 6.1,
8.2-8.5, and 9, with the backend deviations listed in section 16. The frontend
implements the client crypto layer in `frontend/src/crypto/`, the register,
login, and logout flows (sections 3.1, 4, 6, 7, and 8.1 for authentication), and
the 1:1 messaging client: typed API calls, polling, decryption, deduplication,
retry-safe sending, key-change blocking, and the chat UI in
`frontend/src/messaging/` and `frontend/src/components/chat/`. There is no local
message cache; decrypted history lives in memory only and is cleared on lock or
logout. This document is the contract the implementation must satisfy. Security
claims and limits are in [THREAT_MODEL.md](THREAT_MODEL.md).

Protocol version: `1`.

## 1. Goals and non-goals

Parley provides 1:1 end-to-end encrypted messaging with:

- a libsodium box keypair per identity;
- a password that unwraps the private key only on the device;
- a separate password-derived authentication secret for the server;
- opaque ciphertext storage;
- key pinning on first contact and a visible safety number.

Parley explicitly does **not** provide forward secrecy, deniability, metadata
hiding, multi-device support, key recovery, group chat, or protection from a
server that serves modified client code. See section 14.

## 2. Cryptographic primitives

All binary values in JSON use standard base64: the RFC 4648 section 4 alphabet
(`A-Z`, `a-z`, `0-9`, `+`, `/`) with mandatory `=` padding. A decoder must be
strict:

- Accept only the 64 standard alphabet characters and `=` padding.
- Reject whitespace (spaces, tabs, newlines), the URL-safe alphabet (`-`, `_`),
  missing padding, extra padding, characters outside the alphabet, and any
  length that is not a whole number of four-character groups.
- Reject non-canonical trailing bits (for example `TR==` for the one-byte value
  `4d`, or `TWF=` for the two-byte value `4d 61`). The reliable test is to
  decode, then re-encode, and require the result to equal the input text
  byte-for-byte.
- The empty string is the canonical encoding of zero bytes. Callers that need a
  fixed length still reject it after decoding.

This matches the backend's `decode_canonical_base64` helper, which calls
`base64.b64decode(value, validate=True)` and then requires
`base64.b64encode(raw).decode("ascii") == value`. The server treats `nonce` and
`ciphertext` as opaque bytes and never decrypts them.

| Purpose | Primitive | Implementation |
|---|---|---|
| Message encryption | `crypto_box_easy` (X25519 + XSalsa20-Poly1305) | `libsodium-wrappers` |
| Message decryption | `crypto_box_open_easy` | `libsodium-wrappers` |
| Identity keypair | `crypto_box_keypair` (X25519) | `libsodium-wrappers` |
| Safety number digest | BLAKE2b-512 (`crypto_generichash`, 64 bytes) | `libsodium-wrappers` |
| Private-key wrapping key | PBKDF2-HMAC-SHA-256, 600,000 iterations, 32-byte output | Web Crypto |
| Auth secret | PBKDF2-HMAC-SHA-256, 600,000 iterations, public username salt | Web Crypto |
| Private-key wrapping | AES-256-GCM, 12-byte IV, 16-byte tag | Web Crypto |
| Auth-secret KDF salt | public `UTF-8("parley/auth/v1:" + username)` | Client |
| Private-key KDF salt | `UTF-8("parley/wrap/v1:") \|\| random 16-byte salt` | Client |
| Private-key wrapping AAD | `UTF-8("parley/wrap/v1") \|\| publicKey` | Client |
| Server auth hash | bcrypt cost 12 over the base64 text of `authSecret` (44 ASCII characters) | Server library |
| Session access token | JWT HS256, 15 minutes | Server library |
| Refresh token | 32 random bytes, stored only as SHA-256 hash | Server library + CSPRNG |

There are no custom cryptographic constructions. Web Crypto is used only for
PBKDF2 and AES-256-GCM key wrapping; message encryption and safety numbers use
libsodium. Random values come from `sodium.randombytes_buf` where libsodium is
already required, and from `crypto.getRandomValues` otherwise.

Usernames are lowercase ASCII only and match `^[a-z0-9_]{3,32}$`. They are not
case-folded and not Unicode-normalized: mixed case or non-ASCII input is
rejected, not normalized into a different name. This removes normalization
ambiguity from the public identity and from the `authSecret` salt. Passwords are
normalized to Unicode NFKC and encoded as UTF-8 before every password-based
derivation; NFKC makes composed and decomposed forms of the same visual password
produce the same secret. The client applies NFKC in both the auth-secret and
wrapped-key paths.

`authSecret` is derived with a public salt:
`UTF-8("parley/auth/v1:" + username)`. No random `authSalt` is generated
or stored. Because the salt is public, an attacker who obtains the stored
bcrypt hash can test password guesses offline without the device; the device-only
wrapped key still prevents message decryption. See
[THREAT_MODEL.md](THREAT_MODEL.md), "Offline guessing boundary".

The server bcrypt-hashes the base64 text of `authSecret`, which is 44 ASCII
characters and therefore below bcrypt's 72-byte input limit. It never hashes or
stores the raw 32 decoded bytes, and it never receives the password.

## 3. Identity registration

### 3.1 Client-side steps

1. Await `sodium.ready`.
2. Generate the box keypair:
   ```
   (publicKey, secretKey) = crypto_box_keypair()   // 32 bytes each
   ```
3. Generate one random salt for local key wrapping:
   ```
   wrapSalt = randombytes_buf(16)   // never leaves the device
   ```
   `authSecret` does not get a random salt. Its salt is public and derived from
   the username in step 5.
4. Normalize the password to NFKC and encode it as UTF-8.
5. Derive two independent 32-byte secrets with different salts **and**
   different domain labels:
   ```
   wrapKey     = PBKDF2-SHA-256(NFKC(password),
                                "parley/wrap/v1:" || wrapSalt,
                                600000, 32)
   authSecret  = PBKDF2-SHA-256(NFKC(password),
                                "parley/auth/v1:" || username,
                                600000, 32)
   ```
   The ASCII label plus a colon is part of the PBKDF2 salt input. The wrap salt
   stays on the device; the auth salt is reproducible from the public username.
6. Import `wrapKey` as an AES-256-GCM key with `encrypt`/`decrypt` usages. Keep
   `wrapKey` in memory only.
7. Generate a 12-byte AES-GCM IV and wrap the raw `secretKey`:
   ```
   aad        = UTF-8("parley/wrap/v1") || publicKey
   wrapped    = AES-256-GCM-Encrypt(wrapKey, iv, aad, secretKey)
   ```
   The public key, not the username, is bound into the AAD so the blob cannot be
   moved to another identity. The stored blob records `v`, `kdf`, `iterations`,
   `salt`, `iv`, and `ciphertext`.
8. Store the identity record **only in IndexedDB** (section 4).
9. Register with the server (section 3.2). `authSecret` and `publicKey` are sent;
   `wrapKey`, `secretKey`, `wrapped`, and `wrapSalt` are not.

The `wrapKey` must never be written to IndexedDB, localStorage, a cookie, a log,
or the network.

### 3.2 `POST /api/v1/auth/register`

Request:

```json
{
  "username": "alice",
  "authSecret": "<base64 of 32-byte authSecret>",
  "publicKey": "<base64 of 32-byte publicKey>"
}
```

Server behavior:

1. Validate the username format and uniqueness.
2. Validate that `authSecret` and `publicKey` are canonical base64 decoding to
   exactly 32 bytes each.
3. bcrypt-hash the base64 text of `authSecret` (`authSecret` is exactly 44 ASCII
   characters) with cost 12 and store only the hash. Never store or log the raw
   value.
4. Store `publicKey`. Do not store an auth salt, `wrapSalt`, `wrapKey`,
   `secretKey`, or any wrapped private-key record.
5. Create a session (section 5) and set the auth cookies.
6. Return `201`:

```json
{
  "user": {
    "id": "<uuid>",
    "username": "alice",
    "public_key": "<base64>",
    "created_at": "2026-01-01T00:00:00Z"
  }
}
```

Errors: `422` invalid input, `409` username taken, `429` rate limited. The
registration response intentionally reveals whether a username is available;
that is unavoidable for a public username registry.

The local identity record should be persisted before or atomically with a
successful registration response. If the server succeeds but the browser cannot
persist the record (for example, storage is full), the client must tell the user
that the account has no usable local key. Parley cannot recover it.

## 4. Private-key storage and unlock

The only persisted copy of the private key is this IndexedDB record, in database
`parley`, object store `identity`, keyed by `username`:

```json
{
  "username": "alice",
  "publicKey": "<base64 32 bytes>",
  "wrapped": {
    "v": 1,
    "kdf": "pbkdf2-sha256",
    "iterations": 600000,
    "salt": "<base64 16 random bytes>",
    "iv": "<base64 12 bytes>",
    "ciphertext": "<base64 AES-256-GCM ciphertext || 16-byte tag>"
  }
}
```

`wrapped.ciphertext` is 48 bytes: 32 bytes of encrypted key plus the 16-byte
GCM tag. The AAD is `UTF-8("parley/wrap/v1") || publicKey`, which binds the
blob to that identity's public key. The random `salt` is combined with the
`"parley/wrap/v1:"` label to form the PBKDF2 salt.

Before deriving a key or running PBKDF2, the client validates the stored blob
and rejects it with `InvalidInputError` when any of these bounds fails:

| Field | Required value |
|---|---|
| `v` | exactly `1` |
| `kdf` | exactly `"pbkdf2-sha256"` |
| `iterations` | an integer in `[1, 10_000_000]` |
| `salt` | canonical base64 decoding to exactly 16 bytes |
| `iv` | canonical base64 decoding to exactly 12 bytes |
| `ciphertext` | canonical base64 decoding to exactly 48 bytes |

All six checks run before the KDF, so a corrupted or hostile blob cannot force
millions of PBKDF2 iterations before being rejected. Unsupported versions or
KDF identifiers are rejected for the same reason; they are never guessed at.

Unlock steps:

1. Read the record from IndexedDB.
2. Derive the AES key from the entered NFKC password, the stored `iterations`,
   the stored `salt`, and the `"parley/wrap/v1:"` label.
3. Decrypt `wrapped.ciphertext` with AES-256-GCM using `wrapped.iv` and the AAD.
   Any authentication failure (wrong password, wrong public key, or a tampered
   blob) is reported as a wrong-password error; nothing is returned.
4. Keep the raw `secretKey` in memory only while the vault is unlocked.
5. On lock/logout, overwrite the byte array with zeros (`sodium.memzero`) and
   drop all references. This is best effort; JavaScript cannot guarantee that
   the garbage collector, engine copies, or immutable strings are erased. The
   base64 wrapper strings and the `CryptoKey` handle cannot be wiped directly,
   so the runtime may retain them until it collects them.

The wrapped record is **not** uploaded to the server and **not** included in any
backup API. Clearing site data, using a different browser profile, or losing the
device makes the key unrecoverable. There is no recovery key, no escrow, and no
server-side wrapped copy.

## 5. Login and sessions

### 5.1 Client-side login preparation

The client already knows the username, so it derives the salt locally:

```
authSalt   = UTF-8("parley/auth/v1:" + username)
authSecret = PBKDF2-SHA-256(NFKC(password), authSalt, 600000, 32)
```

There is no `/auth/params` endpoint in the MVP and no auth salt is stored on the
server. Deriving the salt from the public username means the bcrypt hash alone is
enough for offline password guessing. The client therefore enforces a password
strength minimum (zxcvbn score >= 3) and the KDF cost is high; the device-only
wrapped private key still prevents message decryption. See
[THREAT_MODEL.md](THREAT_MODEL.md).

### 5.2 `POST /api/v1/auth/login`

Request:

```json
{
  "username": "alice",
  "authSecret": "<base64 of 32-byte authSecret>"
}
```

Client steps before the request:

1. Normalize the password to NFKC.
2. Derive `authSecret` from the password, the username-derived salt, and the
   `"parley/auth/v1"` label.
3. Send only `authSecret`; the password never leaves the device.

Server behavior:

1. Look up the user. If the user does not exist, verify the supplied base64 text
   against a fixed dummy bcrypt hash so the response time is similar, then return
   a generic `401`.
2. bcrypt-verify the base64 text of `authSecret` against the stored hash. Do not
   hash the decoded bytes.
3. On success, create a session and set cookies.
4. Return the user object (not the wrapped key, because the server does not have
   one).

After a successful login the client:

1. Reads the local identity record.
2. Derives `wrapKey` from the password and the wrapped record's `salt`.
3. Decrypts `wrapped.ciphertext` and opens the vault.
4. If no local record exists, reports that this device has no key for the
   account. It must not generate a replacement key silently.

### 5.3 Cookies and tokens

- Access token: JWT HS256 signed with the server `SECRET_KEY`, 15-minute
  lifetime, claims include `sub` (user id), `sid` (session id), `typ: "access"`,
  `iat`, and `exp`. Every authenticated request checks that the session still
  exists and is neither revoked nor expired.
- Refresh token: 32 random bytes, 30-day lifetime, stored server-side only as
  SHA-256(token).
- Cookie names: `parley_access` and `parley_refresh`.
- Flags: `HttpOnly`, `SameSite=Lax`, `Path=/` for access, and
  `Path=/api/v1/auth` for refresh. `Secure` is required in production; it may be
  disabled only when `DEBUG=True` for local HTTP development. No `Domain`
  attribute is set, so both cookies are host-only. The refresh path deliberately
  covers both `/api/v1/auth/refresh` and `/api/v1/auth/logout`. When a cookie is
  deleted, the server uses exactly the same `Path`, `Domain`, `SameSite`,
  `Secure`, and `HttpOnly` attributes that were used to set it; otherwise a
  browser keeps the old cookie.
- The API accepts only cookies, not an `Authorization: Bearer` header, to keep
  the token surface small.
- **Origin check for state-changing requests.** Every `POST`, `PUT`, `PATCH`, and
  `DELETE` request must carry an `Origin` header that matches one entry in the
  configured allowlist by **exact whole-origin equality** (scheme + host +
  port). There is no prefix, suffix, substring, or wildcard matching. A missing
  `Origin` header or the literal value `null` is rejected with `403` on every
  state-changing endpoint, including logout. Non-browser clients must therefore
  send an explicit `Origin` header. This, plus `SameSite=Lax`, is the CSRF
  defense. A dedicated origin (not a shared subdomain) is required.
- `POST /api/v1/auth/refresh` rotates the refresh token. Rotation is atomic and
  single-use: the server flips the presented session with a conditional update
  (`... WHERE id = :id AND revoked = 0`) and creates the replacement in the same
  transaction. If exactly one row changed, the caller gets new cookies.
- **Session states.** `revoked` remains the boolean every authentication check
  reads. `revoked_reason` records why it became true: `rotated`, `logout`,
  `reuse_detected`, `expired`, or `user_deleted`; it is NULL while the session is
  active. `rotated_at` records when the session was rotated (UTC), NULL
  otherwise.
- **Refresh reuse rules.** If the conditional update changes no row, the server
  re-reads the session and applies these rules:
  - `revoked_reason = 'rotated'` and the replay is more than
    `REFRESH_REUSE_GRACE_SECONDS` (integer, default 10, allowed 0-60) after
    `rotated_at`: theft signal. Revoke every non-revoked session for that user
    with `revoked_reason = 'reuse_detected'`, return `401`, and clear both
    cookies.
  - `revoked_reason = 'rotated'` within the grace window: assume a concurrent
    refresh from another tab. Return `401`, revoke nothing, and do **not** clear
    cookies, because the browser may already hold the replacement pair.
  - Any other revoked reason, an expired session, or an unknown token: return
    `401`, do not revoke other sessions, and clear both cookies.
- **Clients should refresh single-flight.** Serialize refreshes per browser
  profile (a tab mutex or one owning tab). The grace window only prevents
  concurrent tabs from logging each other out; it does not make parallel
  refreshes correct, and a replay outside the window is still treated as theft.
- `POST /api/v1/auth/logout` is idempotent and always returns `200`. It revokes
  the session named by a valid access cookie and the session named by a valid
  refresh cookie independently, so a valid refresh cookie is revoked even when
  the access cookie is missing or expired. A session that is still active gets
  `revoked_reason = 'logout'`; a session that is already revoked keeps its
  existing reason. Logout never revokes other sessions. It always deletes both
  cookies and never returns `401` for missing cookies.
- Registration and login are rate-limited in process. The limiter is per worker,
  not shared across processes or hosts; a multi-worker deployment needs a shared
  limiter.

Passwords cannot be changed in the MVP. A password change would require
re-deriving both secrets and re-wrapping the local key; a reset cannot restore
history because the server has no copy of the key. See section 14.

## 6. Public-key lookup and trust-on-first-use pinning

### 6.1 `GET /api/v1/users/{username}/key`

Requires a session. Returns:

```json
{
  "username": "bob",
  "public_key": "<base64 32 bytes>"
}
```

An unknown username returns `404`.

The server has no contact list beyond message rows. It does not receive the
client's pins or verification state.

### 6.2 Pin record

On first contact with a username, the client stores an IndexedDB record in the
`contacts` store, keyed by `owner + ":" + username`:

```json
{
  "owner": "alice",
  "username": "bob",
  "publicKey": "<base64>",
  "firstSeen": 1767225600000,
  "verified": false
}
```

`firstSeen` is milliseconds since the Unix epoch. `verified` becomes true only
when the user marks the safety number as compared out of band. Pinning is
trust-on-first-use: it detects a later change; it does not authenticate the
first contact.

### 6.3 Change handling

- Before sending, the client resolves the recipient key. If there is no pin, it
  fetches the key, computes the safety number, shows it, and pins the key.
- If the fetched key differs from the pin, the client blocks sending and shows
  both safety numbers. Sending remains blocked until the user explicitly
  acknowledges the new key.
- Acknowledging replaces the pinned key, sets `verified` to false, and keeps the
  original `firstSeen` value. The old key is not retained by the storage helper;
  the user-facing warning is the audit record.
- On receipt, the client fetches the sender key and compares it with the pin. A
  changed key blocks automatic decryption and shows the same warning.
- The server cannot force a client to accept a new key. A malicious server can
  lie about the key; the safety number is the only way for users to detect it.

There is no key rotation protocol in the MVP. A new key means old ciphertext may
no longer decrypt. The client does **not** persist the recipient public key used
for each sent message; sent history is decrypted with the current pinned key. If
the contact key changed and the user accepted the new key, messages sent under
the old key can no longer be decrypted by the sender and are shown as an error
rather than silently dropped.

## 7. Safety number

The safety number is a public comparison string derived from both identities'
public keys:

1. Decode both 32-byte public keys.
2. Sort them lexicographically by unsigned byte value:
   `pkLow, pkHigh`.
3. Compute a 64-byte BLAKE2b digest:
   ```
   digest = crypto_generichash(
     64,
     UTF-8("parley/safety/v1") || pkLow || pkHigh
   )
   ```
4. Split the first 48 bytes into 12 consecutive 4-byte groups. Interpret each
   group as a big-endian unsigned 32-bit integer and reduce it modulo `10^5`:
   ```
   group[i] = big_endian_u32(digest[4*i .. 4*i+3]) % 100000
   ```
5. Zero-pad each group to exactly 5 digits and join them with single spaces:
   ```
   12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890
   ```
6. Both parties compute the same string because the keys are sorted. Display it
   in the contact view and require an explicit "mark as verified" action after
   the user compares it out of band.

The modulo reduction introduces a small bias (2^32 is not a multiple of 10^5);
the safety number is a comparison value, not a secret or a key. It is safe to
display and read aloud. A matching safety number only proves that both sides see
the same two public keys. It does not prove that the keys belong to the people
behind the usernames. A mismatched safety number means a key substitution, a
wrong contact, or a tampered client.

## 8. Sending messages

### 8.1 Client steps

1. Ensure the vault is unlocked and the recipient key is pinned (section 6).
2. Generate one UUIDv4 `client_message_id` per logical message.
3. Build the plaintext envelope (section 8.1.1), including the sender's and
   recipient's public keys, and encode it as UTF-8. The client rejects a body
   longer than 60,000 UTF-8 bytes.
4. Generate a 24-byte nonce with `randombytes_buf(24)`.
5. Encrypt the envelope, not the bare text:
   ```
   ciphertext = crypto_box_easy(envelope_json, nonce, recipientPublicKey, mySecretKey)
   ```
   `crypto_box_easy` returns the 16-byte authenticator followed by the
   ciphertext.
6. Keep the `client_message_id`, envelope timestamp, recipient username, nonce,
   and ciphertext in memory with the pending send. This MVP has no local message
   cache: the pending payload is dropped when the vault locks, the user signs
   out, or the tab closes. A failed send can be retried manually only while that
   in-memory payload still exists.
7. `POST /api/v1/messages` (section 8.2). On network failure or a `5xx`
   response, retry with the same `client_message_id`, nonce, and ciphertext; do
   not re-encrypt unless the recipient key changed (which is blocked until
   acknowledged). The server deduplicates the retry on
   `(sender, client_message_id)` and returns the original row, so the client does
   not create a duplicate. A `4xx` response (including `409`) is not retried.

The sender can decrypt their own sent message later:

```
plaintext = crypto_box_open_easy(ciphertext, nonce, recipientPublicKey, mySecretKey)
```

This works because the box shared secret is symmetric in the two keypairs. The
design requires the recipient public key that was current when the message was
sent, not a newly fetched key. The MVP does not persist that per-message key, so
it decrypts sent history with the current pinned key; after an accepted key
change, older sent rows may fail to decrypt and are shown as errors. Keeping the
per-message key would require a local message cache, which this MVP deliberately
does not have.

#### 8.1.1 Plaintext envelope

The bytes handed to `crypto_box_easy` are a UTF-8 JSON object:

```json
{
  "v": 1,
  "id": "<clientMessageId>",
  "ts": 1767225600000,
  "from": "<sender public key, base64 32 bytes>",
  "to": "<recipient public key, base64 32 bytes>",
  "body": "<text>"
}
```

- `v` is the envelope version (`1`).
- `id` is the same UUIDv4 sent as `client_message_id` to the server.
- `ts` is the client send time in milliseconds since the Unix epoch.
- `from` is the sender's 32-byte crypto_box public key as standard padded
  base64. The client verifies that the supplied sender public key matches the
  public key derived from the sender's secret key before encrypting.
- `to` is the recipient's 32-byte crypto_box public key as standard padded
  base64.
- `body` is the UTF-8 message text. Empty text is allowed; more than 60,000
  UTF-8 bytes is rejected before encryption.

After `crypto_box_open_easy`, the client must:

1. Reject anything where `v !== 1` or the JSON shape is invalid.
2. Decode `from` and `to` as standard padded base64 and require exactly 32
   bytes each.
3. Require `from` to equal the sender public key used for the box (the pinned
   contact key) and `to` to equal the caller's own public key. Compare decoded
   bytes, not strings. Any mismatch is `EnvelopeMismatchError`.
4. Reject anything where the inner `id` does not equal the outer
   `client_message_id` (`EnvelopeMismatchError`). This is what makes a server
   that moves ciphertext between message rows detectable.
5. Only then display `body`.

**Why sender and recipient binding is required.** A crypto_box shared secret is
symmetric in the two keypairs: the key for Alice-to-Bob is byte-identical to the
key for Bob-to-Alice. Without names inside the authenticated plaintext, a
malicious server could take a ciphertext Bob sent to Alice, present it to Bob as
if Alice had sent it, and Bob's `crypto_box_open_easy(alicePublicKey,
bobSecretKey)` would succeed. Bob would see his own old message attributed to
Alice. The `from` and `to` fields are inside the AEAD-protected envelope, so the
server cannot rewrite them. Requiring `from` to match the verified sender key
and `to` to match the receiver's own key rejects that reflection, a redirect to
a third user, and a replay of a message from a different conversation. The
server can still drop, delay, duplicate, or reorder whole ciphertexts; see
[THREAT_MODEL.md](THREAT_MODEL.md).

The envelope is authenticated by the AEAD, so a server cannot change `id`,
`ts`, `from`, `to`, or `body` without failing decryption or the post-decryption
checks.

### 8.2 `POST /api/v1/messages`

Request:

```json
{
  "recipient": "bob",
  "client_message_id": "<uuidv4>",
  "nonce": "<base64 24 bytes>",
  "ciphertext": "<base64>",
  "client_ts": "2026-01-01T00:00:00Z"
}
```

Server behavior:

1. Require a session and derive the sender from it.
2. Validate `client_message_id` is a canonical lowercase UUIDv4 string.
3. Validate `recipient` exists, is not the sender, and matches the username
   rules.
4. Decode and validate `nonce` is exactly 24 bytes.
5. Decode and validate `ciphertext` is valid base64 and at most 65,536 bytes
   (64 KiB) decoded. The server does not enforce a minimum, does not inspect the
   authenticator, and never parses the body. Reject invalid base64.
6. Insert `client_message_id`, `nonce`, `ciphertext`, and `client_ts` as opaque
   data, with a unique constraint on `(sender_id, client_message_id)`.
7. Return `201` on the first successful send:

```json
{
  "id": "<uuid>",
  "client_message_id": "<uuidv4>",
  "created_at": "2026-01-01T00:00:00Z"
}
```

Idempotent retry:

- Same sender, same `client_message_id`, and byte-identical `recipient`,
  `nonce`, and `ciphertext` returns `200` with the original message and server
  `id`. No new row is created, and `client_ts` is not part of the identity
  comparison.
- Same sender and same `client_message_id` with a different `recipient`,
  `nonce`, or `ciphertext` returns `409` and creates nothing.
- Different senders may reuse the same `client_message_id`; the uniqueness rule
  is scoped to the sender.

The server never receives a plaintext length field, a subject, a preview, or a
message type. The ciphertext length implies an approximate plaintext length.

### 8.3 `GET /api/v1/messages/inbox?after=<cursor>`

Returns messages addressed to the current user, ordered by ascending
`(created_at, id)`:

```json
{
  "messages": [
    {
      "id": "<uuid>",
      "sender": "alice",
      "recipient": "bob",
      "client_message_id": "<uuidv4>",
      "nonce": "<base64 24 bytes>",
      "ciphertext": "<base64>",
      "client_ts": "2026-01-01T00:00:00Z",
      "created_at": "2026-01-01T00:00:00Z",
      "acked_at": null
    }
  ],
  "next_cursor": "<opaque cursor>"
}
```

The page size is fixed at 100. `after` is the opaque `next_cursor` from the
previous page; omit it for the first poll. The server returns only messages where
the current user is the recipient. `next_cursor` is always a usable cursor: for a
non-empty page it is the `(created_at, id)` cursor of the last returned message,
and for an empty page it echoes the supplied `after` value (or `null` when the
poll started without one). A client must therefore never move its stored cursor
backwards, and must not overwrite a stored non-null cursor with `null`.

Client behavior:

1. Fetch the sender's key (section 6) and check the pin.
2. If the key matches, decrypt with `crypto_box_open_easy(ciphertext, nonce,
   senderPublicKey, mySecretKey)`.
3. Deduplicate by `(direction, client_message_id)`.
4. Advance the in-memory cursor past a row only after the row is displayed in the
   message store as a decrypted message, or after it is recognised as already
   displayed. Rows that fail decryption, fail the envelope check, or belong to a
   blocked peer are shown as visible errors but are not acknowledged; they remain
   eligible for a later re-sync. The cursor is not persisted; there is no local
   message cache.
5. If decryption fails, show an authentication warning; do not display
   ciphertext as plaintext.
6. Acknowledge a row only after step 2 succeeded and the plaintext was stored. An
   error row or a blocked-peer row is never acknowledged. After the user accepts a
   changed key, the re-sync from the start processes those rows again; a row that
   now decrypts is displayed and acknowledged exactly once.

### 8.4 `GET /api/v1/messages/sent?after=<cursor>`

Returns messages sent by the current user, in the same shape, ordered by
ascending `(created_at, id)`. Both inbox and sent responses include the
`client_message_id`. This lets the sender decrypt their own history after a
reload using the locally stored recipient public key. The server does not return
plaintext or the recipient's private data.

### 8.5 `POST /api/v1/messages/{id}/ack`

The recipient marks a delivered message as acknowledged. Only the recipient may
call it; any other authenticated user receives `403`, and an unknown message
returns `404`. The operation is idempotent and returns the message id and
`acked_at`.

### 8.6 Polling transport

- Each sync pass polls both `GET /messages/inbox?after=<cursor>` and
  `GET /messages/sent?after=<cursor>`, following cursors up to a hard cap. The
  inbox interval is 5 seconds while the tab is visible, with 0–1 seconds of
  random jitter. When there is nothing new, each endpoint is requested once with
  the stored cursor and returns an empty page, so the pass performs no decrypts
  and no acknowledgements.
- On errors, use exponential backoff from 5 seconds to 60 seconds. A successful
  pass resets the interval to 5 seconds.
- Pause polling when the document is hidden; poll immediately on visibility
  resume.
- Cursors and pending payloads are in memory only. A reload re-fetches the
  server's history and decrypts it again; there is no local message cache. A
  send that was accepted by the server is reconciled with the local echo on the
  next sent-history sync by `client_message_id`.
- There are no WebSockets, server-sent events, push notifications, typing
  indicators, or read receipts in the MVP.
- Delivery is at-least-once. The client deduplicates and tolerates reordering.
- The server retains messages indefinitely in the MVP. There is no disappearing
  message feature and no guarantee of secure deletion from backups.

## 9. Server API summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | No | Liveness |
| `POST` | `/api/v1/auth/register` | No | Create account and session |
| `POST` | `/api/v1/auth/login` | No | Verify `authSecret` and create session |
| `POST` | `/api/v1/auth/refresh` | Refresh cookie | Rotate refresh token |
| `POST` | `/api/v1/auth/logout` | Optional access/refresh cookie | Revoke known sessions and clear cookies (idempotent) |
| `GET` | `/api/v1/users/{username}/key` | Access cookie | Public key lookup |
| `POST` | `/api/v1/messages` | Access cookie | Store opaque ciphertext |
| `GET` | `/api/v1/messages/inbox` | Access cookie | Inbound ciphertext, cursor paginated |
| `GET` | `/api/v1/messages/sent` | Access cookie | Outbound ciphertext, cursor paginated |
| `POST` | `/api/v1/messages/{id}/ack` | Access cookie | Recipient acknowledges a message |

All state-changing requests also require an allowed `Origin` header.

All error responses use a generic body:

```json
{ "detail": "Invalid credentials" }
```

The login endpoint must not reveal whether a username exists through its body.
Registration necessarily does.

## 10. Server data model

```
users
  id                  uuid primary key
  username            text unique, lowercase ASCII
  auth_hash           bcrypt hash of the base64 text of authSecret
  public_key          bytea(32)
  created_at          timestamptz

sessions
  id                  uuid primary key
  user_id             uuid references users
  refresh_token_hash  bytea(32) unique
  created_at          timestamptz
  expires_at          timestamptz
  revoked             boolean
  revoked_reason      text null (rotated | logout | reuse_detected | expired | user_deleted)
  rotated_at          timestamptz null

messages
  id                  uuid primary key
  sender_id           uuid references users
  client_message_id   uuidv4
  recipient_id        uuid references users
  nonce               bytea(24)
  ciphertext          bytea
  client_ts           timestamptz
  created_at          timestamptz
  acked_at            timestamptz null
  unique (sender_id, client_message_id)
  index (recipient_id, created_at, id)
  index (sender_id, created_at, id)
```

There is no auth-salt column: the auth salt is public and derived from the
username. There is no `seq` column; pagination uses the opaque
`(created_at, id)` cursor. There is no table for private keys,
wrapped keys, recovery bundles, contact pins, safety numbers, message plaintext,
or message previews. The server does not store `authSecret` after hashing it, and
must not log it.

The MVP creates the schema with `Base.metadata.create_all` at startup. Migrations
are deferred until the first schema change; this is not a production migration
strategy. Because `create_all` only creates missing tables and never alters an
existing one, a development SQLite database created before the session-state
change must be deleted and recreated. It will not gain the `revoked_reason` or
`rotated_at` columns automatically.

Operational requirements:

- HTTPS only in production; HSTS; strict CSP; no third-party scripts on the app
  origin.
- Do not log request bodies, cookies, `authSecret`, message contents, or
  ciphertext in application logs. Access logs may contain IP, time, path, and
  status.
- Rate-limit registration and login. The MVP limiter is an in-process counter:
  it is per worker and resets on restart, so a multi-worker deployment needs a
  shared store. Key lookups, sends, and polls still need limits.
- Enforce a maximum HTTP request body size at the proxy. The application
  independently caps decoded ciphertext at 64 KiB and returns validation errors
  without echoing the submitted values.
- Back up the database securely; backups contain ciphertext and metadata, not
  plaintext.
- Run as an unprivileged user if containerized; use a secret manager for
  `SECRET_KEY`.

## 11. Key compromise and risk

- **Private key compromise:** all past and future messages to/from that identity
  are readable by the attacker. There is no forward secrecy. Rotate by creating a
  new identity; old ciphertext remains exposed.
- **Password compromise:** the attacker can unwrap the local private key if they
  also have the device's IndexedDB record. Without that record, the password does
  not decrypt server-side data.
- **Server compromise:** the attacker gets usernames, public keys, bcrypt hashes,
  the contact graph, timestamps, ciphertext sizes, nonces, and ciphertext. The
  public username-derived salt lets them test password guesses offline against
  the bcrypt hash, recovering `authSecret` and possibly the password. They still
  need the device-only wrapped private key to decrypt messages. They can also
  serve modified client code, which defeats the model on the next visit.
- **Device compromise:** while unlocked, the attacker has the vault. While
  locked, the device's wrapped private-key record can be attacked offline with
  password guesses; the server hash is not needed for that local attack.
- **Offline guessing mitigation:** the client enforces zxcvbn score >= 3 before
  allowing a password, and PBKDF2 runs at 600,000 iterations. Neither makes a
  weak password safe, and bcrypt cost 12 is the final server-side slowdown.

## 12. Message validation rules

- `client_message_id`: canonical lowercase UUIDv4 string. Uniqueness is scoped
  to `(sender_id, client_message_id)`.
- Nonce: exactly 24 bytes after base64 decode.
- Ciphertext: valid standard base64, at most 65,536 bytes decoded. The server
  does not enforce a minimum and does not inspect the body.
- `client_ts`: ISO 8601 timestamp; the server stores it as supplied (normalized
  to UTC) and does not use it for ordering.
- `recipient`: a valid existing username, not the sender.
- Plaintext: the client should reject an encoded plaintext larger than 64 KiB
  before encrypting.
- Base64: standard alphabet (`A-Z`, `a-z`, `0-9`, `+`, `/`) with mandatory `=`
  padding. Reject whitespace, the URL-safe alphabet, missing or extra padding,
  and non-canonical trailing bits. Decode then re-encode and require the text
  to match; the empty string is the canonical encoding of zero bytes. This is
  the same rule as section 2 and the backend's `decode_canonical_base64`.
- The server must not attempt to interpret, decompress, re-encrypt, or scan the
  ciphertext.

## 13. Verification checklist for the implementation

Before claiming the design works:

- [ ] A registration round trip stores only the documented server fields.
- [ ] The server request/response schemas reject raw passwords and wrapped keys.
- [ ] The wrapped private key is absent from network traffic and server storage.
- [ ] `wrapKey` and `authSecret` differ even when the password is the same.
- [ ] A message round trip decrypts for the recipient.
- [ ] A sender can decrypt their own sent message after reload.
- [ ] A modified ciphertext fails authentication.
- [ ] A ciphertext reflected to its sender, or redirected to a third user, is
      rejected by the sender/recipient binding in the envelope.
- [ ] A changed public key blocks sending until acknowledged.
- [ ] Both parties compute the same safety number.
- [ ] The server cannot decrypt a message from its database alone.
- [ ] Logs contain no auth secrets, cookies, or message bodies.
- [ ] Rate limits and body-size limits are enforced.

## 14. Deferred and out of scope

- **Forward secrecy / ratchet.** Static box keys do not provide it. A future
  version could add X3DH + Double Ratchet, but that is a different protocol.
- **Post-compromise security.** Not provided.
- **Deniability.** Not claimed.
- **Metadata hiding.** No sealed sender, padding, cover traffic, or mixing.
- **Multi-device / key sync.** The private key is local to one browser profile.
- **Key recovery / escrow.** No recovery key, no server-side wrapped copy.
- **Password change/reset.** Not implemented. Parley has no reset and no
  recovery by design. A future password change would require re-wrapping the
  private key locally with the new `wrapKey` and issuing a new `authSecret` in one
  atomic, client-driven step; a server-only password reset cannot restore
  history.
- **Group chat.** Not in scope.
- **Attachments.** Not in scope; they would need their own streaming encryption
  design.
- **Disappearing messages / secure deletion.** Not in scope.
- **Push notifications and read receipts.** Not in scope; both add metadata.
- **Key rotation.** Not in the MVP. Pinning detects changes; it does not define a
  safe rotation protocol.
- **Malicious-server code transparency.** Not implemented. A server that serves
  modified JavaScript can steal keys and plaintext.
- **Audit and formal verification.** None. This is a portfolio design and must
  not be represented as production-grade for high-risk users.

## 15. Roadmap

- **Argon2id via libsodium** for password-based derivation, replacing Web Crypto
  PBKDF2 once browser support and deployment constraints allow it. Argon2id is
  memory-hard; PBKDF2 at 600,000 iterations is the current interoperable choice.
- A shared, cross-process rate limiter.
- Reviewed database migrations.
- A locally re-wrapped private key plus new `authSecret` for password changes,
  as one atomic client-driven operation.

## 16. Backend implementation deviations

The backend MVP forced these deviations from, or clarifications of, the design
above. They are explicit because the code must not claim more than it does.

- **SQLite development schema.** The development database stores UUIDs as
  `TEXT(36)`, binary values as `BLOB`, and timestamps as naive UTC `DATETIME`
  rather than the `uuid`, `bytea`, and `timestamptz` types shown in section 10.
  Those types remain the target for a PostgreSQL deployment.
- **Schema creation, not migrations.** Tables are created with
  `Base.metadata.create_all` at startup. Migrations are deferred; this is not a
  production migration strategy.
- **HTTP status codes.** FastAPI returns `422` for schema/validation failures
  where the design text says `400`. Authentication failures remain `401`, and
  authorization or Origin failures remain `403`.
- **Opaque cursor, fixed page size.** Pagination uses an opaque base64url cursor
  over `(created_at, id)` and always returns at most 100 rows. There is no `seq`
  column and no `limit` query parameter.
- **Idempotent send.** `POST /api/v1/messages` requires `client_message_id` and
  enforces uniqueness on `(sender_id, client_message_id)`, as described in
  section 8.2. Identical retries return the original message with `200`;
  conflicting reuse returns `409`. This is no longer a deviation.
- **First schema change.** The `client_message_id` column and its unique
  constraint are the first schema change since the MVP. `create_all` does not
  alter an existing table, so a development SQLite database created before this
  change must be recreated. Reviewed migrations are still deferred; this is not
  a production migration strategy.
- **No `auth_salt`, `kdf_version`, or `/auth/params`.** The auth salt is the
  public username-derived value in section 2, so there is nothing to fetch or
  store. There is also no `/auth/me`; callers use the user object returned by
  register/login and the public-key endpoint.
- **In-process rate limiter.** Registration and login limits live in one worker
  process, reset on restart, and are not shared across processes. This matches
  the design note in section 10 and is not a distributed guarantee.
- **Refresh reuse handling.** Refresh rotation marks the old session revoked and
  creates a new row. Presenting a revoked refresh token revokes every session for
  that user before returning `401`, as a theft signal.
- **Timestamps.** `client_ts` is normalized to UTC when stored; message ordering
  uses the server's `created_at`, never `client_ts`.
- **No local message cache.** Decrypted messages, cursors, and pending send
  payloads live only in memory. A reload or re-login re-fetches and decrypts the
  server's history. There is no IndexedDB, localStorage, sessionStorage, cookie,
  URL, or log copy of message plaintext or ciphertext.
- **Cursor stability.** The client stores the cursor returned by the last page
  and never replaces a non-null cursor with `null`. The backend echoes the input
  cursor on an empty page and returns the last item's cursor on a non-empty page,
  so reaching the end does not reset the next poll to the start of history.
- **Sent history uses the current pin.** The client does not persist the
  recipient public key that was used for each sent message. After a key change is
  acknowledged, older sent rows encrypted to the previous key cannot be
  decrypted by the sender and are shown as errors. This is a known MVP
  limitation, not a guarantee of historical sent-message readability.
- **Retry budget.** A send makes the initial attempt plus up to three automatic
  retries for network errors and `5xx` responses, with 500 ms, 1 s, and 2 s
  delays, then leaves a failed row with a manual Retry action while the in-memory
  payload exists. Acknowledgements retry twice (500 ms, 1 s) for the same
  retryable errors; `4xx` responses are not retried.
- **Key-change acknowledgement re-syncs history.** Accepting a new peer key
  replaces the pin, clears the block, resets both in-memory cursors, and runs a
  sync so previously hidden rows can be decrypted with the accepted key. Rows
  that were blocked had not been acknowledged, so the re-sync processes them
  again; a row that decrypts now is shown and acknowledged once.

## 17. Client crypto implementation notes

The client crypto layer lives in `frontend/src/crypto/` and is covered by
vitest. It depends only on `libsodium-wrappers` and Web Crypto; there are no
custom primitives.

- **Binary encoding.** Public keys, secret keys, nonces, salts, IVs, ciphertext,
  and the derived auth secret are standard padded base64 in memory and on the
  wire.
- **Async surface.** `ready()` resolves the single libsodium initialisation
  promise. `deriveAuthSecret`, the keypair/wrapping helpers, the message helpers,
  the safety number, and the IndexedDB helpers return promises. Synchronous
  validation failures throw a typed error.
- **Typed failures.** `InvalidInputError`, `DecryptionError`, `WrongPasswordError`,
  `EnvelopeMismatchError`, `KeyChangedError`, `WeakPasswordError`, and
  `StorageError` all extend `ParleyError`. No helper returns a silent default.
- **Test-only KDF override.** `deriveAuthSecret` and `wrapSecretKey` accept an
  optional iteration count so tests can use a low work factor. Production callers
  omit it and get the 600,000 constant.
- **Storage names.** Database `parley` version 1, stores `identity` (keyed by
  `username`) and `contacts` (keyed by `owner + ":" + username`). Only the
  wrapped key blob and public metadata are stored; no raw private key, password,
  wrap key, or auth secret is persisted.
- **Length limits.** `encryptMessage` rejects a body over 60,000 UTF-8 bytes and
  an envelope over 64,000 bytes, leaving room for the 16-byte box authenticator
  under the server's 65,536-byte ciphertext limit.
- **Memory.** Raw secret buffers are overwritten with `sodium.memzero` when they
  are no longer needed. JavaScript strings, base64 wrappers, and `CryptoKey`
  handles cannot be zeroed, and the engine or garbage collector may retain
  copies. Zeroization is best effort, not a guarantee.

## 18. Client messaging implementation notes

The messaging engine lives in `frontend/src/messaging/` and the chat UI in
`frontend/src/components/chat/`. All cryptography is called through
`frontend/src/crypto/`; components never call libsodium or Web Crypto directly.

- **State.** A Zustand store holds conversations, per-conversation items, sync
  state, and key-change blocks. Plaintext exists only in this in-memory store
  and in the engine's pending send payloads. It is cleared on lock, logout, and
  engine stop.
- **Deduplication.** Rows are matched by direction and `client_message_id`. A
  local send echo is replaced by the server row when sent history catches up; a
  later successful decrypt replaces an earlier visible error for the same row.
- **Send retry safety.** The engine encrypts once, keeps the exact nonce,
  ciphertext, `client_ts`, and `client_message_id`, and reuses that payload for
  every retry. A `4xx` response is final and drops the payload, because replaying
  it cannot succeed.
- **Acknowledgements.** Inbox rows are acknowledged only after they decrypt and
  are stored. Rows that produce an error (decryption failure, envelope mismatch,
  invalid input) and rows from a blocked peer are never acknowledged. Already
  acknowledged rows are skipped, so a re-sync does not send a duplicate ack.
  Acknowledgements retry twice for retryable errors; `4xx` responses are final.
- **Key changes.** A changed sender or recipient key blocks sending and
  automatic decryption, records both safety numbers, and requires explicit user
  acknowledgement before the pin is replaced and history is re-synced.
- **Plain text only.** The UI renders message bodies as text nodes. It never uses
  `dangerouslySetInnerHTML` or an HTML renderer.
