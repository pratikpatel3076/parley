# Parley Protocol (MVP)

Status: specified design. The repository is a scaffold; none of the endpoints
below are implemented yet. This document is the contract the implementation must
satisfy. Security claims and limits are in [THREAT_MODEL.md](THREAT_MODEL.md).

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

All binary values in JSON are standard base64 (RFC 4648 section 4, with
padding). The server treats `nonce` and `ciphertext` as opaque bytes and never
decrypts them.

| Purpose | Primitive | Implementation |
|---|---|---|
| Message encryption | `crypto_box_easy` (X25519 + XSalsa20-Poly1305) | `libsodium-wrappers` |
| Message decryption | `crypto_box_open_easy` | `libsodium-wrappers` |
| Identity keypair | `crypto_box_keypair` (X25519) | `libsodium-wrappers` |
| Safety number digest | BLAKE2b-256 (`crypto_generichash`) | `libsodium-wrappers` |
| Private-key wrapping key | PBKDF2-HMAC-SHA-256, 310,000 iterations, 32-byte output | Web Crypto |
| Private-key wrapping | AES-256-GCM | Web Crypto |
| Server auth hash | bcrypt, cost 12 | Server library |
| Session access token | JWT HS256, 15 minutes | Server library |
| Refresh token | 32 random bytes, stored only as SHA-256 hash | Server library + CSPRNG |

There are no custom cryptographic constructions. Web Crypto is used only for
PBKDF2 and AES-256-GCM key wrapping; message encryption and safety numbers use
libsodium. Random values come from `sodium.randombytes_buf` where libsodium is
already required, and from `crypto.getRandomValues` otherwise.

Usernames are ASCII, lowercase, and match `^[a-z0-9_]{3,32}$`. Passwords are
normalized to Unicode NFC and encoded as UTF-8 before derivation; this avoids
cross-platform differences in the same visual password. Usernames are not
normalized with Unicode because they are restricted to ASCII.

## 3. Identity registration

### 3.1 Client-side steps

1. Await `sodium.ready`.
2. Generate the box keypair:
   ```
   (publicKey, secretKey) = crypto_box_keypair()   // 32 bytes each
   ```
3. Generate two independent random salts:
   ```
   wrapSalt = randombytes_buf(16)   // never leaves the device
   authSalt = randombytes_buf(16)   // sent to the server
   ```
4. Normalize the password to NFC and encode it as UTF-8.
5. Derive two independent 32-byte secrets with different salts **and**
   different domain labels:
   ```
   wrapKey     = PBKDF2-SHA-256(password, "parley/wrap/v1" || 0x00 || wrapSalt,
                                310000, 32)
   authSecret  = PBKDF2-SHA-256(password, "parley/auth/v1" || 0x00 || authSalt,
                                310000, 32)
   ```
   The ASCII label is part of the PBKDF2 salt input. The label and salt are
   concatenated with a zero byte so the inputs are unambiguous.
6. Import `wrapKey` as an AES-256-GCM key with `encrypt`/`decrypt` usages. Keep
   `wrapKey` in memory only.
7. Generate a 12-byte AES-GCM nonce and wrap the raw `secretKey`:
   ```
   aad        = UTF-8("parley/private-key/v1" || 0x00 || username)
   wrapped    = AES-256-GCM-Encrypt(wrapKey, nonce, aad, secretKey)
   ```
8. Store the identity record **only in IndexedDB** (section 4).
9. Register with the server (section 3.2). `authSecret`, `authSalt`, and
   `publicKey` are sent; `wrapKey`, `secretKey`, `wrapped`, and `wrapSalt` are
   not.

The `wrapKey` must never be written to IndexedDB, localStorage, a cookie, a log,
or the network.

### 3.2 `POST /api/v1/auth/register`

Request:

```json
{
  "username": "alice",
  "auth_secret": "<base64 of 32-byte authSecret>",
  "auth_salt": "<base64 of 16-byte authSalt>",
  "public_key": "<base64 of 32-byte publicKey>",
  "kdf_version": 1
}
```

Server behavior:

1. Validate the username format and uniqueness.
2. Decode and validate lengths: `auth_secret` 32 bytes, `auth_salt` 16 bytes,
   `public_key` 32 bytes.
3. Require `kdf_version == 1`; reject unknown versions rather than guessing.
4. Hash `auth_secret` with bcrypt cost 12 and store the hash. Never store the
   raw value.
5. Store `auth_salt`, `public_key`, and `kdf_version`. Do not store `wrapSalt`,
   `wrapKey`, `secretKey`, or any wrapped private-key record.
6. Create a session (section 5) and set the auth cookies.
7. Return `201`:

```json
{
  "user": {
    "id": "<uuid>",
    "username": "alice",
    "public_key": "<base64>",
    "created_at": "2026-01-01T00:00:00Z"
  },
  "kdf_version": 1
}
```

Errors: `400` invalid input, `409` username taken, `429` rate limited. The
registration response intentionally reveals whether a username is available;
that is unavoidable for a public username registry.

The local identity record should be persisted before or atomically with a
successful registration response. If the server succeeds but the browser cannot
persist the record (for example, storage is full), the client must tell the user
that the account has no usable local key. Parley cannot recover it.

## 4. Private-key storage and unlock

The only persisted copy of the private key is this IndexedDB record:

```json
{
  "v": 1,
  "username": "alice",
  "public_key": "<base64 32 bytes>",
  "wrap_salt": "<base64 16 bytes>",
  "wrap_nonce": "<base64 12 bytes>",
  "wrapped_secret_key": "<base64 AES-256-GCM ciphertext>",
  "created_at": "2026-01-01T00:00:00Z"
}
```

`wrapped_secret_key` is 48 bytes: 32 bytes of encrypted key plus the 16-byte
GCM tag. The AAD is `UTF-8("parley/private-key/v1" || 0x00 || username)`, which
binds the record to the account name.

Unlock steps:

1. Read the record from IndexedDB.
2. Derive `wrapKey` from the entered password, `wrap_salt`, and the same label.
3. Decrypt `wrapped_secret_key` with AES-256-GCM using `wrap_nonce` and the AAD.
4. Keep the raw `secretKey` in memory only while the vault is unlocked.
5. On lock/logout, overwrite the byte array with zeros (`sodium.memzero`) and
   drop all references. This is best effort; JavaScript cannot guarantee that
   the garbage collector or engine copies are erased.

The wrapped record is **not** uploaded to the server and **not** included in any
backup API. Clearing site data, using a different browser profile, or losing the
device makes the key unrecoverable. There is no recovery key, no escrow, and no
server-side wrapped copy.

## 5. Login and sessions

### 5.1 `GET /api/v1/auth/params?username=alice`

Returns the public KDF parameters needed before login:

```json
{ "auth_salt": "<base64 16 bytes>", "kdf_version": 1 }
```

The endpoint requires no session because the client has not authenticated yet.
For an unknown username, the server returns a synthetic salt:

```
fakeSalt = HMAC-SHA-256(SECRET_KEY, "parley/fake-auth-salt/v1" || 0x00 || username)[0:16]
```

with the same shape and KDF version, so a caller cannot distinguish "unknown
user" from "known user" by the response body. Timing and rate limits can still
leak information; the server should rate-limit per IP and username.

### 5.2 `POST /api/v1/auth/login`

Request:

```json
{
  "username": "alice",
  "auth_secret": "<base64 of 32-byte authSecret>"
}
```

Client steps before the request:

1. Normalize the password to NFC.
2. Derive `authSecret` from the password, the returned `auth_salt`, and the
   `"parley/auth/v1"` label.
3. Send only `authSecret`; the password never leaves the device.

Server behavior:

1. Look up the user. If the user does not exist, verify against a fixed dummy
   bcrypt hash so the response time is similar, then return a generic `401`.
2. bcrypt-verify the decoded `auth_secret` against the stored hash.
3. On success, create a session and set cookies.
4. Return the user object (not the wrapped key, because the server does not have
   one).

After a successful login the client:

1. Reads the local identity record.
2. Derives `wrapKey` from the password and `wrap_salt`.
3. Decrypts `wrapped_secret_key` and opens the vault.
4. If no local record exists, reports that this device has no key for the
   account. It must not generate a replacement key silently.

### 5.3 Cookies and tokens

- Access token: JWT HS256 signed with the server `SECRET_KEY`, 15-minute
  lifetime, claims include `sub` (user id), `typ: "access"`, `iat`, and `exp`.
- Refresh token: 32 random bytes, 30-day lifetime, stored server-side only as
  SHA-256(token).
- Cookie names: `parley_access` and `parley_refresh`.
- Flags: `HttpOnly`, `SameSite=Lax`, `Path=/` for access, and
  `Path=/api/v1/auth` for refresh. `Secure` is required in production and is
  configurable for local HTTP development.
- The API accepts only cookies, not an `Authorization: Bearer` header, to keep
  the token surface small.
- Every state-changing request must have an `Origin` header in the configured
  allowlist. This, plus `SameSite=Lax`, is the CSRF defense. A dedicated
  origin (not a shared subdomain) is required.
- `POST /api/v1/auth/refresh` rotates the refresh token. If the presented token
  matches a revoked/rotated session, revoke all sessions for that user; treat it
  as a theft signal.
- `POST /api/v1/auth/logout` revokes the current session and deletes both
  cookies.
- `GET /api/v1/auth/me` returns the current user's id, username, and public key.

Passwords cannot be changed in the MVP. A password change would require
re-deriving both secrets and re-wrapping the local key; a reset cannot restore
history because the server has no copy of the key. See section 14.

## 6. Public-key lookup and trust-on-first-use pinning

### 6.1 `GET /api/v1/keys/{username}`

Requires a session. Returns:

```json
{
  "username": "bob",
  "public_key": "<base64 32 bytes>",
  "kdf_version": 1
}
```

The server has no contact list beyond message rows. It does not receive the
client's pins or verification state.

### 6.2 Pin record

On first contact with a username, the client stores:

```json
{
  "username": "bob",
  "public_key": "<base64>",
  "first_seen": "2026-01-01T00:00:00Z",
  "last_seen": "2026-01-02T00:00:00Z",
  "verified": false,
  "safety_number": "12345 67890 ..."
}
```

`verified` becomes true only when the user marks the safety number as compared
out of band. Pinning is trust-on-first-use: it detects a later change; it does
not authenticate the first contact.

### 6.3 Change handling

- Before sending, the client resolves the recipient key. If there is no pin, it
  fetches the key, computes the safety number, shows it, and pins the key.
- If the fetched key differs from the pin, the client blocks sending and shows
  both safety numbers. Sending remains blocked until the user explicitly
  acknowledges the new key.
- Acknowledging updates the pin, sets `verified` to false, and records the change
  time. The old key is retained for display/audit, not for silent fallback.
- On receipt, the client fetches the sender key and compares it with the pin. A
  changed key blocks automatic decryption and shows the same warning.
- The server cannot force a client to accept a new key. A malicious server can
  lie about the key; the safety number is the only way for users to detect it.

There is no key rotation protocol in the MVP. A new key means old ciphertext may
no longer decrypt; the client should keep the recipient public key it used for
each sent message so the sender can still decrypt their own sent messages.

## 7. Safety number

The safety number is a public comparison string derived from both identities'
public keys:

1. Decode both 32-byte public keys.
2. Sort them lexicographically by unsigned byte value:
   `pkLow, pkHigh`.
3. Compute:
   ```
   digest = crypto_generichash(
     32,
     UTF-8("parley/safety-number/v1") || 0x00 || pkLow || pkHigh
   )
   ```
4. Interpret `digest` as a big-endian unsigned integer, reduce modulo `10^60`,
   and zero-pad to exactly 60 decimal digits:
   ```
   digits = decimal(digest_as_integer % 10**60).zfill(60)
   ```
5. Group into 12 groups of 5 digits separated by spaces:
   ```
   12345 67890 12345 67890 12345 67890 12345 67890 12345 67890 12345 67890
   ```
6. Both parties compute the same string because the keys are sorted. Display it
   in the contact view and require an explicit "mark as verified" action after
   the user compares it out of band.

The modulo reduction introduces a negligible bias; the safety number is a
comparison value, not a secret or a key. It is safe to display and read aloud.
A matching safety number only proves that both sides see the same two public
keys. It does not prove that the keys belong to the people behind the usernames.
A mismatched safety number means a key substitution, a wrong contact, or a
tampered client.

## 8. Sending messages

### 8.1 Client steps

1. Ensure the vault is unlocked and the recipient key is pinned (section 6).
2. Encode the plaintext as UTF-8.
3. Generate a 24-byte nonce with `randombytes_buf(24)`.
4. Encrypt:
   ```
   ciphertext = crypto_box_easy(plaintext, nonce, recipientPublicKey, mySecretKey)
   ```
   `crypto_box_easy` returns the 16-byte authenticator followed by the
   ciphertext.
5. Generate `client_message_id` as a UUID v4 for idempotent retries.
6. Persist the sent record locally with the recipient public key used, nonce,
   ciphertext, id, and timestamp.
7. `POST /api/v1/messages` (section 8.2). On network failure, retry with the same
   `client_message_id`; do not re-encrypt unless the recipient key changed
   (which is blocked until acknowledged).

The sender can decrypt their own sent message later:

```
plaintext = crypto_box_open_easy(ciphertext, nonce, recipientPublicKey, mySecretKey)
```

This works because the box shared secret is symmetric in the two keypairs. The
client must use the recipient public key that was current when the message was
sent, not a newly fetched key.

### 8.2 `POST /api/v1/messages`

Request:

```json
{
  "to": "bob",
  "nonce": "<base64 24 bytes>",
  "ciphertext": "<base64>",
  "client_message_id": "<uuid v4>"
}
```

Server behavior:

1. Require a session and derive the sender from it.
2. Validate `to` exists, is not the sender, and matches the username rules.
3. Decode and validate `nonce` is exactly 24 bytes.
4. Decode and validate `ciphertext`: at least 16 bytes (the authenticator) and at
   most 16,384 bytes (16 KiB plaintext + 16-byte authenticator). Reject invalid
   base64.
5. Enforce per-sender rate and size limits.
6. Insert an opaque row. If `(sender_id, client_message_id)` already exists,
   return the existing row instead of inserting a duplicate.
7. Return `201`:

```json
{
  "id": "<uuid>",
  "seq": 123,
  "created_at": "2026-01-01T00:00:00Z"
}
```

The server never receives a plaintext length field, a subject, a preview, or a
message type. The ciphertext length implies an approximate plaintext length.

### 8.3 `GET /api/v1/messages?after=<seq>&limit=100`

Returns messages addressed to the current user, ordered by ascending `seq`:

```json
{
  "messages": [
    {
      "id": "<uuid>",
      "seq": 123,
      "from": "alice",
      "nonce": "<base64 24 bytes>",
      "ciphertext": "<base64>",
      "created_at": "2026-01-01T00:00:00Z"
    }
  ],
  "next_cursor": 123
}
```

`after` is the highest `seq` the client has processed; omit it for the first
poll. `limit` defaults to 100 and is capped at 100. `next_cursor` is the highest
returned `seq` (or the input `after` if empty).

Client behavior:

1. Fetch the sender's key (section 6) and check the pin.
2. If the key matches, decrypt with `crypto_box_open_easy(ciphertext, nonce,
   senderPublicKey, mySecretKey)`.
3. Deduplicate by message id.
4. Advance the cursor only after the message is persisted/displayed locally.
5. If decryption fails, show an authentication warning; do not display
   ciphertext as plaintext.

### 8.4 `GET /api/v1/messages/sent?after=<seq>&limit=100`

Returns messages sent by the current user, in the same shape with `to` instead
of `from`. This lets the sender decrypt their own history after a reload using
the locally stored recipient public key. The server does not return plaintext or
the recipient's private data.

### 8.5 Polling transport

- The client polls `GET /messages?after=<cursor>` every 5 seconds while the tab
  is visible, with 0–1 seconds of random jitter.
- On errors, use exponential backoff from 5 seconds to 60 seconds.
- Pause polling when the document is hidden; poll immediately on visibility
  resume.
- There are no WebSockets, server-sent events, push notifications, typing
  indicators, or read receipts in the MVP.
- Delivery is at-least-once. The client deduplicates and tolerates reordering.
- The server retains messages indefinitely in the MVP. There is no disappearing
  message feature and no guarantee of secure deletion from backups.

## 9. Server API summary

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | No | Liveness |
| `GET` | `/api/v1/auth/params` | No | Public KDF salt/version for a username |
| `POST` | `/api/v1/auth/register` | No | Create account and session |
| `POST` | `/api/v1/auth/login` | No | Verify `authSecret` and create session |
| `POST` | `/api/v1/auth/refresh` | Refresh cookie | Rotate refresh token |
| `POST` | `/api/v1/auth/logout` | Access cookie | Revoke session and clear cookies |
| `GET` | `/api/v1/auth/me` | Access cookie | Current user |
| `GET` | `/api/v1/keys/{username}` | Access cookie | Public key lookup |
| `POST` | `/api/v1/messages` | Access cookie | Store opaque ciphertext |
| `GET` | `/api/v1/messages` | Access cookie | Inbound ciphertext, cursor paginated |
| `GET` | `/api/v1/messages/sent` | Access cookie | Outbound ciphertext, cursor paginated |

All error responses use a generic body:

```json
{ "detail": "Invalid credentials" }
```

The login and params endpoints must not reveal whether a username exists through
their body. Registration necessarily does.

## 10. Server data model

```
users
  id                  uuid primary key
  username            text unique, lowercase ASCII
  auth_secret_hash    bcrypt hash of authSecret
  auth_salt           bytea(16)
  kdf_version         smallint
  public_key          bytea(32)
  created_at          timestamptz

sessions
  id                  uuid primary key
  user_id             uuid references users
  refresh_token_hash  bytea(32) unique
  created_at          timestamptz
  last_used_at        timestamptz
  expires_at          timestamptz
  revoked_at          timestamptz null

messages
  id                  uuid primary key
  seq                 bigserial unique
  sender_id           uuid references users
  recipient_id        uuid references users
  nonce               bytea(24)
  ciphertext          bytea
  client_message_id   uuid
  created_at          timestamptz
  unique (sender_id, client_message_id)
  index (recipient_id, seq)
  index (sender_id, seq)
```

There is no table for private keys, wrapped keys, recovery bundles, contact
pins, safety numbers, message plaintext, or message previews. The server does not
store `authSecret` after hashing it, and must not log it.

Operational requirements:

- HTTPS only in production; HSTS; strict CSP; no third-party scripts on the app
  origin.
- Do not log request bodies, cookies, `authSecret`, message contents, or
  ciphertext in application logs. Access logs may contain IP, time, path, and
  status.
- Rate-limit registration, login, key lookups, sends, and polls.
- Enforce a maximum request body size at the proxy and application layers.
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
  auth salts, the contact graph, timestamps, ciphertext sizes, nonces, and
  ciphertext. They still need a client's private key (or a password plus that
  client's wrapped record) to decrypt. They can also serve modified client code,
  which defeats the model on the next visit.
- **Device compromise:** while unlocked, the attacker has the vault. While
  locked, a weak password can be guessed offline from the wrapped record.

## 12. Message validation rules

- Nonce: exactly 24 bytes after base64 decode.
- Ciphertext: at least 16 bytes (empty plaintext is allowed and produces a
  16-byte authenticator) and at most 16,400 bytes.
- `client_message_id`: UUID v4 string; idempotency key scoped to the sender.
- `to`: a valid existing username, not the sender.
- Plaintext: the client should reject an encoded plaintext larger than 16 KiB
  before encrypting.
- Base64: standard alphabet with padding; reject non-canonical encodings where
  practical.
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
- **Password change/reset.** Not implemented. A reset cannot restore history;
  the correct user experience is to be explicit about permanent loss.
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
