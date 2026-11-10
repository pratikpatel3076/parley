# Parley Threat Model

Status: design document for the protocol in [PROTOCOL.md](PROTOCOL.md). The
repository currently contains a scaffold, not a working messenger. This model
describes the intended design and its limits; it is not a claim that the code
has been audited.

## 1. Scope

Parley is a 1:1 end-to-end encrypted messenger. A user registers a username,
generates a libsodium box keypair on the device, and keeps the private key
wrapped in IndexedDB. Messages are encrypted on the sender's device and stored
by the server as opaque nonce + ciphertext. The server relays ciphertext and
stores account metadata.

The security goal is narrow:

- The server cannot read message plaintext from what it stores.
- The server does not receive the private key, the password, or `wrapKey`.
- A message cannot be forged or modified without detection by the recipient.
- A contact's public key change is visible and blocks sending until the user
  acknowledges it.

Everything else is explicitly out of scope or a known limitation.

## 2. Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Message plaintext | Sender/recipient device memory; never the server | The content users expect to keep private |
| Private box key (`secretKey`) | Wrapped in IndexedDB; unwrapped in memory while the vault is open | Decrypts every message to/from the identity; compromise breaks all history for that identity |
| Password | User's memory/password manager; typed into the client | Derives `wrapKey`; never sent to the server in the intended design |
| `wrapKey` | Derived in client memory; never persisted | Unlocks the wrapped private key |
| `authSecret` | Derived in client memory; bcrypt hash on the server | Authenticates the user; not sufficient to decrypt messages |
| Public keys | Server and clients | Identity for encryption; substitution enables MITM |
| Contact pins / safety numbers | Client IndexedDB / user's eyes | Detect key substitution after first contact |
| Message ciphertext + nonces | Server and recipient device | Confidential only while keys are safe |
| Contact graph | Server (sender/recipient ids) | Metadata; reveals who talks to whom |
| Session cookies | Browser cookie jar; hashes in server DB | Account access |
| Server `SECRET_KEY` | Server environment/secret store | Signs sessions; compromise allows session forgery, not message decryption |

## 3. Adversaries

### 3.1 Passive network observer

- **Capabilities:** observes packets, TLS handshake metadata, IP addresses,
  packet sizes, and timing.
- **Can learn:** that a client talks to the Parley server, when, how often, and
  roughly how much data is exchanged. Without breaking TLS, no HTTP bodies or
  cookies.
- **Cannot:** read message plaintext or ciphertext contents, recover keys, or
  forge messages.
- **Mitigation:** HTTPS/TLS is required in production. TLS is not pinned; a
  compromised certificate authority or a user who ignores certificate warnings
  can enable an active attack.
- **Residual:** traffic analysis is not prevented. Polling intervals and message
  sizes leak activity and approximate message length.

### 3.2 Honest-but-curious server

- **Capabilities:** runs the documented code, stores the database, serves the
  client, and can inspect everything it receives and stores.
- **Can see:** usernames, public keys, auth salts, bcrypt hashes of
  `authSecret`, sender/recipient ids, timestamps, ciphertext sizes, nonces,
  ciphertext, IP addresses, user agents, session metadata, polling patterns,
  and error/rate-limit events.
- **Cannot see:** message plaintext, private keys, `wrapKey`, the raw password,
  or the preimage of `authSecret`. It cannot decrypt a stored message with its
  database alone.
- **Can still do:** withhold, delay, reorder, duplicate, or drop ciphertext;
  deny service; retain data after deletion requests; attempt offline guessing of
  `authSecret` from the bcrypt hash. Because it does not hold a wrapped private
  key, guessing `authSecret` alone does not decrypt messages.
- **Important boundary:** the server also serves the JavaScript. An
  honest-but-curious server that is later compromised, or a server operator who
  changes the served code, becomes the malicious-server case. End-to-end
  encryption cannot protect a user from a client that has been rewritten to
  exfiltrate keys.

### 3.3 Malicious server

- **Capabilities:** everything the honest-but-curious server can do, plus
  serving modified JavaScript, lying about public keys, replaying or modifying
  API responses, and selectively censoring.
- **Can:** steal plaintext or private keys by serving malicious client code;
  substitute a public key on first contact (first-contact MITM); suppress a key
  change warning by lying; replay old ciphertext; cause denials of service.
- **Cannot:** forge a valid `crypto_box_easy` ciphertext for a pinned key without
  the sender's private key; decrypt ciphertext without obtaining keys.
- **Mitigations:**
  - Public keys are pinned on first contact; a changed key blocks sending.
  - Safety numbers can be compared out of band to detect substitution.
  - AEAD rejects modified ciphertext.
  - Clients should require explicit user acknowledgement before accepting a new
    key.
- **Hard limit:** if the server serves modified JavaScript, all client-side
  guarantees are void. There is no reproducible-build, code-signing, or
  transparency-log verification in this design. This is not a defense against a
  malicious server; it is a boundary of the threat model.

### 3.4 Stolen device

- **Locked device / offline disk image:** attacker gets IndexedDB, which
  contains the wrapped private key, contact pins, and cached ciphertext. The
  private key requires the password-derived `wrapKey`. A weak password can be
  guessed offline.
- **Unlocked device or active session:** the unwrapped private key and decrypted
  messages are in process memory. The attacker can read them, screenshot them,
  or use the open session.
- **Mitigations:** OS/browser lock screen, full-disk encryption, a strong unique
  password, and closing the vault on logout. JavaScript cannot guarantee
  zeroization; `sodium.memzero` is best effort because the garbage collector and
  copies may retain bytes.
- **Not provided:** secure enclave storage, hardware-backed key wrapping,
  remote wipe, auto-lock timer, or protection from malware/browser extensions.

### 3.5 Another user

- **Capabilities:** can register, send messages, enumerate some account
  information, spam, and attempt to substitute keys.
- **Can see:** their own conversation, their own recipient's public key, and any
  metadata the server exposes to them (for example, whether a username exists,
  depending on endpoint behavior).
- **Cannot:** decrypt another user's messages, read another user's private key,
  or forge a message that verifies under another user's pinned public key.
- **Server-side requirements:** authorization on every message read/write,
  per-user rate limits, body-size limits, and generic authentication errors.
- **Residual:** usernames are public identifiers; a user can be messaged by
  anyone who knows the username unless the product adds blocking/allow-lists
  (not in the MVP).

### 3.6 Local attackers and client-side compromise

- **XSS, malicious browser extension, compromised dependency, or a hostile
  page in the same origin** can read the unwrapped key while the vault is open
  and can call the client's crypto functions.
- **Mitigations:** a strict CSP, no third-party scripts, dependency pinning and
  review, and treating the client bundle as part of the trusted computing base.
- **Not provided:** protection from a compromised browser, OS, or extension.

## 4. What the server can and cannot see

### Can see

- Usernames and account creation times.
- Public keys and public-key changes.
- `authSalt` and a bcrypt hash of `authSecret` (not `authSecret` itself after
  the request completes, unless the server logs request bodies).
- Who sends to whom (sender and recipient ids), message timestamps, and message
  counts.
- Nonce and ciphertext sizes. Parley does not pad messages, so ciphertext length
  approximates plaintext length (plaintext length + 16-byte authenticator; the
  24-byte nonce is stored separately).
- IP addresses, user agents, request timing, polling cadence, and error/rate
  limit activity, at least in access logs even if not stored in the application
  database.
- Delivery/queue state, if implemented, and the fact that a message was fetched.
- Account/session metadata needed to operate the service.

### Cannot see

- Message plaintext.
- The private key, the wrapped private-key record, or `wrapKey`.
- The raw password.
- The preimage of `authSecret` from the bcrypt hash.
- Contact pins and safety numbers, unless the client sends them (it should not).
- Decrypted contact names or message history stored only on the device.

### Offline guessing boundary

The server stores `authSalt` and `bcrypt(authSecret)`. If `authSecret` were a
low-entropy value, the bcrypt hash would permit offline guessing; it is a
310,000-iteration PBKDF2 output of the password, so the attacker is effectively
guessing the password, slowed by both PBKDF2 and bcrypt. Without the client's
wrapped private key, a successful guess of `authSecret` still does not yield the
private key.

If an attacker obtains **both** a copy of the client's IndexedDB wrapped-key
record and the server's `authSalt`/hash, the attacker can guess the password,
derive `wrapKey`, and unwrap the private key. This is inherent to password-based
key wrapping. A strong, unique password is part of the security contract.

## 5. Trust assumptions

1. TLS is used in production, the client validates certificates, and users do
   not click through certificate warnings.
2. The server enforces authorization, rate limits, body-size limits, and the
   documented data-minimization rules.
3. The served client code is the reviewed code. A malicious or compromised
   server can bypass every client-side guarantee.
4. `libsodium-wrappers`, the browser's Web Crypto implementation, and bcrypt are
   correct and not backdoored. Dependency integrity and update review are
   operational responsibilities.
5. The user's browser, OS, and extensions are not compromised.
6. The user chooses a strong unique password and protects the device.
7. The user compares safety numbers out of band when identity assurance matters.
8. Usernames are unique and registration is controlled enough to limit
   impersonation and spam.
9. The server does not log request bodies, cookies, `authSecret`, or message
   contents. This is a policy and implementation requirement, not a cryptographic
   guarantee.

## 6. Non-goals and explicit limitations

- **No forward secrecy and no post-compromise security.** The design uses static
  box keys. If a private key is later compromised, an attacker who also has
  recorded ciphertext can decrypt past messages for that identity. There is no
  ratchet, no ephemeral key exchange, and no key erasure schedule.
- **No deniability.** Parley makes no cryptographic or legal deniability claim.
- **No metadata hiding.** The server sees the contact graph, timestamps, sizes,
  and activity. There is no sealed sender, mixnet, cover traffic, or padding.
- **No multi-device support.** The private key is stored only in the browser
  profile that created it. There is no key sync, device enrollment, or
  multi-device history.
- **No key recovery.** Forgetting the password or clearing site data makes the
  private key unrecoverable and history unreadable. There is no recovery key,
  escrow, or server-side wrapped copy. Password reset cannot restore history.
- **Trust-on-first-use key pinning is not authentication.** Parley pins keys on
  first contact and blocks a changed key until acknowledged, but first contact
  is vulnerable to server-side substitution. TOFU is a change-detection
  mechanism; only an out-of-band safety-number comparison provides identity
  assurance, and only if the user actually performs it.
- **No protection from a malicious server serving modified JavaScript.** See
  above. This includes a compromised CDN, dependency, or deployment pipeline.
- **No protection from a compromised endpoint.** Malware, browser extensions,
  XSS, and a compromised OS are outside the model.
- **No group chat.** Only 1:1 conversations are in scope.
- **No disappearing messages or guaranteed secure deletion.** The server may
  retain ciphertext; backups and browser storage may retain copies.
- **No message padding or traffic-analysis resistance.** Ciphertext sizes leak
  approximate plaintext sizes.
- **No anonymity.** Usernames and IP addresses are visible to the server.
- **No spam prevention beyond rate limits.**
- **No password policy enforcement on the server.** The server never sees the
  password; the client must enforce a minimum length and warn about weak
  passwords.
- **No quantum resistance.**
- **No secure hardware key storage.** The wrapped key is ordinary IndexedDB
  data, not protected by a secure enclave.
- **No formal verification or third-party audit.** This is a portfolio design
  and should not be used for high-risk communication without review.

## 7. Residual risks and open questions

- First-contact key substitution by a malicious server is possible. Safety
  numbers mitigate it only after out-of-band verification.
- A stolen device with a weak password is likely to lose message history.
- A server that serves malicious JavaScript defeats the design.
- Username enumeration and traffic analysis are not fully addressed. The
  `GET /auth/params` endpoint should return a synthetic salt for unknown
  usernames so responses are indistinguishable, but timing and rate limits can
  still leak information.
- There is no protocol for key rotation, account deletion, or device migration.
  These need explicit designs before they are claimed.
- `authSecret` is a bearer credential. A server that logs it can authenticate as
  the user to the server, but still cannot forge `crypto_box_easy` messages
  without the private key.
- Message ordering, duplicate delivery, replay, and retention are transport
  concerns. The MVP deduplicates by message id and tolerates reordering, but it
  does not claim exactly-once delivery.
- The safety number proves both parties see the same two public keys; it does
  not prove the keys belong to the humans the usernames suggest.

## 8. Out-of-scope feature checklist

| Feature | Status |
|---|---|
| Forward secrecy / ratchet | Not implemented, not claimed |
| Post-compromise security | Not implemented, not claimed |
| Deniability | Not claimed |
| Metadata protection | Not implemented |
| Multi-device / key sync | Not implemented |
| Key recovery / escrow | Not implemented |
| Group chat | Not implemented |
| Disappearing messages | Not implemented |
| Attachments | Not implemented |
| Read receipts / typing indicators | Not implemented |
| Push notifications | Not implemented |
| Account deletion / key rotation | Not designed |
| Malicious-server code transparency | Not implemented |
