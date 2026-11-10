import { beforeEach, describe, expect, it } from 'vitest'

import {
  DecryptionError,
  EnvelopeMismatchError,
  InvalidInputError,
  KeyChangedError,
  MAX_PLAINTEXT_BYTES,
  PBKDF2_ITERATIONS,
  ParleyError,
  WeakPasswordError,
  WrongPasswordError,
  acknowledgeKeyChange,
  assertStrongPassword,
  checkPassword,
  decryptReceived,
  decryptSent,
  deleteIdentity,
  deriveAuthSecret,
  encryptMessage,
  generateIdentity,
  getContact,
  loadIdentity,
  pinOrCheckContact,
  ready,
  safetyNumber,
  saveIdentity,
  setVerified,
  sodium,
  unwrapSecretKey,
  wrapSecretKey,
  type Identity,
  type WrappedKey,
} from './index'

// PBKDF2 at 600k iterations is correct but too slow for every unit test. The
// public API allows an explicit lower count for tests only.
const ITERATIONS = 1_000

function b64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL)
}

function fromB64(value: string): Uint8Array {
  return sodium.from_base64(value, sodium.base64_variants.ORIGINAL)
}

function tamper(value: string): string {
  const bytes = fromB64(value)
  bytes[0] ^= 0xff
  return b64(bytes)
}

function username(prefix = 'u'): string {
  return `${prefix}${Math.random().toString(36).slice(2, 12)}`
}

async function identities(): Promise<[Identity, Identity, Identity]> {
  return Promise.all([
    generateIdentity(),
    generateIdentity(),
    generateIdentity(),
  ])
}

beforeEach(async () => {
  await ready()
})

describe('constants', () => {
  it('uses 600,000 PBKDF2 iterations by default', () => {
    expect(PBKDF2_ITERATIONS).toBe(600_000)
  })
})

describe('deriveAuthSecret', () => {
  it('is deterministic and decodes to exactly 32 bytes', async () => {
    const first = await deriveAuthSecret('correct horse battery', 'alice', ITERATIONS)
    const second = await deriveAuthSecret('correct horse battery', 'alice', ITERATIONS)

    expect(first).toBe(second)
    expect(fromB64(first)).toHaveLength(32)
  })

  it('changes with the username and with the password', async () => {
    const base = await deriveAuthSecret('same-password', 'alice', ITERATIONS)
    const otherUser = await deriveAuthSecret('same-password', 'bob', ITERATIONS)
    const otherPassword = await deriveAuthSecret('other-password', 'alice', ITERATIONS)

    expect(base).not.toBe(otherUser)
    expect(base).not.toBe(otherPassword)
  })

  it('treats NFKC-equivalent passwords as identical', async () => {
    const composed = 'p\u00e4ssw\u00f6rd-\u00e9\u00e9'
    const decomposed = 'pa\u0308sswo\u0308rd-e\u0301e\u0301'

    const first = await deriveAuthSecret(composed, 'alice', ITERATIONS)
    const second = await deriveAuthSecret(decomposed, 'alice', ITERATIONS)

    expect(first).toBe(second)
  })

  it('rejects an invalid username', async () => {
    await expect(
      deriveAuthSecret('correct horse battery', 'Not-A-User', ITERATIONS),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })

  it('rejects an empty password', async () => {
    await expect(
      deriveAuthSecret('', 'alice', ITERATIONS),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })
})

describe('key wrapping', () => {
  it('never stores the password or the auth secret in the blob', async () => {
    const alice = await generateIdentity()
    const password = 'wrapping-password-9f3a'
    const authSecret = await deriveAuthSecret(password, 'alice', ITERATIONS)

    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      password,
      { iterations: ITERATIONS },
    )
    const serialized = JSON.stringify(blob)

    expect(serialized).not.toContain(password)
    expect(serialized).not.toContain(authSecret)
    expect(serialized).not.toContain(alice.secretKey)
    expect(blob.v).toBe(1)
    expect(blob.kdf).toBe('pbkdf2-sha256')
    expect(blob.iterations).toBe(ITERATIONS)
  })

  it('unwraps with the right password', async () => {
    const alice = await generateIdentity()
    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'right-password-123',
      { iterations: ITERATIONS },
    )

    const secret = await unwrapSecretKey(
      blob,
      alice.publicKey,
      'right-password-123',
    )

    expect(secret).toBe(alice.secretKey)
  })

  it('throws WrongPasswordError on a wrong password', async () => {
    const alice = await generateIdentity()
    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'right-password-123',
      { iterations: ITERATIONS },
    )

    await expect(
      unwrapSecretKey(blob, alice.publicKey, 'wrong-password-123'),
    ).rejects.toBeInstanceOf(WrongPasswordError)
  })

  it('fails when the blob is paired with a different public key', async () => {
    const [alice, bob] = await identities()
    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'right-password-123',
      { iterations: ITERATIONS },
    )

    await expect(
      unwrapSecretKey(blob, bob.publicKey, 'right-password-123'),
    ).rejects.toBeInstanceOf(WrongPasswordError)
  })

  it('fails on a tampered blob', async () => {
    const alice = await generateIdentity()
    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'right-password-123',
      { iterations: ITERATIONS },
    )
    const tampered: WrappedKey = {
      ...blob,
      ciphertext: tamper(blob.ciphertext),
    }

    await expect(
      unwrapSecretKey(tampered, alice.publicKey, 'right-password-123'),
    ).rejects.toBeInstanceOf(WrongPasswordError)
  })

  it('rejects a structurally invalid blob with InvalidInputError', async () => {
    const alice = await generateIdentity()
    const blob = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'right-password-123',
      { iterations: ITERATIONS },
    )

    await expect(
      unwrapSecretKey(
        { ...blob, kdf: 'md5' } as unknown as WrappedKey,
        alice.publicKey,
        'right-password-123',
      ),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })
})

describe('message encryption', () => {
  it('round-trips a message from Alice to Bob', async () => {
    const [alice, bob] = await identities()
    const clientMessageId = crypto.randomUUID()

    const encrypted = await encryptMessage({
      plaintext: 'hello bob',
      clientMessageId,
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    const decrypted = await decryptReceived({
      ...encrypted,
      clientMessageId,
      senderPublicKey: alice.publicKey,
      recipientSecretKey: bob.secretKey,
    })

    expect(decrypted.plaintext).toBe('hello bob')
    expect(typeof decrypted.timestamp).toBe('number')
  })

  it('lets the sender decrypt their own sent message', async () => {
    const [alice, bob] = await identities()
    const clientMessageId = crypto.randomUUID()
    const encrypted = await encryptMessage({
      plaintext: 'saved to sent history',
      clientMessageId,
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    const decrypted = await decryptSent({
      ...encrypted,
      clientMessageId,
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    expect(decrypted.plaintext).toBe('saved to sent history')
  })

  it('throws DecryptionError for tampered ciphertext', async () => {
    const [alice, bob] = await identities()
    const encrypted = await encryptMessage({
      plaintext: 'opaque body',
      clientMessageId: crypto.randomUUID(),
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    await expect(
      decryptReceived({
        nonce: encrypted.nonce,
        ciphertext: tamper(encrypted.ciphertext),
        clientMessageId: crypto.randomUUID(),
        senderPublicKey: alice.publicKey,
        recipientSecretKey: bob.secretKey,
      }),
    ).rejects.toBeInstanceOf(DecryptionError)
  })

  it('throws DecryptionError with the wrong key', async () => {
    const [alice, bob, carol] = await identities()
    const clientMessageId = crypto.randomUUID()
    const encrypted = await encryptMessage({
      plaintext: 'for bob only',
      clientMessageId,
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    await expect(
      decryptReceived({
        ...encrypted,
        clientMessageId,
        senderPublicKey: carol.publicKey,
        recipientSecretKey: bob.secretKey,
      }),
    ).rejects.toBeInstanceOf(DecryptionError)
  })

  it('throws EnvelopeMismatchError when the inner and outer ids differ', async () => {
    const [alice, bob] = await identities()
    const encrypted = await encryptMessage({
      plaintext: 'id check',
      clientMessageId: crypto.randomUUID(),
      recipientPublicKey: bob.publicKey,
      senderSecretKey: alice.secretKey,
    })

    await expect(
      decryptReceived({
        ...encrypted,
        clientMessageId: crypto.randomUUID(),
        senderPublicKey: alice.publicKey,
        recipientSecretKey: bob.secretKey,
      }),
    ).rejects.toBeInstanceOf(EnvelopeMismatchError)
  })

  it('rejects an oversized plaintext', async () => {
    const [alice, bob] = await identities()

    await expect(
      encryptMessage({
        plaintext: 'x'.repeat(MAX_PLAINTEXT_BYTES + 1),
        clientMessageId: crypto.randomUUID(),
        recipientPublicKey: bob.publicKey,
        senderSecretKey: alice.secretKey,
      }),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })

  it('uses a unique nonce across 1000 encryptions', async () => {
    const [alice, bob] = await identities()
    const nonces = new Set<string>()

    for (let index = 0; index < 1000; index += 1) {
      const encrypted = await encryptMessage({
        plaintext: 'same plaintext every time',
        clientMessageId: crypto.randomUUID(),
        recipientPublicKey: bob.publicKey,
        senderSecretKey: alice.secretKey,
      })
      nonces.add(encrypted.nonce)
    }

    expect(nonces.size).toBe(1000)
  })
})

describe('safety numbers', () => {
  it('is identical from both sides and formatted as 12 groups of 5 digits', async () => {
    const [alice, bob] = await identities()

    const fromAlice = await safetyNumber(alice.publicKey, bob.publicKey)
    const fromBob = await safetyNumber(bob.publicKey, alice.publicKey)

    expect(fromAlice).toBe(fromBob)
    const groups = fromAlice.split(' ')
    expect(groups).toHaveLength(12)
    for (const group of groups) {
      expect(group).toMatch(/^\d{5}$/)
    }
  })

  it('differs for a different key', async () => {
    const [alice, bob, carol] = await identities()

    const withBob = await safetyNumber(alice.publicKey, bob.publicKey)
    const withCarol = await safetyNumber(alice.publicKey, carol.publicKey)

    expect(withBob).not.toBe(withCarol)
  })
})

describe('storage and pinning', () => {
  it('round-trips a wrapped identity through IndexedDB', async () => {
    const alice = await generateIdentity()
    const owner = username()
    const wrapped = await wrapSecretKey(
      alice.secretKey,
      alice.publicKey,
      'identity-password-123',
      { iterations: ITERATIONS },
    )

    await saveIdentity({ username: owner, publicKey: alice.publicKey, wrapped })
    const loaded = await loadIdentity(owner)

    expect(loaded).toEqual({
      username: owner,
      publicKey: alice.publicKey,
      wrapped,
    })

    await deleteIdentity(owner)
    expect(await loadIdentity(owner)).toBeUndefined()
  })

  it('pins on first sight and accepts the same key again', async () => {
    const [alice, bob] = await identities()
    const owner = username()

    const first = await pinOrCheckContact(owner, username('b'), bob.publicKey)
    expect(first.verified).toBe(false)
    expect(first.publicKey).toBe(bob.publicKey)

    const second = await pinOrCheckContact(
      owner,
      first.username,
      bob.publicKey,
    )
    expect(second.firstSeen).toBe(first.firstSeen)

    // The pin is stored per owner and does not leak the private key.
    expect(await getContact(owner, first.username)).toEqual(first)
    expect(JSON.stringify(first)).not.toContain(alice.secretKey)
  })

  it('throws KeyChangedError when the pinned key changes', async () => {
    const [alice, bob] = await identities()
    const owner = username()
    const contactName = username('b')
    await pinOrCheckContact(owner, contactName, bob.publicKey)

    const attempt = pinOrCheckContact(owner, contactName, alice.publicKey)

    await expect(attempt).rejects.toBeInstanceOf(KeyChangedError)
    await expect(attempt).rejects.toMatchObject({
      username: contactName,
      pinnedKey: bob.publicKey,
      seenKey: alice.publicKey,
    })
  })

  it('acknowledgeKeyChange replaces the pin and resets verified', async () => {
    const [alice, bob] = await identities()
    const owner = username()
    const contactName = username('b')
    await pinOrCheckContact(owner, contactName, bob.publicKey)
    await setVerified(owner, contactName, true)
    expect((await getContact(owner, contactName))?.verified).toBe(true)

    const updated = await acknowledgeKeyChange(
      owner,
      contactName,
      alice.publicKey,
    )

    expect(updated.publicKey).toBe(alice.publicKey)
    expect(updated.verified).toBe(false)
    expect((await getContact(owner, contactName))?.verified).toBe(false)
  })

  it('refuses to verify an unknown contact', async () => {
    await expect(
      setVerified(username(), username('b'), true),
    ).rejects.toBeInstanceOf(InvalidInputError)
  })
})

describe('password policy', () => {
  it('rejects a short password', () => {
    const result = checkPassword('Sh0rt!', 'alice')

    expect(result.ok).toBe(false)
  })

  it('rejects a long but weak password', () => {
    const result = checkPassword('aaaaaaaaaaaa', 'alice')

    expect(result.ok).toBe(false)
    expect(result.score).toBeLessThan(3)
  })

  it('accepts a strong password', () => {
    const result = checkPassword('vN7#qL2$wR9!tY4@', 'alice')

    expect(result.ok).toBe(true)
    expect(result.score).toBeGreaterThanOrEqual(3)
  })

  it('assertStrongPassword throws WeakPasswordError', () => {
    expect(() => assertStrongPassword('Sh0rt!', 'alice')).toThrow(
      WeakPasswordError,
    )
  })

  it('preserves typed error identity', async () => {
    const alice = await generateIdentity()
    try {
      await unwrapSecretKey(
        {
          v: 1,
          kdf: 'pbkdf2-sha256',
          iterations: ITERATIONS,
          salt: b64(sodium.randombytes_buf(16)),
          iv: b64(sodium.randombytes_buf(12)),
          ciphertext: b64(sodium.randombytes_buf(48)),
        },
        alice.publicKey,
        'right-password-123',
      )
      throw new Error('expected unwrap to fail')
    } catch (error) {
      expect(error).toBeInstanceOf(ParleyError)
      expect(error).toBeInstanceOf(WrongPasswordError)
    }
  })
})
