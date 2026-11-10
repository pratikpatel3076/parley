/**
 * Public surface of the Parley client crypto layer.
 *
 * Import from `frontend/src/crypto` (or the `./crypto` directory) rather than
 * reaching into individual modules, so the API stays reviewable.
 */

export {
  PBKDF2_ITERATIONS,
  DOMAIN_AUTH,
  DOMAIN_WRAP,
  DOMAIN_SAFETY,
  ENVELOPE_VERSION,
  WRAPPED_KEY_VERSION,
  KDF_PBKDF2_SHA256,
  USERNAME_PATTERN,
  KEY_BYTES,
  NONCE_BYTES,
  SALT_BYTES,
  IV_BYTES,
  AUTH_SECRET_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_ENVELOPE_BYTES,
  MIN_PASSWORD_LENGTH,
  MIN_PASSWORD_SCORE,
} from './constants'

export {
  ParleyError,
  DecryptionError,
  KeyChangedError,
  WrongPasswordError,
  EnvelopeMismatchError,
  InvalidInputError,
  WeakPasswordError,
  StorageError,
} from './errors'

export { ready, sodium } from './sodium'

export { assertUsername, deriveAuthSecret } from './derive'

export {
  generateIdentity,
  wrapSecretKey,
  unwrapSecretKey,
  type Identity,
  type WrappedKey,
  type WrapOptions,
} from './keys'

export {
  saveIdentity,
  loadIdentity,
  deleteIdentity,
  getContact,
  putContact,
  setVerified,
  type StoredIdentity,
  type StoredContact,
} from './storage'

export {
  encryptMessage,
  decryptReceived,
  decryptSent,
  type EncryptedMessage,
  type DecryptedMessage,
  type EncryptMessageInput,
  type DecryptReceivedInput,
  type DecryptSentInput,
} from './messages'

export { safetyNumber, pinOrCheckContact, acknowledgeKeyChange } from './verify'

export {
  checkPassword,
  assertStrongPassword,
  type PasswordCheckResult,
  type PasswordFeedback,
} from './password'
