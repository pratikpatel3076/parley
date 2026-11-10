/**
 * IndexedDB persistence for the wrapped identity and pinned contact keys.
 *
 * Only `WrappedKey` blobs are stored for identities. Raw secret keys and wrap
 * keys never reach IndexedDB, localStorage, sessionStorage, cookies, the
 * network, or logs.
 */
import { InvalidInputError, StorageError } from './errors'
import { assertUsername } from './derive'
import type { WrappedKey } from './keys'

const DB_NAME = 'parley'
const DB_VERSION = 1
const IDENTITY_STORE = 'identity'
const CONTACT_STORE = 'contacts'

export interface StoredIdentity {
  username: string
  publicKey: string
  wrapped: WrappedKey
}

export interface StoredContact {
  owner: string
  username: string
  publicKey: string
  /** Milliseconds since the epoch when this contact key was first pinned. */
  firstSeen: number
  verified: boolean
}

let databasePromise: Promise<IDBDatabase> | null = null

function contactKey(owner: string, username: string): string {
  return `${owner}:${username}`
}

function openDatabase(): Promise<IDBDatabase> {
  if (databasePromise !== null) {
    return databasePromise
  }

  databasePromise = new Promise<IDBDatabase>((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      reject(new StorageError('IndexedDB is not available'))
      return
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION)
    request.onupgradeneeded = () => {
      const db = request.result
      if (!db.objectStoreNames.contains(IDENTITY_STORE)) {
        db.createObjectStore(IDENTITY_STORE, { keyPath: 'username' })
      }
      if (!db.objectStoreNames.contains(CONTACT_STORE)) {
        // Out-of-line keys: owner + ":" + contact.
        db.createObjectStore(CONTACT_STORE)
      }
    }
    request.onsuccess = () => resolve(request.result)
    request.onerror = () =>
      reject(new StorageError('Could not open the parley database'))
    request.onblocked = () =>
      reject(new StorageError('The parley database upgrade was blocked'))
  })

  return databasePromise
}

async function read<T>(
  storeName: string,
  key: IDBValidKey,
): Promise<T | undefined> {
  const db = await openDatabase()
  return new Promise<T | undefined>((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readonly')
    const request = transaction.objectStore(storeName).get(key)
    let value: T | undefined
    request.onsuccess = () => {
      value = request.result as T | undefined
    }
    request.onerror = () => reject(new StorageError('Read failed'))
    transaction.oncomplete = () => resolve(value)
    transaction.onerror = () => reject(new StorageError('Read failed'))
    transaction.onabort = () => reject(new StorageError('Read aborted'))
  })
}

async function write(
  storeName: string,
  key: IDBValidKey | undefined,
  value: unknown,
): Promise<void> {
  const db = await openDatabase()
  return new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readwrite')
    const store = transaction.objectStore(storeName)
    if (key === undefined) {
      store.put(value)
    } else {
      store.put(value, key)
    }
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new StorageError('Write failed'))
    transaction.onabort = () => reject(new StorageError('Write aborted'))
  })
}

async function remove(storeName: string, key: IDBValidKey): Promise<void> {
  const db = await openDatabase()
  return new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readwrite')
    transaction.objectStore(storeName).delete(key)
    transaction.oncomplete = () => resolve()
    transaction.onerror = () => reject(new StorageError('Delete failed'))
    transaction.onabort = () => reject(new StorageError('Delete aborted'))
  })
}

/** Persist (or replace) the wrapped identity for a username. */
export async function saveIdentity(identity: StoredIdentity): Promise<void> {
  if (typeof identity !== 'object' || identity === null) {
    throw new InvalidInputError('identity must be an object')
  }
  assertUsername(identity.username)
  if (typeof identity.publicKey !== 'string') {
    throw new InvalidInputError('publicKey must be a string')
  }
  if (typeof identity.wrapped !== 'object' || identity.wrapped === null) {
    throw new InvalidInputError('wrapped must be an object')
  }
  await write(IDENTITY_STORE, undefined, identity)
}

/** Load the wrapped identity for a username, or undefined when absent. */
export async function loadIdentity(
  username: string,
): Promise<StoredIdentity | undefined> {
  assertUsername(username)
  return read<StoredIdentity>(IDENTITY_STORE, username)
}

/** Delete the stored identity for a username. Missing entries are a no-op. */
export async function deleteIdentity(username: string): Promise<void> {
  assertUsername(username)
  await remove(IDENTITY_STORE, username)
}

/** Read a pinned contact for an owner. */
export async function getContact(
  owner: string,
  username: string,
): Promise<StoredContact | undefined> {
  assertUsername(owner)
  assertUsername(username)
  return read<StoredContact>(CONTACT_STORE, contactKey(owner, username))
}

/** Insert or replace a contact record. */
export async function putContact(contact: StoredContact): Promise<void> {
  if (typeof contact !== 'object' || contact === null) {
    throw new InvalidInputError('contact must be an object')
  }
  assertUsername(contact.owner)
  assertUsername(contact.username)
  if (typeof contact.publicKey !== 'string' || contact.publicKey.length === 0) {
    throw new InvalidInputError('publicKey must be a non-empty string')
  }
  if (!Number.isFinite(contact.firstSeen)) {
    throw new InvalidInputError('firstSeen must be a finite number')
  }
  if (typeof contact.verified !== 'boolean') {
    throw new InvalidInputError('verified must be a boolean')
  }
  await write(
    CONTACT_STORE,
    contactKey(contact.owner, contact.username),
    contact,
  )
}

/** Update the verified flag; the contact must already be pinned. */
export async function setVerified(
  owner: string,
  username: string,
  verified: boolean,
): Promise<void> {
  assertUsername(owner)
  assertUsername(username)
  if (typeof verified !== 'boolean') {
    throw new InvalidInputError('verified must be a boolean')
  }

  const existing = await getContact(owner, username)
  if (existing === undefined) {
    throw new InvalidInputError('Cannot verify an unknown contact')
  }
  await putContact({ ...existing, verified })
}
