/**
 * Local-only removal of a device identity.
 *
 * This deletes the wrapped private-key record and the contact pins owned by the
 * same username from IndexedDB. It never contacts the server: the account (and
 * its ciphertext) remain, and the key is unrecoverable.
 */
import { StorageError } from '../crypto/errors'
import { loadCrypto } from './cryptoLoader'

const DB_NAME = 'parley'
const DB_VERSION = 1
const CONTACT_STORE = 'contacts'

function openDatabase(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    try {
      if (typeof indexedDB === 'undefined') {
        reject(new StorageError('IndexedDB is not available'))
        return
      }
      const request = indexedDB.open(DB_NAME, DB_VERSION)
      request.onupgradeneeded = () => {
        const db = request.result
        if (!db.objectStoreNames.contains('identity')) {
          db.createObjectStore('identity', { keyPath: 'username' })
        }
        if (!db.objectStoreNames.contains(CONTACT_STORE)) {
          db.createObjectStore(CONTACT_STORE)
        }
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () =>
        reject(new StorageError('Could not open the parley database'))
      request.onblocked = () =>
        reject(new StorageError('The parley database upgrade was blocked'))
    } catch {
      reject(new StorageError('Could not open the parley database'))
    }
  })
}

/** Delete every pinned contact whose owner is `owner`. */
export async function deleteContactsForOwner(owner: string): Promise<void> {
  const db = await openDatabase()
  await new Promise<void>((resolve, reject) => {
    try {
      const transaction = db.transaction(CONTACT_STORE, 'readwrite')
      const store = transaction.objectStore(CONTACT_STORE)
      const keysRequest = store.getAllKeys()
      keysRequest.onsuccess = () => {
        for (const key of keysRequest.result) {
          if (typeof key === 'string' && key.startsWith(`${owner}:`)) {
            store.delete(key)
          }
        }
      }
      transaction.oncomplete = () => resolve()
      transaction.onerror = () => reject(new StorageError('Delete failed'))
      transaction.onabort = () => reject(new StorageError('Delete aborted'))
    } catch {
      reject(new StorageError('Delete failed'))
    }
  })
  db.close()
}

/**
 * Remove the local identity and its contact pins for `username`.
 *
 * The server is deliberately not called. If the account exists server-side, the
 * user can only recover it by registering again with a fresh key.
 */
export async function removeDeviceKey(username: string): Promise<void> {
  const crypto = await loadCrypto()
  await crypto.deleteIdentity(username)
  await deleteContactsForOwner(username)
}
