/**
 * The only value the UI persists in localStorage.
 *
 * Passwords, derived secrets, and key material must never be written here.
 */

const LAST_USERNAME_KEY = 'parley.lastUsername'

export function readLastUsername(): string {
  try {
    return localStorage.getItem(LAST_USERNAME_KEY) ?? ''
  } catch {
    return ''
  }
}

export function saveLastUsername(username: string): void {
  try {
    localStorage.setItem(LAST_USERNAME_KEY, username)
  } catch {
    // A blocked or full localStorage must not break sign-in.
  }
}
