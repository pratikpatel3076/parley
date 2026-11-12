/**
 * HTTP client for the Parley API.
 *
 * Security notes:
 * - Cookies are the only credential. Every request uses `credentials: "include"`.
 * - The raw password never reaches this module. Callers pass the derived
 *   `authSecret`, which is still a bearer credential; request bodies are never
 *   copied into errors, logs, or URLs.
 * - A 401 on a normal endpoint triggers at most one refresh and one retry. Auth
 *   endpoints never refresh, so a failed login cannot loop.
 */

const API_BASE = '/api/v1'
const REFRESH_PATH = `${API_BASE}/auth/refresh`
const REFRESH_LOCK = 'parley-refresh'
const REFRESH_RETRY_DELAY_MS = 300

const AUTH_PATHS = [
  `${API_BASE}/auth/register`,
  `${API_BASE}/auth/login`,
  `${API_BASE}/auth/refresh`,
  `${API_BASE}/auth/logout`,
]

/** Emitted on `window` when refresh and the retry both return 401. */
export const SESSION_EXPIRED_EVENT = 'session-expired'

/** A failed API call. `status` is 0 for a network failure. */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export interface UserPayload {
  id: string
  username: string
  public_key: string
  created_at: string
}

export interface AuthResponse {
  user: UserPayload
}

export interface PublicKeyResponse {
  username: string
  public_key: string
}

export interface RegisterInput {
  username: string
  authSecret: string
  publicKey: string
}

export interface LoginInput {
  username: string
  authSecret: string
}

function isAuthPath(path: string): boolean {
  return AUTH_PATHS.some(
    (authPath) => path === authPath || path.startsWith(`${authPath}?`),
  )
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds)
  })
}

function emitSessionExpired(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT))
  }
}

/** Send one request. Network failures become a typed, safe error. */
function send(path: string, init: RequestInit): Promise<Response> {
  const headers = new Headers(init.headers)
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  return fetch(path, {
    ...init,
    headers,
    credentials: 'include',
  }).catch(() => {
    // Do not inspect or include the request body: it may hold an authSecret.
    throw new ApiError(0, 'Could not reach the server')
  })
}

function safeDetail(data: unknown): string | undefined {
  if (typeof data !== 'object' || data === null) {
    return undefined
  }
  const detail = (data as { detail?: unknown }).detail
  return typeof detail === 'string' && detail.length > 0 ? detail : undefined
}

async function parseResponse(response: Response): Promise<unknown> {
  const text = await response.text()
  let data: unknown = null
  if (text.length > 0) {
    try {
      data = JSON.parse(text)
    } catch {
      data = null
    }
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      safeDetail(data) ?? `Request failed (${response.status})`,
    )
  }

  return data
}

/** Result of a refresh: `null` means success, otherwise an HTTP status (0 = network). */
let refreshPromise: Promise<number | null> | null = null

async function refreshRequest(): Promise<number | null> {
  try {
    const response = await fetch(REFRESH_PATH, {
      method: 'POST',
      credentials: 'include',
    })
    return response.ok ? null : response.status
  } catch {
    return 0
  }
}

async function withRefreshLock(
  task: () => Promise<number | null>,
): Promise<number | null> {
  const locks =
    typeof navigator !== 'undefined' ? navigator.locks : undefined
  if (locks !== undefined && typeof locks.request === 'function') {
    // Serialize across tabs. Inside a tab, `refreshPromise` is the single flight.
    return locks.request(REFRESH_LOCK, task)
  }
  return task()
}

function refreshSession(): Promise<number | null> {
  if (refreshPromise === null) {
    refreshPromise = withRefreshLock(refreshRequest).finally(() => {
      refreshPromise = null
    })
  }
  return refreshPromise
}

/**
 * Fetch a Parley endpoint with cookies.
 *
 * On a 401 from a non-auth endpoint the client refreshes once and retries the
 * original request once. If the refresh itself returns 401, the client waits
 * briefly for another tab's rotation and retries the original request once. A
 * second 401 emits {@link SESSION_EXPIRED_EVENT} and throws `ApiError(401)`.
 */
export async function apiFetch<T = unknown>(
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await send(path, init)
  if (response.status !== 401 || isAuthPath(path)) {
    return (await parseResponse(response)) as T
  }

  const refreshStatus = await refreshSession()
  if (refreshStatus === null) {
    const retry = await send(path, init)
    return (await parseResponse(retry)) as T
  }

  if (refreshStatus === 401) {
    await delay(REFRESH_RETRY_DELAY_MS)
    const retry = await send(path, init)
    if (retry.status === 401) {
      emitSessionExpired()
      throw new ApiError(401, 'Session expired')
    }
    return (await parseResponse(retry)) as T
  }

  throw new ApiError(
    refreshStatus === 0 ? 0 : refreshStatus,
    refreshStatus === 0
      ? 'Could not reach the server'
      : 'Could not refresh the session',
  )
}

/** Create an account. The server also starts a session. */
export function register(input: RegisterInput): Promise<AuthResponse> {
  return apiFetch<AuthResponse>(`${API_BASE}/auth/register`, {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/** Verify the derived auth secret and start a session. */
export function login(input: LoginInput): Promise<AuthResponse> {
  return apiFetch<AuthResponse>(`${API_BASE}/auth/login`, {
    method: 'POST',
    body: JSON.stringify(input),
  })
}

/** Revoke the current sessions. Idempotent; never requires a valid session. */
export async function logout(): Promise<void> {
  await apiFetch(`${API_BASE}/auth/logout`, { method: 'POST' })
}

/** Fetch a user's public key. Requires a session. */
export function getUserKey(username: string): Promise<PublicKeyResponse> {
  return apiFetch<PublicKeyResponse>(
    `${API_BASE}/users/${encodeURIComponent(username)}/key`,
  )
}
