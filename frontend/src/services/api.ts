const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'https://localhost:8443/api'
const BACKEND_BASE_URL = import.meta.env.VITE_BACKEND_BASE_URL ?? 'https://localhost:8443'

export const GOOGLE_LOGIN_URL = `${BACKEND_BASE_URL}/oauth2/authorization/google`

export interface ClientCryptoMaterial {
  kdfSaltBase64: string
  kdfIterations: number
  publicKeySpkiBase64: string
  encryptedPrivateKeyBase64: string
  privateKeyIvBase64: string
}

export interface RegistrationResult {
  userId: number
  username: string
  status: string
  totpSecret: string
  totpProvisioningUri: string
}

export interface AuthenticatedUser {
  id: number
  username: string
  email: string
  role: string
  accessExpiresAt: string | null
}

export interface VaultCryptoMaterial {
  kdfAlgorithm: string
  kdfSaltBase64: string
  kdfIterations: number
  publicKeyAlgorithm: string
  publicKeySpkiBase64: string
  encryptedPrivateKeyBase64: string
  privateKeyIvBase64: string
  privateKeyAlgorithm: string
  cryptoVersion: number
}

export interface EncryptedSecretPayload {
  encryptedBlobBase64: string
  encryptionIvBase64: string
  wrappedDataKeyBase64: string
}

export interface VaultSecretCipher extends EncryptedSecretPayload {
  secretId: number
  versionNumber: number
  encryptionAlgorithm: string
  wrappingAlgorithm: string
  createdAt: string
  updatedAt: string
  rotationDueAt: string | null
}

export interface SecurityPolicy {
  minimumLoginPasswordLength: number
  minimumMasterPasswordLength: number
  maximumFailedLoginAttempts: number
  secretRotationDays: number
}

export interface AdminUser {
  id: number
  username: string
  email: string
  role: string
  status: string
  mfaEnabled: boolean
  failedLoginAttempts: number
  lockedUntil: string | null
  activeSessionCount: number
}

export interface BlockedIpAddress {
  ipAddress: string
  reason: string
  blockedUntil: string
  createdAt: string
}

export interface HoneypotStatus {
  enabled: boolean
  enabledUntil: string | null
  enabledBy: number | null
}

export interface SecurityAlert {
  id: number
  userId: number | null
  username: string | null
  alertType: string
  severity: string
  ipAddress: string | null
  description: string
  acknowledgedBy: number | null
  acknowledgedAt: string | null
  createdAt: string
}

export interface AuditLogEntry {
  id: number
  actorUserId: number | null
  actorUsername: string | null
  eventType: string
  targetType: string | null
  targetId: string | null
  targetUsername: string | null
  ipAddress: string | null
  eventData: string
  occurredAt: string
  previousHash: string | null
  entryHash: string
}

export interface AuditIntegrity {
  valid: boolean
  checkedRecords: number
  brokenAtId: number | null
  message: string
}

export interface HoneypotDemoStatus {
  enabled: boolean
  enabledUntil?: string
}

export interface HoneypotDemoResult {
  triggered: boolean
  message: string
}

export interface ShareRecipient {
  userId: number
  username: string
  email: string
  publicKeyAlgorithm: string
  publicKeySpkiBase64: string
}

export interface SharedRecipient {
  userId: number
  username: string
  email: string
}

export interface ReceivedSecretCipher extends VaultSecretCipher {
  ownerUserId: number
  ownerUsername: string
}

interface ApiErrorBody { error?: string }

interface SessionRefreshResponse { accessExpiresAt: string }

let refreshInFlight: Promise<SessionRefreshResponse> | null = null

async function csrfToken(): Promise<string> {
  return (await request<{ token: string }>('/auth/csrf')).token
}

function send(path: string, options: RequestInit = {}): Promise<Response> {
  return fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers: { ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers },
  })
}

function canAutomaticallyRefresh(path: string): boolean {
  return path === '/auth/me'
    || path === '/auth/csrf'
    || path.startsWith('/vault/')
    || path.startsWith('/sharing/')
    || path.startsWith('/admin/')
}

async function readError(response: Response): Promise<string> {
  let message = `Zahtjev nije uspio (HTTP ${response.status})`
  try {
    const body = await response.json() as ApiErrorBody
    message = body.error ?? message
  } catch { /* Sigurnosni odgovor može biti bez JSON tijela. */ }
  return message
}

async function performRefresh(): Promise<SessionRefreshResponse> {
  const response = await send('/auth/refresh', { method: 'POST' })
  if (!response.ok) throw new Error(await readError(response))
  const refreshed = await response.json() as SessionRefreshResponse
  window.dispatchEvent(new CustomEvent('secure-vault:session-refreshed', { detail: refreshed }))
  return refreshed
}

function refreshOnce(): Promise<SessionRefreshResponse> {
  if (!refreshInFlight) {
    refreshInFlight = performRefresh().finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  let response = await send(path, options)

  if (response.status === 401 && canAutomaticallyRefresh(path)) {
    try {
      await refreshOnce()
      response = await send(path, options)
    } catch {
      window.dispatchEvent(new Event('secure-vault:session-expired'))
      throw new Error('Sesija je istekla. Prijavi se ponovo.')
    }
  }

  if (!response.ok) {
    if (response.status === 401 && canAutomaticallyRefresh(path)) {
      window.dispatchEvent(new Event('secure-vault:session-expired'))
    }
    throw new Error(await readError(response))
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const api = {
  publicSecurityPolicy: () => request<SecurityPolicy>('/security-policy/public'),
  register: (body: { username: string; email: string; loginPassword: string; cryptoMaterial: ClientCryptoMaterial }) => request<RegistrationResult>('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
  setupOidc: (cryptoMaterial: ClientCryptoMaterial) => request<RegistrationResult>('/auth/oidc/setup', { method: 'POST', body: JSON.stringify(cryptoMaterial) }),
  loginOidcMfa: (body: { code: string }) => request<AuthenticatedUser>('/auth/oidc/mfa', { method: 'POST', body: JSON.stringify(body) }),
  confirmMfa: (body: { username: string; code: string }) => request<{ message: string }>('/auth/mfa/confirm', { method: 'POST', body: JSON.stringify(body) }),
  loginPassword: (body: { username: string; password: string }) => request<{ mfaRequired: boolean; mfaChallenge: string; expiresAt: string }>('/auth/login/password', { method: 'POST', body: JSON.stringify(body) }),
  loginMfa: (body: { mfaChallenge: string; code: string }) => request<AuthenticatedUser>('/auth/login/mfa', { method: 'POST', body: JSON.stringify(body) }),
  me: () => request<AuthenticatedUser>('/auth/me'),
  refresh: () => refreshOnce(),
  logout: () => request<{ message: string }>('/auth/logout', { method: 'POST' }),
  vaultCryptoMaterial: () => request<VaultCryptoMaterial>('/vault/crypto-material'),
  listSecrets: () => request<VaultSecretCipher[]>('/vault/secrets'),
  createSecret: async (body: EncryptedSecretPayload) => {
    return request<{ secretId: number; versionNumber: number }>('/vault/secrets', {
      method: 'POST',
      headers: { 'X-XSRF-TOKEN': await csrfToken() },
      body: JSON.stringify(body),
    })
  },
  updateSecret: async (secretId: number, body: EncryptedSecretPayload) => request<{ secretId: number; versionNumber: number }>(`/vault/secrets/${secretId}`, {
    method: 'PUT',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
    body: JSON.stringify(body),
  }),
  rotateSecret: async (secretId: number, body: EncryptedSecretPayload) => request<{ secretId: number; versionNumber: number }>(`/vault/secrets/${secretId}/rotate`, {
    method: 'PUT',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
    body: JSON.stringify(body),
  }),
  deleteSecret: async (secretId: number) => request<void>(`/vault/secrets/${secretId}`, {
    method: 'DELETE',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  listAdminUsers: () => request<AdminUser[]>('/admin/users'),
  listBlockedIps: () => request<BlockedIpAddress[]>('/admin/blocked-ips'),
  unblockIp: async (ipAddress: string) => request<void>(`/admin/blocked-ips/${encodeURIComponent(ipAddress)}`, {
    method: 'DELETE',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  adminSecurityPolicy: () => request<SecurityPolicy>('/admin/security-policy'),
  updateSecurityPolicy: async (body: SecurityPolicy) => request<SecurityPolicy>('/admin/security-policy', {
    method: 'PUT', headers: { 'X-XSRF-TOKEN': await csrfToken() }, body: JSON.stringify(body),
  }),
  honeypotStatus: () => request<HoneypotStatus>('/admin/honeypot/status'),
  configureHoneypot: async (enabled: boolean, durationMinutes = 5) => request<HoneypotStatus>('/admin/honeypot/status', {
    method: 'PUT',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
    body: JSON.stringify({ enabled, durationMinutes }),
  }),
  listSecurityAlerts: () => request<SecurityAlert[]>('/admin/security-alerts'),
  listAuditLogs: () => request<AuditLogEntry[]>('/admin/audit'),
  verifyAuditIntegrity: () => request<AuditIntegrity>('/admin/audit/integrity'),
  acknowledgeSecurityAlert: async (alertId: number) => request<SecurityAlert>(`/admin/security-alerts/${alertId}/acknowledge`, {
    method: 'POST',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  honeypotDemoStatus: () => request<HoneypotDemoStatus>('/demo/honeypot/status'),
  runHoneypotDemo: async (query: string): Promise<HoneypotDemoResult> => {
    const response = await send(`/demo/honeypot/search?q=${encodeURIComponent(query)}`)
    const body = await response.json() as { code?: string; error?: string; matches?: number }
    if (response.status === 403 && body.code === 'HONEYTOKEN_TRIGGERED') {
      return { triggered: true, message: body.error ?? 'Honeytoken je aktiviran.' }
    }
    if (!response.ok) throw new Error(body.error ?? `Zahtjev nije uspio (HTTP ${response.status})`)
    return { triggered: false, message: 'Honeytoken nije pronađen.' }
  },
  promoteToTeamLead: async (userId: number) => request<AdminUser>(`/admin/users/${userId}/promote-team-lead`, {
    method: 'POST',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  demoteToDeveloper: async (userId: number) => request<AdminUser>(`/admin/users/${userId}/demote-developer`, {
    method: 'POST',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  freezeUser: (userId: number) => adminUserAction(userId, 'freeze'),
  unfreezeUser: (userId: number) => adminUserAction(userId, 'unfreeze'),
  disableUser: (userId: number) => adminUserAction(userId, 'disable'),
  unlockUser: (userId: number) => adminUserAction(userId, 'unlock'),
  revokeUserSessions: (userId: number) => adminUserAction(userId, 'revoke-sessions'),
  listShareRecipients: () => request<ShareRecipient[]>('/sharing/developers'),
  listSharedRecipients: (secretId: number) => request<SharedRecipient[]>(`/sharing/secrets/${secretId}/recipients`),
  shareSecret: async (secretId: number, body: { recipientUserId: number; versionNumber: number; wrappedDataKeyBase64: string }) => request<void>(`/sharing/secrets/${secretId}`, {
    method: 'POST',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
    body: JSON.stringify(body),
  }),
  revokeSecretAccess: async (secretId: number, recipientId: number) => request<void>(`/sharing/secrets/${secretId}/recipients/${recipientId}`, {
    method: 'DELETE',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  }),
  listReceivedSecrets: () => request<ReceivedSecretCipher[]>('/sharing/received'),
}

async function adminUserAction(userId: number, action: string): Promise<AdminUser> {
  return request<AdminUser>(`/admin/users/${userId}/${action}`, {
    method: 'POST',
    headers: { 'X-XSRF-TOKEN': await csrfToken() },
  })
}
