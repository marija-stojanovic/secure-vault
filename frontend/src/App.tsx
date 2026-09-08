import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import './App.css'
import { api, GOOGLE_LOGIN_URL, type AdminUser, type AuditIntegrity, type AuditLogEntry, type AuthenticatedUser, type BlockedIpAddress, type HoneypotDemoStatus, type HoneypotStatus, type ReceivedSecretCipher, type RegistrationResult, type SecurityAlert, type SecurityPolicy, type ShareRecipient, type SharedRecipient, type VaultSecretCipher } from './services/api'
import { createRegistrationCryptoMaterial, decryptSecret, encryptSecret, unlockVault, wrapSecretDataKeyForRecipient, type SecretPlaintext, type UnlockedVaultKeys } from './services/crypto'
import { MfaQrCode } from './components/MfaQrCode'

type View = 'register' | 'oidc-setup' | 'oidc-mfa' | 'activate' | 'login' | 'account'
type AdminSection = 'users' | 'policy' | 'gateway' | 'honeypot' | 'audit'
interface DecryptedVaultSecret { encrypted: VaultSecretCipher; plaintext: SecretPlaintext }
interface DecryptedReceivedSecret { encrypted: ReceivedSecretCipher; plaintext: SecretPlaintext }
interface ConfirmationRequest {
  title: string
  message: string
  confirmLabel: string
  danger?: boolean
  onConfirm: () => Promise<void>
}
interface SessionRefreshedDetail { accessExpiresAt: string }

const oidcParameters = new URLSearchParams(window.location.search)
const initialOidcResult = oidcParameters.get('oidc')
const oidcErrors: Record<string, string> = {
  'account-inactive': 'Lokalni nalog mora biti ACTIVE i imati potvrđen MFA.',
  'email-unverified': 'Google email adresa nije verifikovana.',
  'invalid-provider': 'Google identitet nije ispravan.',
  'provider-error': 'Google prijava nije završena ili je odbijena.',
}
const initialOidcError = initialOidcResult === 'error'
  ? oidcErrors[oidcParameters.get('reason') ?? ''] ?? 'Google OIDC prijava nije uspjela.'
  : ''
const defaultSecurityPolicy: SecurityPolicy = { minimumLoginPasswordLength: 12, minimumMasterPasswordLength: 14, maximumFailedLoginAttempts: 5, secretRotationDays: 90 }

function rotationExpired(rotationDueAt: string | null): boolean {
  return !rotationDueAt || new Date(rotationDueAt).getTime() <= Date.now()
}

function App() {
  const [view, setView] = useState<View>(initialOidcResult === 'setup' ? 'oidc-setup' : initialOidcResult === 'mfa' ? 'oidc-mfa' : 'login')
  const [busy, setBusy] = useState(initialOidcResult === 'success')
  const [message, setMessage] = useState('')
  const [error, setError] = useState(initialOidcError)
  const [registration, setRegistration] = useState<RegistrationResult | null>(null)
  const [oidcRegistration, setOidcRegistration] = useState(initialOidcResult === 'setup')
  const [challenge, setChallenge] = useState('')
  const [user, setUser] = useState<AuthenticatedUser | null>(null)
  const [vaultKeys, setVaultKeys] = useState<UnlockedVaultKeys | null>(null)
  const [vaultSecrets, setVaultSecrets] = useState<DecryptedVaultSecret[]>([])
  const [showCreateSecret, setShowCreateSecret] = useState(false)
  const [revealedSecretId, setRevealedSecretId] = useState<number | null>(null)
  const [editingSecretId, setEditingSecretId] = useState<number | null>(null)
  const [adminUsers, setAdminUsers] = useState<AdminUser[] | null>(null)
  const [blockedIps, setBlockedIps] = useState<BlockedIpAddress[] | null>(null)
  const [honeypotStatus, setHoneypotStatus] = useState<HoneypotStatus | null>(null)
  const [securityAlerts, setSecurityAlerts] = useState<SecurityAlert[] | null>(null)
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[] | null>(null)
  const [auditIntegrity, setAuditIntegrity] = useState<AuditIntegrity | null>(null)
  const [auditActorFilter, setAuditActorFilter] = useState('')
  const [auditEventFilter, setAuditEventFilter] = useState('')
  const [auditDateFilter, setAuditDateFilter] = useState('')
  const [honeypotDemoStatus, setHoneypotDemoStatus] = useState<HoneypotDemoStatus | null>(null)
  const [securityPolicy, setSecurityPolicy] = useState<SecurityPolicy>(defaultSecurityPolicy)
  const [showPolicyEditor, setShowPolicyEditor] = useState(false)
  const [managedUserId, setManagedUserId] = useState<number | null>(null)
  const [adminSection, setAdminSection] = useState<AdminSection>('users')
  const [confirmation, setConfirmation] = useState<ConfirmationRequest | null>(null)
  const [receivedSecrets, setReceivedSecrets] = useState<DecryptedReceivedSecret[]>([])
  const [revealedReceivedSecretId, setRevealedReceivedSecretId] = useState<number | null>(null)
  const [sharingSecretId, setSharingSecretId] = useState<number | null>(null)
  const [shareCandidates, setShareCandidates] = useState<ShareRecipient[]>([])
  const [sharedRecipients, setSharedRecipients] = useState<SharedRecipient[]>([])
  const managedUser = adminUsers?.find((listed) => listed.id === managedUserId) ?? null
  const expiredVaultSecrets = vaultSecrets.filter(({ encrypted }) => rotationExpired(encrypted.rotationDueAt))
  const activeReceivedSecrets = receivedSecrets.filter(({ encrypted }) => !rotationExpired(encrypted.rotationDueAt))
  const filteredAuditLogs = (auditLogs ?? []).filter((entry) =>
    (!auditActorFilter || String(entry.actorUserId ?? '').includes(auditActorFilter.trim()))
    && (!auditEventFilter || entry.eventType.toLowerCase().includes(auditEventFilter.trim().toLowerCase()))
    && (!auditDateFilter || entry.occurredAt.slice(0, 10) === auditDateFilter))

  useEffect(() => {
    api.publicSecurityPolicy().then(setSecurityPolicy).catch(() => { /* Sigurne zadane vrijednosti ostaju aktivne. */ })
  }, [])

  useEffect(() => {
    if (!user || user.role === 'ADMIN') {
      setHoneypotDemoStatus(null)
      return
    }
    api.honeypotDemoStatus().then(setHoneypotDemoStatus).catch(() => setHoneypotDemoStatus(null))
  }, [user])

  useEffect(() => {
    if (!initialOidcResult) return

    window.history.replaceState({}, '', window.location.pathname)
    if (initialOidcResult === 'success') {
      api.me()
        .then((authenticated) => {
          setUser(authenticated)
          setMessage('Prijava je uspješna.')
          setView('account')
        })
        .catch((caught) => setError(caught instanceof Error ? caught.message : 'OIDC sesija nije dostupna'))
        .finally(() => setBusy(false))
      return
    }

  }, [])

  useEffect(() => {
    const sessionExpired = () => {
      setVaultKeys(null)
      setVaultSecrets([])
      setShowCreateSecret(false)
      setRevealedSecretId(null)
      setEditingSecretId(null)
      setAdminUsers(null)
      setBlockedIps(null)
      setHoneypotStatus(null)
      setSecurityAlerts(null)
      setAuditLogs(null)
      setAuditIntegrity(null)
      setHoneypotDemoStatus(null)
      setShowPolicyEditor(false)
      setManagedUserId(null)
      setConfirmation(null)
      setReceivedSecrets([])
      setRevealedReceivedSecretId(null)
      setSharingSecretId(null)
      setShareCandidates([])
      setSharedRecipients([])
      setUser(null)
      setChallenge('')
      setMessage('')
      setError('Sesija je istekla. Vault je automatski zaključan.')
      setView('login')
    }
    window.addEventListener('secure-vault:session-expired', sessionExpired)
    const sessionRefreshed = (event: Event) => {
      const { accessExpiresAt } = (event as CustomEvent<SessionRefreshedDetail>).detail
      setVaultKeys(null)
      setVaultSecrets([])
      setShowCreateSecret(false)
      setRevealedSecretId(null)
      setEditingSecretId(null)
      setReceivedSecrets([])
      setRevealedReceivedSecretId(null)
      setSharingSecretId(null)
      setShareCandidates([])
      setSharedRecipients([])
      setUser((current) => current ? { ...current, accessExpiresAt } : current)
      setError('')
      setMessage('Sesija je obnovljena. Vault je zaključan.')
    }
    window.addEventListener('secure-vault:session-refreshed', sessionRefreshed)
    return () => {
      window.removeEventListener('secure-vault:session-expired', sessionExpired)
      window.removeEventListener('secure-vault:session-refreshed', sessionRefreshed)
    }
  }, [])

  useEffect(() => {
    if (!user?.accessExpiresAt) return
    const millisecondsUntilExpiry = new Date(user.accessExpiresAt).getTime() - Date.now()
    const timer = window.setTimeout(
      () => {
        setVaultKeys(null)
        setVaultSecrets([])
        setShowCreateSecret(false)
        setRevealedSecretId(null)
        setEditingSecretId(null)
        setAdminUsers(null)
        setBlockedIps(null)
        setHoneypotStatus(null)
        setSecurityAlerts(null)
        setAuditLogs(null)
        setAuditIntegrity(null)
        setHoneypotDemoStatus(null)
        setShowPolicyEditor(false)
        setManagedUserId(null)
        setConfirmation(null)
        setReceivedSecrets([])
        setRevealedReceivedSecretId(null)
        setSharingSecretId(null)
        setShareCandidates([])
        setSharedRecipients([])
        setMessage('Vault je zaključan zbog isteka access tokena.')
      },
      Math.max(0, millisecondsUntilExpiry),
    )
    return () => window.clearTimeout(timer)
  }, [user?.accessExpiresAt])

  function begin(next: View) {
    setView(next)
    setMessage('')
    setError('')
  }

  async function run(action: () => Promise<void>) {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      await action()
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Došlo je do greške')
    } finally {
      setBusy(false)
    }
  }

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const masterPassword = String(form.get('masterPassword'))
    const confirmation = String(form.get('masterPasswordConfirmation'))
    if (masterPassword !== confirmation) {
      setError('Master lozinke se ne podudaraju')
      return
    }
    await run(async () => {
      const cryptoMaterial = await createRegistrationCryptoMaterial(masterPassword, securityPolicy.minimumMasterPasswordLength)
      const result = await api.register({
        username: String(form.get('username')).trim(),
        email: String(form.get('email')).trim(),
        loginPassword: String(form.get('loginPassword')),
        cryptoMaterial,
      })
      formElement.reset()
      setRegistration(result)
      setOidcRegistration(false)
      setMessage('Nalog je kreiran. Postavi MFA.')
      setView('activate')
    })
  }

  async function setupOidcAccount(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const masterPassword = String(form.get('masterPassword'))
    if (masterPassword !== String(form.get('masterPasswordConfirmation'))) {
      setError('Master lozinke se ne podudaraju')
      return
    }
    await run(async () => {
      const cryptoMaterial = await createRegistrationCryptoMaterial(masterPassword, securityPolicy.minimumMasterPasswordLength)
      const result = await api.setupOidc(cryptoMaterial)
      formElement.reset()
      setRegistration(result)
      setOidcRegistration(true)
      setMessage('Nalog je kreiran. Postavi MFA.')
      setView('activate')
    })
  }

  async function confirmMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    await run(async () => {
      await api.confirmMfa({ username: String(form.get('username')).trim(), code: String(form.get('code')).trim() })
      setMessage(oidcRegistration
        ? 'MFA je aktiviran. Nastavi sa Google nalogom.'
        : 'MFA je aktiviran. Možeš se prijaviti.')
      setView('login')
    })
  }

  async function loginPassword(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    await run(async () => {
      const result = await api.loginPassword({ username: String(form.get('username')).trim(), password: String(form.get('password')) })
      setChallenge(result.mfaChallenge)
      setMessage('Unesi kod iz authenticator aplikacije.')
    })
  }

  async function loginMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    await run(async () => {
      const authenticated = await api.loginMfa({ mfaChallenge: challenge, code: String(form.get('code')).trim() })
      setUser(authenticated)
      setChallenge('')
      setMessage('Prijava je uspješna.')
      setView('account')
    })
  }

  async function loginOidcMfa(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    await run(async () => {
      const authenticated = await api.loginOidcMfa({ code: String(form.get('code')).trim() })
      setUser(authenticated)
      setMessage('Prijava je uspješna.')
      setView('account')
    })
  }

  async function loadAdminUsers() {
    await run(async () => {
      const [users, policy] = await Promise.all([api.listAdminUsers(), api.adminSecurityPolicy()])
      setAdminUsers(users)
      setSecurityPolicy(policy)
      setMessage('Administracija je učitana.')
    })
  }

  async function loadBlockedIps() {
    await run(async () => {
      setBlockedIps(await api.listBlockedIps())
    })
  }

  async function loadHoneypotSecurity() {
    await run(async () => {
      const [status, alerts] = await Promise.all([api.honeypotStatus(), api.listSecurityAlerts()])
      setHoneypotStatus(status)
      setSecurityAlerts(alerts)
    })
  }

  async function loadAuditLogs() {
    await run(async () => {
      setAuditLogs(await api.listAuditLogs())
      setAuditIntegrity(null)
    })
  }

  async function verifyAuditIntegrity() {
    await run(async () => setAuditIntegrity(await api.verifyAuditIntegrity()))
  }

  async function configureHoneypot(enabled: boolean) {
    await run(async () => {
      setHoneypotStatus(await api.configureHoneypot(enabled, 5))
      setMessage(enabled
        ? 'Izolovani demonstracioni endpoint je uključen na 5 minuta.'
        : 'Demonstracioni endpoint je isključen.')
    })
  }

  async function acknowledgeAlert(alertId: number) {
    await run(async () => {
      const acknowledged = await api.acknowledgeSecurityAlert(alertId)
      setSecurityAlerts((current) => current?.map((alert) => alert.id === acknowledged.id ? acknowledged : alert) ?? null)
      setMessage('Sigurnosno upozorenje je označeno kao pregledano.')
    })
  }

  async function runHoneypotDemo(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const query = String(new FormData(event.currentTarget).get('query'))
    await run(async () => {
      const result = await api.runHoneypotDemo(query)
      if (!result.triggered) {
        setMessage(result.message)
        return
      }
      setVaultKeys(null)
      setVaultSecrets([])
      setReceivedSecrets([])
      setUser(null)
      setHoneypotDemoStatus(null)
      setView('login')
      setMessage('Honeytoken je detektovan. Testni nalog je zamrznut i njegove sesije su opozvane.')
    })
  }

  async function unblockIp(ipAddress: string) {
    await run(async () => {
      await api.unblockIp(ipAddress)
      setBlockedIps((current) => current?.filter((block) => block.ipAddress !== ipAddress) ?? null)
      setMessage(`IP adresa ${ipAddress} je odblokirana.`)
    })
  }

  async function openPolicyEditor() {
    await run(async () => {
      setSecurityPolicy(await api.adminSecurityPolicy())
      setShowPolicyEditor(true)
    })
  }

  function updatePolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const requested: SecurityPolicy = {
      minimumLoginPasswordLength: Number(form.get('minimumLoginPasswordLength')),
      minimumMasterPasswordLength: Number(form.get('minimumMasterPasswordLength')),
      maximumFailedLoginAttempts: Number(form.get('maximumFailedLoginAttempts')),
      secretRotationDays: Number(form.get('secretRotationDays')),
    }
    setConfirmation({
      title: 'Sačuvati sigurnosne politike?',
      message: 'Nova pravila primjenjivaće se na naredne registracije, prijave i rotacije tajni.',
      confirmLabel: 'Sačuvaj politike',
      onConfirm: async () => run(async () => {
        setSecurityPolicy(await api.updateSecurityPolicy(requested))
        if (vaultKeys) setVaultSecrets(await loadVaultSecrets(vaultKeys))
        setShowPolicyEditor(false)
        setMessage('Sigurnosne politike su sačuvane.')
      }),
    })
  }

  async function promoteUserToTeamLead(userId: number) {
    await run(async () => {
      const promoted = await api.promoteToTeamLead(userId)
      setAdminUsers((current) => current?.map((listed) => listed.id === promoted.id ? promoted : listed) ?? null)
      setMessage(`Korisnik ${promoted.username} je promovisan u Team Lead.`)
    })
  }

  async function demoteUserToDeveloper(userId: number, username: string) {
    await run(async () => {
      const demoted = await api.demoteToDeveloper(userId)
      setAdminUsers((current) => current?.map((listed) => listed.id === demoted.id ? demoted : listed) ?? null)
      setMessage(`Korisnik ${username} je vraćen u Developer ulogu.`)
    })
  }

  async function runAdminUserAction(
    userId: number,
    action: (id: number) => Promise<AdminUser>,
    successMessage: string,
  ) {
    await run(async () => {
      const updated = await action(userId)
      setAdminUsers((current) => current?.map((listed) => listed.id === updated.id ? updated : listed) ?? null)
      setMessage(successMessage)
    })
  }

  async function confirmPendingAction() {
    const pending = confirmation
    setConfirmation(null)
    if (pending) await pending.onConfirm()
  }

  async function unlockUserVault(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formElement = event.currentTarget
    const masterPassword = String(new FormData(formElement).get('masterPassword'))
    await run(async () => {
      const material = await api.vaultCryptoMaterial()
      const keys = await unlockVault(masterPassword, material)
      const [secrets, received] = await Promise.all([
        loadVaultSecrets(keys),
        user?.role === 'DEVELOPER' ? loadReceivedSecrets(keys) : Promise.resolve([]),
      ])
      formElement.reset()
      setVaultKeys(keys)
      setVaultSecrets(secrets)
      setReceivedSecrets(received)
      setMessage('Vault je otključan.')
    })
  }

  async function loadVaultSecrets(keys: UnlockedVaultKeys): Promise<DecryptedVaultSecret[]> {
    const encryptedSecrets = await api.listSecrets()
    return Promise.all(encryptedSecrets.map(async (encrypted) => ({
      encrypted,
      plaintext: await decryptSecret(encrypted, keys.privateKey),
    })))
  }

  async function loadReceivedSecrets(keys: UnlockedVaultKeys): Promise<DecryptedReceivedSecret[]> {
    const encryptedSecrets = await api.listReceivedSecrets()
    return Promise.all(encryptedSecrets.map(async (encrypted) => ({
      encrypted,
      plaintext: await decryptSecret(encrypted, keys.privateKey),
    })))
  }

  async function refreshReceivedSecrets() {
    if (!vaultKeys) return
    await run(async () => {
      setReceivedSecrets(await loadReceivedSecrets(vaultKeys))
      setRevealedReceivedSecretId(null)
      setMessage('Podijeljene tajne su osvježene.')
    })
  }

  async function openSharing(secretId: number) {
    if (sharingSecretId === secretId) {
      setSharingSecretId(null)
      setShareCandidates([])
      setSharedRecipients([])
      return
    }
    await run(async () => {
      const [candidates, recipients] = await Promise.all([
        api.listShareRecipients(),
        api.listSharedRecipients(secretId),
      ])
      setShareCandidates(candidates)
      setSharedRecipients(recipients)
      setSharingSecretId(secretId)
    })
  }

  async function shareWithDeveloper(encrypted: VaultSecretCipher, recipient: ShareRecipient) {
    if (!vaultKeys) return
    await run(async () => {
      const wrappedDataKeyBase64 = await wrapSecretDataKeyForRecipient(
        encrypted,
        vaultKeys.privateKey,
        recipient.publicKeySpkiBase64,
        recipient.publicKeyAlgorithm,
      )
      await api.shareSecret(encrypted.secretId, {
        recipientUserId: recipient.userId,
        versionNumber: encrypted.versionNumber,
        wrappedDataKeyBase64,
      })
      setSharedRecipients(await api.listSharedRecipients(encrypted.secretId))
      setMessage(`Tajna je sigurno podijeljena s korisnikom ${recipient.username}.`)
    })
  }

  async function revokeDeveloperAccess(secretId: number, recipientId: number, username: string) {
    await run(async () => {
      await api.revokeSecretAccess(secretId, recipientId)
      setSharedRecipients(await api.listSharedRecipients(secretId))
      setMessage(`Pristup korisnika ${username} je opozvan.`)
    })
  }

  async function createVaultSecret(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!vaultKeys) {
      setError('Prvo otključaj Vault')
      return
    }
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    await run(async () => {
      const payload = await encryptSecret({
        name: String(form.get('name')).trim(),
        value: String(form.get('value')),
      }, vaultKeys.publicKey)
      await api.createSecret(payload)
      const secrets = await loadVaultSecrets(vaultKeys)
      formElement.reset()
      setVaultSecrets(secrets)
      setShowCreateSecret(false)
      setMessage('Tajna je sačuvana.')
    })
  }

  async function updateVaultSecret(event: FormEvent<HTMLFormElement>, secretId: number, rotation: boolean) {
    event.preventDefault()
    if (!vaultKeys) {
      setError('Prvo otključaj Vault')
      return
    }
    const form = new FormData(event.currentTarget)
    await run(async () => {
      const payload = await encryptSecret({
        name: String(form.get('name')).trim(),
        value: String(form.get('value')),
      }, vaultKeys.publicKey)
      const result = rotation
        ? await api.rotateSecret(secretId, payload)
        : await api.updateSecret(secretId, payload)
      setVaultSecrets(await loadVaultSecrets(vaultKeys))
      setEditingSecretId(null)
      setRevealedSecretId(null)
      setMessage(rotation
        ? `Tajna je rotirana. Kreirana je verzija ${result.versionNumber}; prethodna dijeljenja treba ponovo odobriti.`
        : `Tajna je ažurirana. Kreirana je verzija ${result.versionNumber}.`)
    })
  }

  async function deleteVaultSecret(secretId: number) {
    if (!vaultKeys) return
    await run(async () => {
      await api.deleteSecret(secretId)
      setVaultSecrets(await loadVaultSecrets(vaultKeys))
      setEditingSecretId(null)
      setRevealedSecretId(null)
      setMessage('Tajna je uklonjena iz Vaulta.')
    })
  }

  function lockVault() {
    setVaultKeys(null)
    setVaultSecrets([])
    setShowCreateSecret(false)
    setRevealedSecretId(null)
    setEditingSecretId(null)
    setReceivedSecrets([])
    setRevealedReceivedSecretId(null)
    setSharingSecretId(null)
    setShareCandidates([])
    setSharedRecipients([])
    setMessage('Vault je zaključan.')
  }

  async function logout() {
    await run(async () => {
      try {
        await api.logout()
      } finally {
        setVaultKeys(null)
        setVaultSecrets([])
        setShowCreateSecret(false)
        setRevealedSecretId(null)
        setEditingSecretId(null)
        setAdminUsers(null)
        setBlockedIps(null)
        setHoneypotStatus(null)
        setSecurityAlerts(null)
        setHoneypotDemoStatus(null)
        setShowPolicyEditor(false)
        setManagedUserId(null)
        setConfirmation(null)
        setReceivedSecrets([])
        setRevealedReceivedSecretId(null)
        setSharingSecretId(null)
        setShareCandidates([])
        setSharedRecipients([])
        setUser(null)
        setChallenge('')
        setMessage('Odjava je uspješna.')
        setView('login')
      }
    })
  }

  return (
    <main className="shell">
      <header className="header">
        <h1>Secure Vault</h1>
        <div className="lock" aria-hidden="true">SV</div>
      </header>
      {message && <div className="notice success">{message}</div>}
      {error && <div className="notice error">{error}</div>}

      <section className="card">
        {view === 'register' && (
          <form onSubmit={register}>
            <div className="form-heading"><h2>Registracija</h2></div>
            <fieldset>
              <legend>Nalog</legend>
              <label>Korisničko ime<input name="username" minLength={3} maxLength={100} required autoComplete="username" /></label>
              <label>Email<input name="email" type="email" maxLength={254} required autoComplete="email" /></label>
              <label>Login lozinka<input name="loginPassword" type="password" minLength={securityPolicy.minimumLoginPasswordLength} maxLength={128} required autoComplete="new-password" /></label>
            </fieldset>
            <fieldset>
              <legend>Vault</legend>
              <label>Master lozinka<input name="masterPassword" type="password" minLength={securityPolicy.minimumMasterPasswordLength} required autoComplete="new-password" /></label>
              <label>Ponovi master lozinku<input name="masterPasswordConfirmation" type="password" minLength={securityPolicy.minimumMasterPasswordLength} required autoComplete="new-password" /></label>
            </fieldset>
            <button className="primary" disabled={busy}>{busy ? 'Kreiranje naloga…' : 'Registruj se'}</button>
            <button type="button" className="text-action" onClick={() => begin('login')}>Već imaš nalog? Prijavi se</button>
          </form>
        )}

        {view === 'oidc-setup' && (
          <form onSubmit={setupOidcAccount}>
            <div className="form-heading"><h2>Postavi master lozinku</h2></div>
            <label>Master lozinka<input name="masterPassword" type="password" minLength={securityPolicy.minimumMasterPasswordLength} required autoComplete="new-password" /></label>
            <label>Ponovi master lozinku<input name="masterPasswordConfirmation" type="password" minLength={securityPolicy.minimumMasterPasswordLength} required autoComplete="new-password" /></label>
            <button className="primary" disabled={busy}>{busy ? 'Kreiranje naloga…' : 'Nastavi'}</button>
          </form>
        )}

        {view === 'activate' && (
          registration ? (
            <form onSubmit={confirmMfa} className="mfa-form">
              <div className="form-heading"><h2>Postavi MFA</h2><p>Skeniraj QR kod authenticator aplikacijom.</p></div>
              <div className="mfa-layout">
                <MfaQrCode provisioningUri={registration.totpProvisioningUri} />
                <div className="mfa-confirm-panel">
                  <h3>Potvrdi kod</h3>
                  <input type="hidden" name="username" value={registration.username} />
                  <label>TOTP kod<input className="code-input" name="code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="000000" required autoFocus autoComplete="one-time-code" /></label>
                  <button className="primary" disabled={busy}>{busy ? 'Provjeravam…' : 'Aktiviraj MFA'}</button>
                </div>
              </div>
              <details className="manual-setup"><summary>Ne možeš skenirati? Prikaži ključ za ručni unos</summary><div className="secret-box"><span>Ručni ključ</span><strong>{registration.totpSecret}</strong><code>{registration.totpProvisioningUri}</code></div></details>
            </form>
          ) : (
            <div className="empty-state"><h2>MFA postavka nije započeta</h2><p>Prvo registruj novi nalog da bi dobila jedinstveni QR kod.</p><button className="primary" onClick={() => begin('register')}>Idi na registraciju</button></div>
          )
        )}

        {view === 'oidc-mfa' && (
          <form onSubmit={loginOidcMfa} className="login-page">
            <div className="form-heading"><h2>MFA potvrda</h2></div>
            <label>TOTP kod<input className="code-input" name="code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="000000" required autoFocus autoComplete="one-time-code" /></label>
            <button className="primary" disabled={busy}>{busy ? 'Prijavljujem…' : 'Prijavi se'}</button>
            <button type="button" className="text-action" onClick={() => begin('login')}>Nazad na prijavu</button>
          </form>
        )}

        {view === 'login' && !challenge && (
          <div className="login-page">
            <div className="form-heading"><h2>Prijava</h2></div>
            <form onSubmit={loginPassword} className="compact-form">
              <label>Korisničko ime<input name="username" required autoComplete="username" /></label>
              <label>Login lozinka<input name="password" type="password" required autoComplete="current-password" /></label>
              <button className="primary" disabled={busy}>{busy ? 'Provjeravam…' : 'Nastavi'}</button>
            </form>
            <div className="login-separator"><span>ili</span></div>
            <div className="login-alternatives">
              <button className="secondary" onClick={() => begin('register')}>Registruj se</button>
              <a className="google-button prominent" href={GOOGLE_LOGIN_URL}>Nastavi sa Google nalogom</a>
            </div>
          </div>
        )}

        {view === 'login' && challenge && (
          <form onSubmit={loginMfa} className="login-page">
            <div className="form-heading"><h2>MFA potvrda</h2></div>
            <label>TOTP kod<input className="code-input" name="code" inputMode="numeric" pattern="[0-9]{6}" maxLength={6} placeholder="000000" required autoFocus autoComplete="one-time-code" /></label>
            <button className="primary" disabled={busy}>{busy ? 'Prijavljujem…' : 'Prijavi se'}</button>
            <button type="button" className="text-action" onClick={() => setChallenge('')}>Nazad na prijavu</button>
          </form>
        )}

        {view === 'account' && (
          <div>
            <div className="account-heading"><h2>Moj nalog</h2><button className="secondary" onClick={logout} disabled={busy}>Odjavi se</button></div>
            {user && <dl className="user-info"><div><dt>Korisnik</dt><dd>{user.username}</dd></div><div><dt>Email</dt><dd>{user.email}</dd></div><div><dt>Uloga</dt><dd>{user.role}</dd></div></dl>}
            {user && user.role !== 'ADMIN' && honeypotDemoStatus && (
              <section className="demo-test-panel">
                <div>
                  <span className="eyebrow">Projektna demonstracija</span>
                  <h3>Honeytoken SQL Injection test</h3>
                  <p>{honeypotDemoStatus.enabled
                    ? `Test je aktivan do ${new Date(honeypotDemoStatus.enabledUntil!).toLocaleTimeString()}.`
                    : 'Test trenutno nije uključen. Admin ga mora privremeno uključiti.'}</p>
                </div>
                {honeypotDemoStatus.enabled && (
                  <form className="demo-test-form" onSubmit={runHoneypotDemo}>
                    <label>Testni unos<input name="query" defaultValue="' OR 1=1 -- " required autoComplete="off" /></label>
                    <button className="danger-button" disabled={busy}>{busy ? 'Testiram…' : 'Pokreni kontrolisani test'}</button>
                  </form>
                )}
              </section>
            )}
            {user?.role === 'ADMIN' && (
              <section className="admin-panel">
                <div className="admin-panel-heading">
                  <div><span className="eyebrow">Administracija</span><h3>Kontrolni centar</h3></div>
                </div>
                <nav className="admin-navigation" aria-label="Administrativne funkcionalnosti">
                  {([['users', 'Korisnici'], ['policy', 'Sigurnosne politike'], ['gateway', 'Blokirane IP adrese'], ['honeypot', 'Honeytoken zaštita'], ['audit', 'Audit log']] as [AdminSection, string][]).map(([section, label]) =>
                    <button type="button" key={section} className={adminSection === section ? 'active' : ''} onClick={() => setAdminSection(section)}>{label}</button>)}
                </nav>
                <div className={`admin-feature ${adminSection === 'users' ? '' : 'admin-feature-hidden'}`}>
                <div className="admin-panel-heading feature-heading">
                  <div><span className="eyebrow">Nalozi i uloge</span><h4>Upravljanje korisnicima</h4></div>
                  <button type="button" className="secondary" onClick={loadAdminUsers} disabled={busy}>{adminUsers ? 'Osvježi listu' : 'Učitaj korisnike'}</button>
                </div>
                {adminUsers && <>
                  <div className="admin-user-list">
                    {adminUsers.map((listed) => (
                      <div className={`admin-user-row ${managedUserId === listed.id ? 'selected' : ''}`} key={listed.id}>
                        <div><strong>{listed.username}</strong><span>{listed.email}</span></div>
                        <div className="admin-user-state"><span>{listed.role}</span><small>{listed.status}</small></div>
                        {listed.id === user?.id
                          ? <span className="role-locked">Trenutni Admin nalog</span>
                          : <button type="button" className="secondary" onClick={() => setManagedUserId((current) => current === listed.id ? null : listed.id)}>
                              {managedUserId === listed.id ? 'Zatvori' : 'Upravljaj'}
                            </button>}
                      </div>
                    ))}
                  </div>
                  {managedUser && managedUser.id !== user?.id && (
                    <section className="managed-user-panel">
                      <div className="managed-user-heading">
                        <div><span className="eyebrow">Odabrani korisnik</span><h4>{managedUser.username}</h4><p>{managedUser.email}</p></div>
                        <button type="button" className="text-action" onClick={() => setManagedUserId(null)}>Zatvori</button>
                      </div>
                      <dl className="managed-user-details">
                        <div><dt>Uloga</dt><dd>{managedUser.role}</dd></div><div><dt>Status</dt><dd>{managedUser.status}</dd></div>
                        <div><dt>Aktivne sesije</dt><dd>{managedUser.activeSessionCount}</dd></div><div><dt>Neuspjele prijave</dt><dd>{managedUser.failedLoginAttempts}</dd></div>
                      </dl>
                      <div className="managed-user-actions">
                        {managedUser.role === 'DEVELOPER' && managedUser.status === 'ACTIVE' && <button type="button" className="secondary" onClick={() => setConfirmation({ title: 'Promocija korisnika', message: `Korisnik „${managedUser.username}“ dobiće Team Lead privilegije.`, confirmLabel: 'Promoviši u Team Lead', onConfirm: () => promoteUserToTeamLead(managedUser.id) })}>Promoviši u Team Lead</button>}
                        {managedUser.role === 'TEAM_LEAD' && managedUser.status === 'ACTIVE' && <button type="button" className="secondary" onClick={() => setConfirmation({ title: 'Promjena uloge', message: `Korisnik „${managedUser.username}“ ponovo će postati Developer.`, confirmLabel: 'Vrati u Developer', onConfirm: () => demoteUserToDeveloper(managedUser.id, managedUser.username) })}>Vrati u Developer</button>}
                        {managedUser.status === 'ACTIVE' && <button type="button" className="secondary" onClick={() => setConfirmation({ title: 'Zamrzavanje naloga', message: `Nalog „${managedUser.username}“ biće zamrznut i sve sesije opozvane.`, confirmLabel: 'Zamrzni', onConfirm: () => runAdminUserAction(managedUser.id, api.freezeUser, `Nalog ${managedUser.username} je zamrznut.`) })}>Zamrzni nalog</button>}
                        {managedUser.status === 'FROZEN' && <button type="button" className="secondary" onClick={() => runAdminUserAction(managedUser.id, api.unfreezeUser, `Nalog ${managedUser.username} je odmrznut.`)}>Odmrzni nalog</button>}
                        {managedUser.status === 'ACTIVE' && (managedUser.lockedUntil || managedUser.failedLoginAttempts > 0) && <button type="button" className="secondary" onClick={() => runAdminUserAction(managedUser.id, api.unlockUser, `Blokada naloga ${managedUser.username} je uklonjena.`)}>Otključaj prijavu</button>}
                        {managedUser.activeSessionCount > 0 && <button type="button" className="secondary" onClick={() => setConfirmation({ title: 'Odjava sa svih uređaja', message: `Sve sesije korisnika „${managedUser.username}“ biće opozvane.`, confirmLabel: 'Opozovi sesije', onConfirm: () => runAdminUserAction(managedUser.id, api.revokeUserSessions, `Sve sesije korisnika ${managedUser.username} su opozvane.`) })}>Opozovi sve sesije</button>}
                      </div>
                      {managedUser.status === 'DISABLED'
                        ? <div className="disabled-account-note"><strong>Nalog je trajno deaktiviran</strong><span>Nije ga moguće ponovo aktivirati kroz aplikaciju.</span></div>
                        : <div className="danger-zone"><div><strong>Trajno deaktiviranje</strong><span>Korisnik će izgubiti pristup. Ovu radnju nije moguće poništiti kroz aplikaciju.</span></div><button type="button" className="danger-button" onClick={() => setConfirmation({ title: 'Trajno deaktivirati nalog?', message: `Upozorenje: nalog „${managedUser.username}“ više se neće moći prijaviti, sve sesije će biti opozvane i deaktivaciju nije moguće poništiti kroz aplikaciju.`, confirmLabel: 'Trajno deaktiviraj', danger: true, onConfirm: () => runAdminUserAction(managedUser.id, api.disableUser, `Nalog ${managedUser.username} je trajno deaktiviran.`) })}>Deaktiviraj nalog</button></div>}
                    </section>
                  )}
                </>}
                </div>
                <section className={`policy-panel ${adminSection === 'policy' ? '' : 'admin-feature-hidden'}`}>
                  <div className="policy-panel-heading">
                    <div><span className="eyebrow">Organizaciona pravila</span><h4>Sigurnosne politike</h4></div>
                    <button type="button" className="secondary" onClick={showPolicyEditor ? () => setShowPolicyEditor(false) : openPolicyEditor} disabled={busy}>
                      {showPolicyEditor ? 'Zatvori' : 'Uredi'}
                    </button>
                  </div>
                  {showPolicyEditor && (
                    <form className="policy-form" onSubmit={updatePolicy} key={JSON.stringify(securityPolicy)}>
                      <label>Minimalna dužina login lozinke<input name="minimumLoginPasswordLength" type="number" min="8" max="128" defaultValue={securityPolicy.minimumLoginPasswordLength} required /></label>
                      <label>Minimalna dužina master lozinke<input name="minimumMasterPasswordLength" type="number" min="12" max="128" defaultValue={securityPolicy.minimumMasterPasswordLength} required /></label>
                      <label>Maksimalno pogrešnih prijava<input name="maximumFailedLoginAttempts" type="number" min="3" max="20" defaultValue={securityPolicy.maximumFailedLoginAttempts} required /></label>
                      <label>Rotacija tajni (dana)<input name="secretRotationDays" type="number" min="1" max="3650" defaultValue={securityPolicy.secretRotationDays} required /></label>
                      <button className="primary" disabled={busy}>Sačuvaj politike</button>
                    </form>
                  )}
                </section>
                <section className={`blocked-ip-panel ${adminSection === 'gateway' ? '' : 'admin-feature-hidden'}`}>
                    <div className="blocked-ip-heading">
                      <div><span className="eyebrow">Gateway zaštita</span><h4>Blokirane IP adrese</h4></div>
                      <div className="blocked-ip-heading-actions"><span className="blocked-ip-count">{blockedIps?.length ?? 0}</span><button type="button" className="secondary" onClick={loadBlockedIps} disabled={busy}>Osvježi blokade</button></div>
                    </div>
                    {blockedIps === null
                      ? <p className="blocked-ip-empty">Klikni „Osvježi blokade“ za pregled aktivnih blokada.</p>
                      : blockedIps.length === 0
                      ? <p className="blocked-ip-empty">Trenutno nema aktivno blokiranih IP adresa.</p>
                      : <div className="blocked-ip-list">{blockedIps.map((block) => (
                          <div className="blocked-ip-row" key={block.ipAddress}>
                            <div><strong>{block.ipAddress}</strong><span>{block.reason}</span><small>Blokirano do {new Date(block.blockedUntil).toLocaleString()}</small></div>
                            <button type="button" className="secondary" onClick={() => setConfirmation({
                              title: 'Odblokirati IP adresu?',
                              message: `IP adresa ${block.ipAddress} ponovo će moći pristupiti aplikaciji.`,
                              confirmLabel: 'Odblokiraj',
                              onConfirm: () => unblockIp(block.ipAddress),
                            })}>Odblokiraj</button>
                          </div>
                        ))}</div>}
                </section>
                <section className={`honeypot-panel ${adminSection === 'honeypot' ? '' : 'admin-feature-hidden'}`}>
                  <div className="honeypot-heading">
                    <div><span className="eyebrow">Detekcija upada</span><h4>Honeytoken zaštita</h4></div>
                    <button type="button" className="secondary" onClick={loadHoneypotSecurity} disabled={busy}>Osvježi</button>
                  </div>
                  {honeypotStatus === null
                    ? <p className="blocked-ip-empty">Klikni „Osvježi“ za stanje zaštite i upozorenja.</p>
                    : <>
                      <div className={`honeypot-status ${honeypotStatus.enabled ? 'enabled' : ''}`}>
                        <div>
                          <strong>{honeypotStatus.enabled ? 'Demo endpoint je privremeno uključen' : 'Demo endpoint je isključen'}</strong>
                          <span>{honeypotStatus.enabled && honeypotStatus.enabledUntil
                            ? `Automatski se isključuje ${new Date(honeypotStatus.enabledUntil).toLocaleString()}.`
                            : 'Honeytoken zapisi ostaju aktivni, ali namjerno ranjivi endpoint nije dostupan.'}</span>
                        </div>
                        {honeypotStatus.enabled
                          ? <button type="button" className="danger-button" onClick={() => configureHoneypot(false)} disabled={busy}>Isključi odmah</button>
                          : <button type="button" className="secondary" onClick={() => setConfirmation({
                              title: 'Uključiti ranjivi demo endpoint?',
                              message: 'Endpoint će biti aktivan 5 minuta. Koristi ga samo za kontrolisani lokalni test sa testnim korisnikom.',
                              confirmLabel: 'Uključi na 5 minuta',
                              danger: true,
                              onConfirm: () => configureHoneypot(true),
                            })} disabled={busy}>Uključi na 5 minuta</button>}
                      </div>
                      <div className="security-alert-heading">
                        <h5>Sigurnosna upozorenja</h5>
                        <span className="blocked-ip-count">{securityAlerts?.filter((alert) => !alert.acknowledgedAt).length ?? 0}</span>
                      </div>
                      {!securityAlerts?.length
                        ? <p className="blocked-ip-empty">Nema sigurnosnih upozorenja.</p>
                        : <div className="security-alert-list">{securityAlerts.map((alert) => (
                            <article className={`security-alert ${alert.acknowledgedAt ? 'acknowledged' : ''}`} key={alert.id}>
                              <div className="security-alert-title"><strong>{alert.severity}: {alert.alertType}</strong><span>{new Date(alert.createdAt).toLocaleString()}</span></div>
                              <p>{alert.description}</p>
                              <small>Korisnik: {alert.username ?? 'nepoznat'} · IP: {alert.ipAddress ?? 'nepoznata'}</small>
                              {!alert.acknowledgedAt && <button type="button" className="secondary" onClick={() => acknowledgeAlert(alert.id)} disabled={busy}>Označi kao pregledano</button>}
                            </article>
                          ))}</div>}
                    </>}
                </section>
                <section className={`audit-panel ${adminSection === 'audit' ? '' : 'admin-feature-hidden'}`}>
                  <div className="audit-heading">
                    <div><span className="eyebrow">Nepromjenjiva evidencija</span><h4>Audit log</h4></div>
                    <div className="audit-actions">
                      <button type="button" className="secondary" onClick={loadAuditLogs} disabled={busy}>{auditLogs ? 'Osvježi' : 'Učitaj zapise'}</button>
                      <button type="button" className="secondary" onClick={verifyAuditIntegrity} disabled={busy}>Provjeri integritet</button>
                    </div>
                  </div>
                  {auditIntegrity && <div className={`audit-integrity ${auditIntegrity.valid ? 'valid' : 'broken'}`}>
                    <strong>{auditIntegrity.valid ? 'Lanac je ispravan' : 'Lanac je narušen'}</strong>
                    <span>{auditIntegrity.checkedRecords} provjerenih zapisa{auditIntegrity.brokenAtId ? ` · greška kod zapisa #${auditIntegrity.brokenAtId}` : ''}</span>
                  </div>}
                  {auditLogs === null
                    ? <p className="blocked-ip-empty">Učitaj zapise za pregled aktivnosti.</p>
                    : <>
                      <div className="audit-filters">
                        <label>ID korisnika<input value={auditActorFilter} onChange={(event) => setAuditActorFilter(event.target.value)} inputMode="numeric" placeholder="npr. 2" /></label>
                        <label>Vrsta događaja<input value={auditEventFilter} onChange={(event) => setAuditEventFilter(event.target.value)} placeholder="npr. SECRET" /></label>
                        <label>Datum<input type="date" value={auditDateFilter} onChange={(event) => setAuditDateFilter(event.target.value)} /></label>
                      </div>
                      <div className="audit-list">
                        {filteredAuditLogs.length === 0 && <p className="blocked-ip-empty">Nema zapisa za izabrane filtre.</p>}
                        {filteredAuditLogs.map((entry) => <article className="audit-row" key={entry.id}>
                          <div className="audit-row-title"><strong>#{entry.id} · {entry.eventType}</strong><span>{new Date(entry.occurredAt).toLocaleString()}</span></div>
                          <small>
                            Izvršilac: {entry.actorUsername ? `${entry.actorUsername} (#${entry.actorUserId})` : entry.actorUserId ? `korisnik #${entry.actorUserId}` : 'neautentifikovan zahtjev'}
                            {' · '}Cilj: {entry.targetUsername ? `${entry.targetUsername} (#${entry.targetId})` : entry.targetType === 'USER' && entry.targetId ? `korisnik #${entry.targetId}` : `${entry.targetType ?? '—'}${entry.targetId ? ` #${entry.targetId}` : ''}`}
                            {' · '}IP: {entry.ipAddress ?? '—'}
                          </small>
                          <code>{entry.eventData}</code>
                          <details><summary>Kriptografski heševi</summary><div>Prethodni: {entry.previousHash ?? 'početak lanca'}</div><div>Zapis: {entry.entryHash}</div></details>
                        </article>)}
                      </div>
                    </>}
                </section>
              </section>
            )}
            {user && (
              <section className={`vault-unlock ${vaultKeys ? 'unlocked' : ''}`}>
                <div className="vault-status">
                  <span className="vault-status-icon" aria-hidden="true">{vaultKeys ? 'O' : 'X'}</span>
                  <div>
                    <h3>{vaultKeys ? 'Vault je otključan' : 'Vault je zaključan'}</h3>
                  </div>
                </div>
                {vaultKeys ? (
                  <button type="button" className="secondary" onClick={lockVault}>Zaključaj Vault</button>
                ) : (
                  <form className="unlock-form" onSubmit={unlockUserVault}>
                    <label>Master lozinka<input name="masterPassword" type="password" minLength={14} required autoComplete="current-password" /></label>
                    <button className="primary" disabled={busy}>{busy ? 'Otključavam…' : 'Otključaj Vault'}</button>
                  </form>
                )}
              </section>
            )}
            {vaultKeys && (
              <section className="secret-manager">
                <div className="secret-manager-heading">
                  <h3>Moje tajne</h3>
                  <button type="button" className={showCreateSecret ? 'secondary' : 'primary'} onClick={() => setShowCreateSecret((visible) => !visible)}>
                    {showCreateSecret ? 'Otkaži' : 'Dodaj tajnu'}
                  </button>
                </div>

                {showCreateSecret && (
                  <form className="secret-form" onSubmit={createVaultSecret}>
                    <label>Naziv tajne<input name="name" minLength={1} maxLength={120} placeholder="npr. GitHub lozinka" required autoFocus /></label>
                    <label>Tajna<textarea name="value" maxLength={100000} rows={5} placeholder="Unesi tajni tekst" required autoComplete="off" /></label>
                    <div className="secret-form-actions">
                      <button type="button" className="secondary" onClick={() => setShowCreateSecret(false)}>Otkaži</button>
                      <button className="primary" disabled={busy}>{busy ? 'Čuvanje…' : 'Sačuvaj tajnu'}</button>
                    </div>
                  </form>
                )}

                {expiredVaultSecrets.length > 0 && (
                  <section className="expired-secrets-panel">
                    <div><strong>Istekle tajne</strong><span>{expiredVaultSecrets.length} {expiredVaultSecrets.length === 1 ? 'tajna zahtijeva' : 'tajne zahtijevaju'} rotaciju prije novog dijeljenja.</span></div>
                    <ul>{expiredVaultSecrets.map(({ encrypted, plaintext }) => <li key={encrypted.secretId}>{plaintext.name}</li>)}</ul>
                  </section>
                )}

                <div className="secret-list">
                  {vaultSecrets.length === 0 && <div className="empty-secret-list">Još nema sačuvanih tajni.</div>}
                  {vaultSecrets.map(({ encrypted, plaintext }) => {
                    const revealed = revealedSecretId === encrypted.secretId
                    const editing = editingSecretId === encrypted.secretId
                    const expired = rotationExpired(encrypted.rotationDueAt)
                    return (
                      <article className="secret-card" key={encrypted.secretId}>
                        <div className="secret-card-heading">
                          <h4>{plaintext.name}</h4>
                          <div className="secret-card-actions">
                            <button type="button" className="secret-action" onClick={() => setRevealedSecretId(revealed ? null : encrypted.secretId)}>{revealed ? 'Sakrij' : 'Prikaži'}</button>
                            <button type="button" className={expired ? 'secret-action rotate-action' : 'secret-action'} onClick={() => setEditingSecretId(editing ? null : encrypted.secretId)}>{editing ? 'Otkaži' : expired ? 'Rotiraj' : 'Izmijeni'}</button>
                            {user?.role === 'TEAM_LEAD' && (expired
                              ? <span className="sharing-blocked">Dijeljenje blokirano</span>
                              : <button type="button" className="secret-action share-action" onClick={() => openSharing(encrypted.secretId)}>{sharingSecretId === encrypted.secretId ? 'Zatvori dijeljenje' : 'Podijeli'}</button>)}
                            <button type="button" className="secret-action danger-action" onClick={() => setConfirmation({
                              title: 'Brisanje tajne',
                              message: `Tajna „${plaintext.name}“ biće uklonjena iz aktivnog Vaulta. Prethodne verzije ostaju u sigurnosnoj evidenciji.`,
                              confirmLabel: 'Obriši tajnu',
                              danger: true,
                              onConfirm: () => deleteVaultSecret(encrypted.secretId),
                            })}>Obriši</button>
                          </div>
                        </div>
                        <div className={`secret-value ${revealed ? 'revealed' : ''}`}><code>{revealed ? plaintext.value : '••••••••••••'}</code></div>
                        {editing && (
                          <form className={`edit-secret-form ${expired ? 'rotation-form' : ''}`} onSubmit={(event) => updateVaultSecret(event, encrypted.secretId, expired)}>
                            {expired && <div className="rotation-form-heading"><strong>Rotacija tajne</strong><span>Unesi novu vrijednost. Biće kreirana nova enkriptovana verzija i novi rok od {securityPolicy.secretRotationDays} dana.</span></div>}
                            <label>Naziv tajne<input name="name" defaultValue={plaintext.name} minLength={1} maxLength={120} required /></label>
                            <label>Tajna<textarea name="value" defaultValue={plaintext.value} maxLength={100000} rows={4} required autoComplete="off" /></label>
                            <button className="primary" disabled={busy}>{busy ? 'Enkriptujem…' : expired ? 'Rotiraj tajnu' : 'Sačuvaj novu verziju'}</button>
                          </form>
                        )}
                        {user?.role === 'TEAM_LEAD' && sharingSecretId === encrypted.secretId && (
                          <div className="sharing-panel">
                            <h5>Podijeli sa Developerom</h5>
                            {shareCandidates.length === 0 && <p>Nema aktivnih Developer korisnika.</p>}
                            {shareCandidates.map((candidate) => {
                              const shared = sharedRecipients.some((recipient) => recipient.userId === candidate.userId)
                              return (
                                <div className="sharing-recipient" key={candidate.userId}>
                                  <div><strong>{candidate.username}</strong><span>{candidate.email}</span></div>
                                  {shared
                                    ? <button type="button" className="secondary" onClick={() => setConfirmation({
                                      title: 'Opozivanje pristupa',
                                      message: `Korisnik „${candidate.username}“ više neće moći otvoriti ovu verziju tajne.`,
                                      confirmLabel: 'Opozovi pristup',
                                      danger: true,
                                      onConfirm: () => revokeDeveloperAccess(encrypted.secretId, candidate.userId, candidate.username),
                                    })} disabled={busy}>Opozovi pristup</button>
                                    : <button type="button" className="secondary" onClick={() => shareWithDeveloper(encrypted, candidate)} disabled={busy}>{busy ? 'Pripremam ključ…' : 'Podijeli'}</button>}
                                </div>
                              )
                            })}
                          </div>
                        )}
                        <div className="secret-card-footer">
                          <span>Verzija {encrypted.versionNumber} · izmijenjeno {new Date(encrypted.updatedAt).toLocaleString()}</span>
                          <span className={expired ? 'rotation-status overdue' : 'rotation-status'}>
                            {expired ? 'Rotacija je potrebna' : `Rok rotacije: ${new Date(encrypted.rotationDueAt!).toLocaleDateString()}`}
                          </span>
                        </div>
                      </article>
                    )
                  })}
                </div>
              </section>
            )}
            {vaultKeys && user?.role === 'DEVELOPER' && (
              <section className="received-secrets">
                <div className="secret-manager-heading">
                  <h3>Podijeljeno sa mnom</h3>
                  <button type="button" className="secondary" onClick={refreshReceivedSecrets} disabled={busy}>Osvježi</button>
                </div>
                <div className="secret-list">
                  {activeReceivedSecrets.length === 0 && <div className="empty-secret-list">Nema važećih tajni podijeljenih s tobom.</div>}
                  {activeReceivedSecrets.map(({ encrypted, plaintext }) => {
                    const revealed = revealedReceivedSecretId === encrypted.secretId
                    return (
                      <article className="secret-card received-card" key={`${encrypted.secretId}-${encrypted.versionNumber}`}>
                        <div className="secret-card-heading">
                          <div><h4>{plaintext.name}</h4><small>Vlasnik: {encrypted.ownerUsername}</small></div>
                          <button type="button" className="secret-action" onClick={() => setRevealedReceivedSecretId(revealed ? null : encrypted.secretId)}>{revealed ? 'Sakrij' : 'Prikaži'}</button>
                        </div>
                        <div className={`secret-value ${revealed ? 'revealed' : ''}`}><code>{revealed ? plaintext.value : '••••••••••••'}</code></div>
                        <div className="secret-card-footer"><span>Podijeljena verzija {encrypted.versionNumber}</span><span className="rotation-status">Važi do {new Date(encrypted.rotationDueAt!).toLocaleDateString()}</span></div>
                      </article>
                    )
                  })}
                </div>
              </section>
            )}
          </div>
        )}
      </section>
      {confirmation && (
        <div className="modal-backdrop" role="presentation">
          <section className="confirmation-modal" role="dialog" aria-modal="true" aria-labelledby="confirmation-title">
            <h3 id="confirmation-title">{confirmation.title}</h3>
            <p>{confirmation.message}</p>
            <div className="modal-actions">
              <button type="button" className="secondary" onClick={() => setConfirmation(null)}>Otkaži</button>
              <button type="button" className={confirmation.danger ? 'danger-button' : 'primary'} onClick={confirmPendingAction}>{confirmation.confirmLabel}</button>
            </div>
          </section>
        </div>
      )}
    </main>
  )
}

export default App
