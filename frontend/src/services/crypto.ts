import type { ClientCryptoMaterial, EncryptedSecretPayload, VaultCryptoMaterial, VaultSecretCipher } from './api'

const PBKDF2_ITERATIONS = 600_000

function toBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

export interface UnlockedVaultKeys {
  privateKey: CryptoKey
  publicKey: CryptoKey
}

export interface SecretPlaintext {
  formatVersion: 1 | 2
  name: string
  value: string
}

export async function encryptSecret(
  plaintext: Pick<SecretPlaintext, 'name' | 'value'>,
  publicKey: CryptoKey,
): Promise<EncryptedSecretPayload> {
  const dataKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  )
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const encoded = new TextEncoder().encode(JSON.stringify({ formatVersion: 2, ...plaintext }))
  const encryptedBlob = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, dataKey, encoded)
  const rawDataKey = await crypto.subtle.exportKey('raw', dataKey)
  const wrappedDataKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawDataKey)

  return {
    encryptedBlobBase64: toBase64(encryptedBlob),
    encryptionIvBase64: toBase64(iv.buffer),
    wrappedDataKeyBase64: toBase64(wrappedDataKey),
  }
}

export async function decryptSecret(
  encrypted: VaultSecretCipher,
  privateKey: CryptoKey,
): Promise<SecretPlaintext> {
  if (encrypted.encryptionAlgorithm !== 'AES-256-GCM'
      || encrypted.wrappingAlgorithm !== 'RSA-OAEP-3072') {
    throw new Error('Algoritam tajne nije podržan')
  }

  try {
    const rawDataKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      fromBase64(encrypted.wrappedDataKeyBase64),
    )
    const dataKey = await crypto.subtle.importKey(
      'raw',
      rawDataKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    )
    const plaintextBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(encrypted.encryptionIvBase64) },
      dataKey,
      fromBase64(encrypted.encryptedBlobBase64),
    )
    const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintextBytes))
    if (!isSecretPlaintext(parsed)) throw new Error('invalid payload')
    return {
      formatVersion: parsed.formatVersion,
      name: parsed.name,
      value: parsed.value,
    }
  } catch {
    throw new Error('Tajna je oštećena ili joj ovaj ključ nema pristup')
  }
}

export async function wrapSecretDataKeyForRecipient(
  encrypted: VaultSecretCipher,
  ownerPrivateKey: CryptoKey,
  recipientPublicKeySpkiBase64: string,
  recipientPublicKeyAlgorithm: string,
): Promise<string> {
  if (encrypted.wrappingAlgorithm !== 'RSA-OAEP-3072'
      || recipientPublicKeyAlgorithm !== 'RSA-OAEP-3072') {
    throw new Error('Algoritam javnog ključa primaoca nije podržan')
  }

  try {
    const rawDataKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      ownerPrivateKey,
      fromBase64(encrypted.wrappedDataKeyBase64),
    )
    const recipientPublicKey = await crypto.subtle.importKey(
      'spki',
      fromBase64(recipientPublicKeySpkiBase64),
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt'],
    )
    const wrappedDataKey = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      recipientPublicKey,
      rawDataKey,
    )
    return toBase64(wrappedDataKey)
  } catch {
    throw new Error('Ključ tajne nije moguće sigurno pripremiti za primaoca')
  }
}

function isSecretPlaintext(value: unknown): value is SecretPlaintext & Record<string, unknown> {
  if (typeof value !== 'object' || value === null) return false
  const candidate = value as Record<string, unknown>
  return (candidate.formatVersion === 1 || candidate.formatVersion === 2)
    && typeof candidate.name === 'string'
    && typeof candidate.value === 'string'
}

export async function unlockVault(
  masterPassword: string,
  material: VaultCryptoMaterial,
): Promise<UnlockedVaultKeys> {
  if (material.kdfAlgorithm !== 'PBKDF2-SHA-256'
      || material.privateKeyAlgorithm !== 'AES-256-GCM'
      || material.publicKeyAlgorithm !== 'RSA-OAEP-3072'
      || material.cryptoVersion !== 1) {
    throw new Error('Kriptografski format naloga nije podržan')
  }

  const passwordMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey'],
  )
  const wrappingKey = await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: fromBase64(material.kdfSaltBase64),
      iterations: material.kdfIterations,
      hash: 'SHA-256',
    },
    passwordMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  )

  try {
    const privateKeyPkcs8 = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromBase64(material.privateKeyIvBase64) },
      wrappingKey,
      fromBase64(material.encryptedPrivateKeyBase64),
    )
    const [privateKey, publicKey] = await Promise.all([
      crypto.subtle.importKey(
        'pkcs8',
        privateKeyPkcs8,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt'],
      ),
      crypto.subtle.importKey(
        'spki',
        fromBase64(material.publicKeySpkiBase64),
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt'],
      ),
    ])
    return { privateKey, publicKey }
  } catch {
    throw new Error('Master lozinka nije ispravna')
  }
}

export async function createRegistrationCryptoMaterial(masterPassword: string, minimumLength = 14): Promise<ClientCryptoMaterial> {
  if (masterPassword.length < minimumLength) throw new Error(`Master lozinka mora imati najmanje ${minimumLength} znakova`)
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const passwordMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(masterPassword), 'PBKDF2', false, ['deriveKey'])
  const wrappingKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    passwordMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSA-OAEP', modulusLength: 3072, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['encrypt', 'decrypt'],
  )
  const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey)
  const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)
  const encryptedPrivateKey = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, privateKey)
  return {
    kdfSaltBase64: toBase64(salt.buffer),
    kdfIterations: PBKDF2_ITERATIONS,
    publicKeySpkiBase64: toBase64(publicKey),
    encryptedPrivateKeyBase64: toBase64(encryptedPrivateKey),
    privateKeyIvBase64: toBase64(iv.buffer),
  }
}
