/**
 * Minimal WebAuthn client.
 *
 * The control plane speaks the standard WebAuthn JSON encoding (base64url
 * strings, camelCase fields), so the only work here is converting those strings
 * into the `ArrayBuffer`s the browser API demands — `navigator.credentials`
 * takes binary data — and re-encoding the result. Keeping this local avoids a
 * dependency on `@simplewebauthn/browser` whose option shapes change between
 * major versions.
 */

/** Credential descriptor as it crosses the wire. */
export interface CredentialDescriptorJson {
  id: string
  type: string
  transports?: string[]
}

/** `PublicKeyCredentialCreationOptions` with base64url challenges. */
export interface CreationOptionsJson {
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  challenge: string
  pubKeyCredParams: { type: string; alg: number }[]
  timeout?: number
  excludeCredentials?: CredentialDescriptorJson[]
  authenticatorSelection?: Record<string, unknown>
  attestation?: string
}

/** `PublicKeyCredentialRequestOptions` with a base64url challenge. */
export interface RequestOptionsJson {
  challenge: string
  timeout?: number
  rpId: string
  allowCredentials?: CredentialDescriptorJson[]
  userVerification?: string
}

/** What `POST /auth/passkey/register/finish` expects. */
export interface RegistrationPayload {
  id: string
  rawId: string
  type: string
  response: {
    clientDataJSON: string
    attestationObject: string
    transports?: string[]
  }
  clientExtensionResults: Record<string, unknown>
  name?: string
}

/** What `POST /auth/passkey/login/finish` expects. */
export interface AssertionPayload {
  id: string
  rawId: string
  type: string
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle: string | null
  }
  clientExtensionResults: Record<string, unknown>
}

/** True when the browser implements WebAuthn (and the page is a secure context). */
export function passkeysSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator !== 'undefined' &&
    typeof navigator.credentials?.create === 'function'
  )
}

/** True when the user dismissed the browser's passkey prompt. */
export function isPasskeyCancellation(error: unknown): boolean {
  return (
    error instanceof DOMException &&
    (error.name === 'NotAllowedError' || error.name === 'AbortError')
  )
}

function toBuffer(value: string): ArrayBuffer {
  const normalised = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = normalised.padEnd(
    normalised.length + ((4 - (normalised.length % 4)) % 4),
    '=',
  )
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes.buffer
}

function fromBuffer(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Runs `navigator.credentials.create` and returns the credential in the shape
 * the control plane stores. `name` is the operator's label for the new passkey.
 */
export async function createPasskey(
  options: CreationOptionsJson,
  name: string,
): Promise<RegistrationPayload> {
  const publicKey = {
    ...options,
    challenge: toBuffer(options.challenge),
    user: { ...options.user, id: toBuffer(options.user.id) },
    excludeCredentials: options.excludeCredentials?.map((descriptor) => ({
      ...descriptor,
      id: toBuffer(descriptor.id),
    })),
  } as unknown as PublicKeyCredentialCreationOptions

  const credential = (await navigator.credentials.create({ publicKey })) as
    | PublicKeyCredential
    | null
  if (!credential) throw new Error('the authenticator returned no credential')

  const response = credential.response as AuthenticatorAttestationResponse
  return {
    id: credential.id,
    rawId: fromBuffer(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: fromBuffer(response.clientDataJSON),
      attestationObject: fromBuffer(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
    clientExtensionResults: { ...credential.getClientExtensionResults() },
    name,
  }
}

/** Runs `navigator.credentials.get` and returns the assertion payload. */
export async function getAssertion(
  options: RequestOptionsJson,
): Promise<AssertionPayload> {
  const publicKey = {
    ...options,
    challenge: toBuffer(options.challenge),
    allowCredentials: options.allowCredentials?.map((descriptor) => ({
      ...descriptor,
      id: toBuffer(descriptor.id),
    })),
  } as unknown as PublicKeyCredentialRequestOptions

  const credential = (await navigator.credentials.get({ publicKey })) as
    | PublicKeyCredential
    | null
  if (!credential) throw new Error('the authenticator returned no assertion')

  const response = credential.response as AuthenticatorAssertionResponse
  return {
    id: credential.id,
    rawId: fromBuffer(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: fromBuffer(response.clientDataJSON),
      authenticatorData: fromBuffer(response.authenticatorData),
      signature: fromBuffer(response.signature),
      userHandle: response.userHandle ? fromBuffer(response.userHandle) : null,
    },
    clientExtensionResults: { ...credential.getClientExtensionResults() },
  }
}
