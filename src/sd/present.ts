import { type AbstractSigner, createJWT, type JWTHeader, type Signer } from 'did-jwt'
import { bytesToBase64url, sha256, stringToBytes } from './util.js'
import type { Disclosure } from './disclosures.js'

export interface CreateSdPresentationOptions {
  /** The signed SD-VC JWT alone (the `jwt` field returned by `issueSdCredential`). */
  vcJwt: string
  /** All disclosures the holder has for this VC. */
  disclosures: Disclosure[]
  /** Names of the claims the holder wants to reveal to this verifier. */
  reveal: string[]
  /** Holder's DID — must equal the VC's `sub` for the binding check to pass. */
  holderDid: string
  /**
   * Holder's signer. Any did-jwt `Signer` function or class extending
   * `AbstractSigner` works (e.g. an `Eip712Signer`, `ES256KSigner`, …).
   */
  signer: Signer | AbstractSigner
  /** JWS algorithm used for the KB-JWT (e.g. `'EIP712'`, `'ES256K'`, `'EdDSA'`). */
  alg: string
  /** Header fields merged into the KB-JWT header alongside `typ: 'kb+jwt'`. */
  headerExtensions?: Record<string, unknown>
  /**
   * Extra claims merged into the KB-JWT payload. The required claims (`aud`,
   * `nonce`, `iat`, `exp`, `sd_hash`) always take precedence. For EIP-712 callers
   * this is `{ domain }`, since the EIP-712 signer reads its domain from the payload.
   */
  payloadExtensions?: Record<string, unknown>
  /** Verifier's identifier — becomes the KB-JWT's `aud` claim. */
  audience: string
  /** Fresh challenge supplied by the verifier — becomes the KB-JWT's `nonce`. */
  nonce: string
  /** KB-JWT expiry in seconds from now (default 300 = 5 minutes). */
  expiresIn?: number
}

export interface CreateSdPresentationResult {
  /** The signed Key-Binding JWT alone. */
  kbJwt: string
  /** Disclosures the holder chose to reveal. */
  presentedDisclosures: Disclosure[]
  /**
   * Full combined SD-JWT-VC presentation form:
   *   `<vcJwt>~<disclosure_a>~…~<disclosure_z>~<kbJwt>`
   */
  combined: string
}

/**
 * Build a Verifiable Presentation in SD-JWT-VC form.
 *
 * The holder picks a subset of claim names to reveal, the helper filters the
 * disclosures, computes a hash binding the KB-JWT to this exact body, and
 * signs the KB-JWT under the supplied JWS algorithm.
 */
export async function createSdPresentation(
  opts: CreateSdPresentationOptions
): Promise<CreateSdPresentationResult> {
  const expiresIn = opts.expiresIn ?? 300

  // Resolve `reveal` against the holder's disclosure store. Reject if any
  // requested claim is missing (a different mistake than "I don't want to
  // reveal that one").
  const selected: Disclosure[] = []
  for (const name of opts.reveal) {
    const d = opts.disclosures.find((x) => x.name === name)
    if (d === undefined) {
      throw new Error(`createSdPresentation: no disclosure available for claim "${name}"`)
    }
    selected.push(d)
  }

  // The SD-JWT-VC body the verifier will hash; the trailing empty slot is
  // critical — it's what `sd_hash` commits to.
  const body = [opts.vcJwt, ...selected.map((d) => d.encoded), ''].join('~')
  const sdHash = bytesToBase64url(await sha256(stringToBytes(body)))

  const now = Math.floor(Date.now() / 1000)
  const kbJwt: string = await createJWT(
    {
      ...(opts.payloadExtensions ?? {}),
      aud: opts.audience,
      nonce: opts.nonce,
      iat: now,
      exp: now + expiresIn,
      sd_hash: sdHash,
    },
    {
      issuer: opts.holderDid,
      signer: opts.signer,
      alg: opts.alg,
    },
    {
      typ: 'kb+jwt',
      ...(opts.headerExtensions ?? {}),
    } as unknown as Partial<JWTHeader>
  )

  return {
    kbJwt,
    presentedDisclosures: selected,
    combined: body + kbJwt,
  }
}
