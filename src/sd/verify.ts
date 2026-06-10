import { type AbstractVerifier, verifyJWT } from 'did-jwt'
import type { Resolvable } from 'did-resolver'
import { verifyCredential } from '../index.js'
import { bytesToBase64url, sha256, stringToBytes } from './util.js'
import { digestDisclosure, parseDisclosure } from './disclosures.js'

export interface VerifySdPresentationOptions {
  resolver: Resolvable
  /** What the verifier expects in the KB-JWT's `aud`. */
  expectedAudience: string
  /** What the verifier expects in the KB-JWT's `nonce` — the challenge it issued. */
  expectedNonce: string
  /** Custom verifier for the JWS algorithm in use (e.g. an `Eip712Verifier`). */
  verifier?: AbstractVerifier
  /** Accepted skew on KB-JWT `iat`/`exp` in seconds (default 60). */
  maxSkewSec?: number
}

export interface VerifiedSdPresentation {
  /** Issuer DID recovered from the VC signature. */
  issuer: string
  /** Holder DID recovered from the KB-JWT signature. */
  holder: string
  /**
   * Materialized claims: always-disclosed fields from the VC's
   * `credentialSubject`, plus every successfully-disclosed hidden claim.
   */
  claims: Record<string, unknown>
  /** Count of digests in `_sd` that were *not* accompanied by a disclosure. */
  undisclosedCount: number
  /** Claim names that were disclosed in this presentation. */
  disclosedNames: string[]
  /** The full VC payload, for advanced inspection. */
  vcPayload: Record<string, unknown>
  /** The KB-JWT payload, for advanced inspection. */
  kbPayload: Record<string, unknown>
}

/**
 * Verify an SD-JWT-VC presentation.
 *
 * Steps performed (failure of any one rejects the whole presentation):
 *   1. Split the combined form on `~`.
 *   2. Signature-verify the VC JWT via did-jwt-vc's `verifyCredential`.
 *   3. For each disclosure: hash it, require the hash to be in `_sd`,
 *      parse the tuple, and merge the claim into the materialized subject.
 *   4. Signature-verify the KB-JWT via did-jwt's `verifyJWT`.
 *   5. Check KB-JWT `aud`, `nonce`, `iat`/`exp`.
 *   6. Recompute `sd_hash` over the presentation body and check it matches.
 *   7. Enforce that the KB-JWT issuer equals the VC subject (holder ↔ subject binding).
 */
export async function verifySdPresentation(
  combined: string,
  opts: VerifySdPresentationOptions
): Promise<VerifiedSdPresentation> {
  const maxSkew = opts.maxSkewSec ?? 60

  // 1. Split the wire form. Expect `<vcJwt>~<d1>~…~<dN>~<kbJwt>`, so at least
  //    two parts; intermediate parts are disclosures (empty strings allowed
  //    but ignored — they appear when there are zero disclosures).
  const parts = combined.split('~')
  if (parts.length < 2) {
    throw new Error('Invalid SD-JWT-VC presentation: expected at least <vcJwt>~<kbJwt>')
  }
  const vcJwt = parts[0]
  const kbJwt = parts[parts.length - 1]
  if (kbJwt === '') {
    throw new Error('Invalid SD-JWT-VC presentation: missing Key-Binding JWT')
  }
  const disclosureEncodeds = parts.slice(1, -1).filter((s) => s.length > 0)

  // 2. VC signature.
  const verifiedVc = await verifyCredential(vcJwt, opts.resolver, {}, opts.verifier)
  const vcPayload = verifiedVc.payload as Record<string, any>
  const issuer: string = verifiedVc.issuer

  // 3. Disclosures.
  const sd: string[] = vcPayload.vc?.credentialSubject?._sd ?? []
  const sdAlg: string = (vcPayload._sd_alg as string) ?? 'sha-256'
  if (sdAlg !== 'sha-256') {
    throw new Error(`Unsupported _sd_alg: ${sdAlg} (only sha-256 is implemented)`)
  }
  const disclosed: Record<string, unknown> = {}
  const disclosedNames: string[] = []
  for (const enc of disclosureEncodeds) {
    const h = await digestDisclosure(enc)
    if (sd.indexOf(h) === -1) {
      throw new Error(`Disclosure digest not present in _sd: ${h}`)
    }
    const [, name, value] = parseDisclosure(enc)
    if (Object.prototype.hasOwnProperty.call(disclosed, name)) {
      throw new Error(`Duplicate disclosure for claim "${name}"`)
    }
    disclosed[name] = value
    disclosedNames.push(name)
  }

  // 4. KB-JWT signature. We disable did-jwt's built-in aud check so we can
  //    produce a friendlier error message in step 5.
  const verifiedKb = await verifyJWT(
    kbJwt,
    {
      resolver: opts.resolver,
      policies: { aud: false },
    },
    opts.verifier
  )
  const kbPayload = verifiedKb.payload as Record<string, any>
  const holder: string = verifiedKb.issuer

  // 5. KB-JWT semantic claims.
  if (kbPayload.nonce !== opts.expectedNonce) {
    throw new Error(
      `KB-JWT nonce mismatch: expected "${opts.expectedNonce}", got "${String(kbPayload.nonce)}"`
    )
  }
  const aud = kbPayload.aud
  const audMatches = Array.isArray(aud)
    ? aud.indexOf(opts.expectedAudience) !== -1
    : aud === opts.expectedAudience
  if (!audMatches) {
    throw new Error(
      `KB-JWT aud mismatch: expected "${opts.expectedAudience}", got "${String(aud)}"`
    )
  }
  const now = Math.floor(Date.now() / 1000)
  if (typeof kbPayload.iat !== 'number') {
    throw new Error('KB-JWT missing required iat claim')
  }
  if (kbPayload.iat > now + maxSkew) {
    throw new Error('KB-JWT iat is in the future')
  }
  if (typeof kbPayload.exp !== 'number') {
    throw new Error('KB-JWT missing required exp claim')
  }
  if (kbPayload.exp < now - maxSkew) {
    throw new Error('KB-JWT has expired')
  }

  // 6. sd_hash binding.
  const body = [vcJwt, ...disclosureEncodeds, ''].join('~')
  const expectedHash = bytesToBase64url(await sha256(stringToBytes(body)))
  if (kbPayload.sd_hash !== expectedHash) {
    throw new Error(
      'KB-JWT sd_hash does not bind to this presentation body (tampering or wrong disclosure set)'
    )
  }

  // 7. Holder ↔ subject binding. `sub` is the only binding mechanism this
  //    implementation supports (no `cnf` yet), so it MUST be present and MUST
  //    match the KB-JWT signer. A missing/non-string `sub` would otherwise let
  //    any DID present the credential.
  const sub = vcPayload.sub
  if (typeof sub !== 'string') {
    throw new Error('VC is missing a string `sub` claim; cannot verify holder binding')
  }
  if (sub !== holder) {
    throw new Error(`Holder ${holder} is not the VC subject ${sub}`)
  }

  // Materialize: always-disclosed fields from the credentialSubject plus the
  // disclosed hidden claims. `_sd` is stripped from the user-facing view.
  const subj = (vcPayload.vc?.credentialSubject ?? {}) as Record<string, unknown>
  const claims: Record<string, unknown> = {}
  for (const k of Object.keys(subj)) {
    if (k === '_sd') continue
    claims[k] = subj[k]
  }
  Object.assign(claims, disclosed)

  return {
    issuer,
    holder,
    claims,
    undisclosedCount: sd.length - disclosureEncodeds.length,
    disclosedNames,
    vcPayload,
    kbPayload,
  }
}
