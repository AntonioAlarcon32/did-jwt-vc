import type { JWTHeader } from 'did-jwt'
import { createVerifiableCredentialJwt } from '../index.js'
import type { Issuer, JWT } from '../types.js'
import { makeDisclosure, type Disclosure } from './disclosures.js'

export interface IssueSdCredentialOptions {
  /** did-jwt-vc Issuer: `{ did, signer, alg }`. */
  issuer: Issuer
  /**
   * Header fields merged into the VC JWT header alongside `typ: 'vc+sd-jwt'`.
   * For EIP-712 callers this is `{ eip712Domain: domain }`. Anything JSON-serialisable works.
   */
  headerExtensions?: Record<string, unknown>
  /**
   * VC payload fields apart from `vc` itself — typically `sub`, `nbf`, `exp`,
   * `jti`. The `iss` is set automatically from `issuer.did`.
   */
  base?: { sub?: string; nbf?: number; exp?: number; jti?: string; [k: string]: unknown }
  /** Extra entries appended after `"VerifiableCredential"` in `vc.type`. */
  type?: string[]
  /** Extra entries appended after the W3C base context in `vc["@context"]`. */
  context?: string[]
  /** Claims that travel in plaintext inside `credentialSubject`. */
  disclosed?: Record<string, unknown>
  /** Claims that are hashed into `_sd`; their disclosures travel separately. */
  hidden: Record<string, unknown>
}

export interface IssueSdCredentialResult {
  /** The signed VC JWT alone — three dot-separated segments. */
  jwt: JWT
  /**
   * All disclosures, in declaration order. The holder must store these to
   * be able to present any of the hidden claims later.
   */
  disclosures: Disclosure[]
  /**
   * The combined SD-JWT-VC form ready to hand to the holder. Format:
   *   `<vcJwt>~<disclosure_1>~<disclosure_2>~…~`
   * The trailing `~` is the empty slot where a Key-Binding JWT will go at
   * presentation time.
   */
  combined: string
}

/**
 * Issue a Verifiable Credential with selectively-disclosable claims.
 *
 * The hidden claims are replaced with their SHA-256 digests inside
 * `vc.credentialSubject._sd`, sorted lexicographically (SD-JWT recommendation).
 * The actual claim values are returned as separate `Disclosure` objects that
 * the issuer must hand to the holder out of band. The signature covers the
 * `_sd` array but never the disclosures.
 */
export async function issueSdCredential(
  opts: IssueSdCredentialOptions
): Promise<IssueSdCredentialResult> {
  if (Object.keys(opts.hidden).length === 0) {
    throw new Error(
      'issueSdCredential: at least one hidden claim is required; use createVerifiableCredentialJwt directly for plain VCs'
    )
  }

  // Build a Disclosure for every hidden claim.
  const disclosures: Disclosure[] = []
  for (const name of Object.keys(opts.hidden)) {
    disclosures.push(await makeDisclosure(name, opts.hidden[name]))
  }

  // _sd is sorted lex so its order doesn't accidentally leak the original
  // claim names (a sorted-by-name array would have been the obvious leak).
  const sd = disclosures.map((d) => d.digest).slice().sort()

  const credentialSubject: Record<string, unknown> = {
    ...(opts.disclosed ?? {}),
    _sd: sd,
  }

  const payload = {
    ...(opts.base ?? {}),
    _sd_alg: 'sha-256',
    vc: {
      '@context': ['https://www.w3.org/2018/credentials/v1', ...(opts.context ?? [])],
      type: ['VerifiableCredential', ...(opts.type ?? [])],
      credentialSubject,
    },
  }

  const jwt: JWT = await createVerifiableCredentialJwt(payload, opts.issuer, {
    header: {
      typ: 'vc+sd-jwt',
      ...(opts.headerExtensions ?? {}),
    } as unknown as Partial<JWTHeader>,
  })

  const combined = [jwt, ...disclosures.map((d) => d.encoded), ''].join('~')
  return { jwt, disclosures, combined }
}
