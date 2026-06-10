import {
  base64ToBytes,
  bytesToBase64url,
  bytesToString,
  randomSalt,
  sha256,
  stringToBytes,
} from './util.js'

/** The unencoded form of a disclosure: `[salt, claim_name, claim_value]`. */
export type DisclosureTuple = readonly [salt: string, name: string, value: unknown]

/** One claim packaged for selective disclosure. */
export interface Disclosure {
  /**
   * The wire form: `base64url(JSON.stringify([salt, name, value]))`.
   * This is what the holder transmits when revealing the claim.
   */
  encoded: string
  /**
   * The digest that goes into the issuer-signed `_sd` array:
   * `base64url(sha256(encoded))`.
   */
  digest: string
  /** The original claim name. Kept for the holder's wallet UI; never crosses the wire. */
  name: string
  /** The original claim value. Kept for the holder's wallet UI; never crosses the wire. */
  value: unknown
}

/**
 * Build a fresh disclosure for a single claim.
 *
 * The salt is freshly generated; reusing salts across credentials would let a
 * verifier link two presentations by hash equality. Each call produces a new salt.
 */
export async function makeDisclosure(name: string, value: unknown): Promise<Disclosure> {
  const tuple: DisclosureTuple = [randomSalt(), name, value]
  // RFC 8259 JSON encoding. The exact byte sequence here is what gets hashed,
  // so two implementations must agree on it.
  const json = JSON.stringify(tuple)
  const encoded = bytesToBase64url(stringToBytes(json))
  const digest = bytesToBase64url(await sha256(stringToBytes(encoded)))
  return { encoded, digest, name, value }
}

/** Compute the `_sd`-array digest for an already-encoded disclosure. */
export async function digestDisclosure(encoded: string): Promise<string> {
  return bytesToBase64url(await sha256(stringToBytes(encoded)))
}

/** Parse the wire form of a disclosure back to its `[salt, name, value]` tuple. */
export function parseDisclosure(encoded: string): DisclosureTuple {
  const json = bytesToString(base64ToBytes(encoded))
  let arr: unknown
  try {
    arr = JSON.parse(json)
  } catch (e) {
    throw new Error(`Invalid disclosure: not valid JSON (${(e as Error).message})`)
  }
  if (
    !Array.isArray(arr) ||
    arr.length !== 3 ||
    typeof arr[0] !== 'string' ||
    typeof arr[1] !== 'string'
  ) {
    throw new Error('Invalid disclosure: expected [salt, name, value] tuple')
  }
  return arr as unknown as DisclosureTuple
}
