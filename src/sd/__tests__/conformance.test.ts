/**
 * Cross-implementation conformance: our SD-JWT issuance/presentation against the
 * independent `@sd-jwt/*` implementation (openwallet-foundation-labs/sd-jwt-js).
 *
 * If these pass, our wire format (`<vcJwt>~<disclosure>~…~[kbJwt]`), disclosure
 * encoding (`base64url(JSON([salt, name, value]))`), and `_sd` digest computation
 * (`base64url(sha256(encoded))`) interoperate with a third-party SD-JWT stack.
 */
import { createHash } from 'node:crypto'
import { describe, expect, it } from '@jest/globals'
import { EthrDID } from 'ethr-did'
import { decodeSdJwt, getClaims, splitSdJwt } from '@sd-jwt/decode'
import type { Issuer } from '../../index.js'
import { createSdPresentation, digestDisclosure, issueSdCredential } from '../index.js'

const issuer = new EthrDID({
  identifier: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
  privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75',
}) as Issuer

const holder = new EthrDID({
  identifier: '0x435df3eda57154cf8cf7926079881f2912f54db4',
  privateKey: '0000000000000000000000000000000000000000000000000000000000000001',
}) as Issuer

// @sd-jwt Hasher: must produce the raw digest bytes for the given algorithm
const hasher = (data: string | ArrayBuffer, alg: string) => {
  const input = typeof data === 'string' ? data : Buffer.from(data)
  return createHash(alg.replace('-', '')).update(input).digest()
}

const hidden = {
  degree: { type: 'BachelorDegree', name: 'Baccalauréat en musiques numériques' },
  birthdate: '1999-12-31',
  nationality: 'ES',
}

async function issueFixture() {
  return issueSdCredential({
    issuer,
    base: { sub: holder.did, nbf: 1562950282 },
    type: ['UniversityDegreeCredential'],
    disclosed: { enrolled: true },
    hidden,
  })
}

describe('SD-JWT conformance against @sd-jwt/decode', () => {
  it('decodeSdJwt parses our combined issuance form and recovers every disclosure', async () => {
    const { combined, disclosures } = await issueFixture()

    const decoded = await decodeSdJwt(combined, hasher)

    expect(decoded.jwt.header.typ).toEqual('vc+sd-jwt')
    expect(decoded.kbJwt).toBeUndefined()
    expect(decoded.disclosures).toHaveLength(disclosures.length)

    for (const ours of disclosures) {
      const theirs = decoded.disclosures.find((d) => d.key === ours.name)
      expect(theirs).toBeDefined()
      expect(theirs!.value).toEqual(ours.value)
      expect(theirs!.encode()).toEqual(ours.encoded)
    }
  })

  it('their digest computation matches the _sd array our issuer signed', async () => {
    const { combined } = await issueFixture()

    const decoded = await decodeSdJwt(combined, hasher)
    const sd: string[] = (decoded.jwt.payload as any).vc.credentialSubject._sd
    expect(sd).toHaveLength(Object.keys(hidden).length)

    for (const theirs of decoded.disclosures) {
      const theirDigest = await theirs.digest({ hasher, alg: 'sha-256' })
      expect(sd).toContain(theirDigest)
      // and our own digest helper agrees byte for byte
      expect(await digestDisclosure(theirs.encode())).toEqual(theirDigest)
    }
  })

  it('getClaims reconstructs the hidden claims through their unpacking logic', async () => {
    const { combined } = await issueFixture()

    const decoded = await decodeSdJwt(combined, hasher)
    const claims = (await getClaims(decoded.jwt.payload, decoded.disclosures, hasher)) as any

    const subject = claims.vc.credentialSubject
    expect(subject._sd).toBeUndefined()
    expect(subject.enrolled).toEqual(true)
    expect(subject.degree).toEqual(hidden.degree)
    expect(subject.birthdate).toEqual(hidden.birthdate)
    expect(subject.nationality).toEqual(hidden.nationality)
  })

  it('a partial presentation parses with the KB-JWT and only the revealed claims', async () => {
    const { jwt, disclosures } = await issueFixture()

    const presentation = await createSdPresentation({
      vcJwt: jwt,
      disclosures,
      reveal: ['degree'],
      holderDid: holder.did,
      signer: holder.signer!,
      alg: holder.alg ?? 'ES256K-R',
      audience: 'did:web:verifier.example',
      nonce: 'nonce-123',
    })

    const decoded = await decodeSdJwt(presentation.combined, hasher)
    expect(decoded.kbJwt).toBeDefined()
    expect((decoded.kbJwt!.header as any).typ).toEqual('kb+jwt')
    expect((decoded.kbJwt!.payload as any).nonce).toEqual('nonce-123')

    expect(decoded.disclosures).toHaveLength(1)
    expect(decoded.disclosures[0].key).toEqual('degree')

    const claims = (await getClaims(decoded.jwt.payload, decoded.disclosures, hasher)) as any
    const subject = claims.vc.credentialSubject
    expect(subject.degree).toEqual(hidden.degree)
    expect(subject.birthdate).toBeUndefined()
    expect(subject.nationality).toBeUndefined()
  })

  it('our sd_hash commits to the same bytes their splitter sees as the presentation body', async () => {
    const { jwt, disclosures } = await issueFixture()

    const presentation = await createSdPresentation({
      vcJwt: jwt,
      disclosures,
      reveal: ['degree', 'birthdate'],
      holderDid: holder.did,
      signer: holder.signer!,
      alg: holder.alg ?? 'ES256K-R',
      audience: 'did:web:verifier.example',
      nonce: 'nonce-456',
    })

    // Rebuild the body exactly as @sd-jwt sees it: everything up to the KB-JWT,
    // including the trailing `~` separator.
    const { jwt: vcPart, disclosures: disclosureParts, kbJwt } = splitSdJwt(presentation.combined)
    expect(kbJwt).toBeDefined()
    const body = [vcPart, ...disclosureParts, ''].join('~')

    const sdHash = Buffer.from(hasher(body, 'sha-256')).toString('base64url')
    const decoded = await decodeSdJwt(presentation.combined, hasher)
    expect((decoded.kbJwt!.payload as any).sd_hash).toEqual(sdHash)
  })
})
