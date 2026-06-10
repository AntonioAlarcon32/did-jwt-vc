import { base64ToBytes, bytesToBase64url } from 'did-jwt'

export { base64ToBytes, bytesToBase64url }

export function stringToBytes(s: string): Uint8Array {
  return new TextEncoder().encode(s)
}

export function bytesToString(b: Uint8Array): string {
  return new TextDecoder().decode(b)
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  // subtle.digest's input must be an ArrayBuffer; copy defensively so the
  // call works regardless of whether the input is backed by a SharedArrayBuffer.
  const buf = new Uint8Array(bytes).buffer
  const h = await crypto.subtle.digest('SHA-256', buf)
  return new Uint8Array(h)
}

export function randomSalt(numBytes = 16): string {
  const bytes = new Uint8Array(numBytes)
  crypto.getRandomValues(bytes)
  return bytesToBase64url(bytes)
}
