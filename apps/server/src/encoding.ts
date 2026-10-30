// Unpadded base64url, the single binary-to-text encoding used on the wire and in D1.

const B64URL = /^[A-Za-z0-9_-]*$/;

export function isB64url(s: string): boolean {
  // length % 4 === 1 can never be produced by an encoder.
  return B64URL.test(s) && s.length % 4 !== 1;
}

/** Decoded byte length of a valid unpadded base64url string, without decoding it. */
export function b64urlByteLength(s: string): number {
  return Math.floor((s.length * 3) / 4);
}

export function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  if (!isB64url(s)) throw new Error("invalid base64url");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
