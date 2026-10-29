// A tiny independent implementation of the client side of the signed-request protocol
// (see README "How a client signs requests"), using only Node's WebCrypto.
import { createHash, randomBytes, webcrypto } from "node:crypto";
import type { APIRequestContext, APIResponse } from "@playwright/test";

const subtle = webcrypto.subtle;

export const b64u = (b: Uint8Array | ArrayBuffer) => Buffer.from(b instanceof ArrayBuffer ? new Uint8Array(b) : b).toString("base64url");
export const unb64u = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
export const randomId = () => b64u(randomBytes(16));

export interface Principal {
  /** Value for X-Bisel-Device. */
  id: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export interface TestDevice extends Principal {
  name: string;
  kind: string;
  sigPub: string;
  encPub: string;
  envelope: string;
  registration(): { id: string; name: string; kind: string; sig_pubkey: string; enc_pubkey: string; envelope: string };
}

/** A fresh software "device": P-256 signing key, P-256 encryption pubkey, random opaque envelope. */
export async function newDevice(name: string, kind = "mac"): Promise<TestDevice> {
  const sig = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const enc = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const sigPub = b64u(await subtle.exportKey("raw", sig.publicKey)); // X9.63 uncompressed, 65 bytes
  const encPub = b64u(await subtle.exportKey("raw", enc.publicKey));
  const envelope = b64u(randomBytes(125)); // the server cannot tell this from a real ECIES envelope
  const id = randomId();
  const d: TestDevice = {
    id,
    name,
    kind,
    sigPub,
    encPub,
    envelope,
    // WebCrypto ECDSA emits raw r||s (64 bytes), which is also what CryptoKit's rawRepresentation is.
    sign: async (m) => new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, sig.privateKey, Buffer.from(m))),
    registration: () => ({ id, name, kind, sig_pubkey: sigPub, enc_pubkey: encPub, envelope }),
  };
  return d;
}

export interface RecoveryKey extends Principal {
  pub: string;
}

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/** Ed25519 recovery key from a 32-byte seed (the spec derives the seed with HKDF from the phrase). */
export async function recoveryKeyFromSeed(seed: Uint8Array): Promise<RecoveryKey> {
  const priv = await subtle.importKey("pkcs8", new Uint8Array(Buffer.concat([PKCS8_ED25519_PREFIX, seed])), { name: "Ed25519" }, true, ["sign"]);
  const jwk = await subtle.exportKey("jwk", priv);
  return {
    id: "recovery",
    pub: b64u(unb64u(jwk.x!)),
    sign: async (m) => new Uint8Array(await subtle.sign({ name: "Ed25519" }, priv, Buffer.from(m))),
  };
}

/** Raw 32-byte X25519 public key (the server only checks that it imports). */
export async function randomX25519Pub(): Promise<string> {
  const k = (await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as unknown as { publicKey: webcrypto.CryptoKey };
  return b64u(await subtle.exportKey("raw", k.publicKey));
}

/** The vault-admin key: Ed25519 by a key derived from VK (the real clients derive it with HKDF; the server only sees the public key). */
export interface AdminKey {
  pub: string;
  sign(message: Uint8Array): Promise<Uint8Array>;
}
export async function newAdminKey(): Promise<AdminKey> {
  const k = await recoveryKeyFromSeed(randomBytes(32));
  return { pub: k.pub, sign: k.sign };
}
/** The admin key the tests' "owner" currently holds (moves on every successful rotation). */
export const adminState: { key: AdminKey | null } = { key: null };

/** The box recovery requests name in X-Bisel-Box (device requests never send it). Unset = the pre-accounts fallback. */
export const boxState: { id: string | null } = { id: null };

/** Routes that need the second (vault-admin) signature. */
export function needsAdmin(method: string, path: string): boolean {
  return (
    (method === "POST" && (path === "/v1/rotate" || path === "/v1/devices" || path === "/v1/recovery/rotate" || path === "/v1/box/claim")) ||
    (method === "DELETE" && path.startsWith("/v1/devices/"))
  );
}

export function pct(s: string): string {
  return encodeURIComponent(s).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());
}

export function canonicalQuery(query: Record<string, string | number>): string {
  return Object.entries(query)
    .map(([k, v]) => [pct(k), pct(String(v))] as const)
    .sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

export interface SignOptions {
  ts?: number;
  nonce?: string;
}

export interface Prepared {
  method: string;
  path: string;
  query: Record<string, string | number>;
  body: Buffer;
  headers: Record<string, string>;
}

export async function prepare(
  principal: Principal,
  method: string,
  path: string,
  opts: {
    query?: Record<string, string | number>;
    json?: unknown;
    rawBody?: Buffer;
    /** undefined: sign with the owner's admin key when the route needs it; false: never; a key: that one. */
    admin?: AdminKey | false;
  } & SignOptions = {},
): Promise<Prepared> {
  const query = opts.query ?? {};
  const body = opts.rawBody ?? (opts.json === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(opts.json)));
  const ts = opts.ts ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? b64u(randomBytes(16));
  const bodyHash = createHash("sha256").update(body).digest("hex");
  const signed = [method, path, canonicalQuery(query), bodyHash, String(ts), nonce].join("\n");
  const sig = await principal.sign(new TextEncoder().encode(signed));
  const adminKey = opts.admin === false ? null : (opts.admin ?? (needsAdmin(method, path) ? adminState.key : null));
  const adminSig = adminKey ? b64u(await adminKey.sign(new TextEncoder().encode(`bisel-admin/v1\n${principal.id}\n${signed}`))) : null;
  return {
    method,
    path,
    query,
    body,
    headers: {
      "X-Bisel-Device": principal.id,
      "X-Bisel-Ts": String(ts),
      "X-Bisel-Nonce": nonce,
      "X-Bisel-Sig": b64u(sig),
      ...(adminSig ? { "X-Bisel-Admin": adminSig } : {}),
      ...(principal.id === "recovery" && boxState.id ? { "X-Bisel-Box": boxState.id } : {}),
      ...(body.length ? { "Content-Type": "application/json" } : {}),
    },
  };
}

export class Bisel {
  readonly api: APIRequestContext;
  readonly extraHeaders: Record<string, string>;
  constructor(api: APIRequestContext, extraHeaders: Record<string, string> = {}) {
    this.api = api;
    this.extraHeaders = extraHeaders;
  }

  /** Send an already-prepared (signed) request. Re-sending the same Prepared is a replay. */
  async send(p: Prepared): Promise<APIResponse> {
    return this.api.fetch(p.path, {
      method: p.method,
      params: Object.keys(p.query).length ? (p.query as Record<string, string>) : undefined,
      headers: { ...p.headers, ...this.extraHeaders },
      data: p.body.length ? p.body : undefined,
      maxRedirects: 0,
    });
  }

  async call(
    principal: Principal,
    method: string,
    path: string,
    opts: Parameters<typeof prepare>[3] = {},
  ): Promise<APIResponse> {
    return this.send(await prepare(principal, method, path, opts));
  }

  /** Unsigned request (bootstrap). */
  async raw(method: string, path: string, headers: Record<string, string>, json?: unknown): Promise<APIResponse> {
    return this.api.fetch(path, {
      method,
      headers: { ...headers, ...this.extraHeaders },
      data: json === undefined ? undefined : Buffer.from(JSON.stringify(json)),
      maxRedirects: 0,
    });
  }
}
