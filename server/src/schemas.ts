import * as z from "zod/mini";
import { b64urlByteLength, isB64url } from "./encoding";

export const MAX_BLOB_BYTES = 256 * 1024;
const MAX_KEY_ENVELOPE_BYTES = 4 * 1024;

/**
 * Wrapped item key at the start of every blob: nonce(12) || IK(32) || tag(16) = 60 bytes = exactly 80
 * base64url characters, so a blob can be re-wrapped by replacing its first 80 characters.
 */
export const WRAPPED_KEY_BYTES = 60;
export const WRAPPED_KEY_CHARS = 80;

/** Hard cap on any request body, applied before authentication (larger is treated as garbage: bare 404). */
export const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** Per-route caps, applied after authentication (413 for the owner). */
export const BODY_LIMITS = {
  bootstrap: 64 * 1024,
  item: 400 * 1024, // 256 KiB blob in base64url plus JSON framing
  small: 32 * 1024,
  rotate: MAX_BODY_BYTES,
} as const;
/**
 * Rotation sends one 127-byte JSON entry per item as a single D1 parameter, and D1 refuses values over 2 MB:
 * 20,000 entries are 2.54 MB, 12,000 are 1.5 MB.
 */
export const MAX_ROTATE_ITEMS = 12_000;
export const MAX_DEVICES = 64;

// zod/mini, not the classic build: the classic import alone is ~25 ms of Worker startup (826 KB of source);
// the same schemas on mini evaluate in well under a millisecond.
const b64 = (maxBytes: number) =>
  z
    .string()
    .check(z.minLength(1), z.refine(isB64url, "must be unpadded base64url"), z.refine((s) => b64urlByteLength(s) <= maxBytes, "too large"));

const intIn = (min: number) => z.int().check(z.minimum(min), z.maximum(Number.MAX_SAFE_INTEGER));
const uint = intIn(0);
const epoch = intIn(1);
const rev = intIn(1);

/** Client-chosen opaque ids (devices, items). E.g. 16 random bytes as base64url, or a UUID. */
export const IdSchema = z.string().check(z.regex(/^[A-Za-z0-9_-]{16,64}$/));

/** Device names are shown in UIs and logs: no control, format (bidi override) or line/paragraph separator characters. */
const deviceName = z
  .string()
  .check(
    z.minLength(1),
    z.maxLength(100),
    z.regex(/^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}\p{Co}\p{Cn}]+$/u, "control or format characters are not allowed"),
  );

export const DeviceRegistrationSchema = z.strictObject({
  id: IdSchema,
  name: deviceName,
  kind: z.string().check(z.regex(/^[a-z0-9_-]{1,32}$/)),
  /** P-256 public key, X9.63 uncompressed (65 bytes), base64url. */
  sig_pubkey: b64(65),
  /** P-256 public key, X9.63 uncompressed (65 bytes), base64url. Opaque to the server. */
  enc_pubkey: b64(65),
  /** VK encrypted to enc_pubkey. Opaque to the server. */
  envelope: b64(MAX_KEY_ENVELOPE_BYTES),
});
export type DeviceRegistration = z.infer<typeof DeviceRegistrationSchema>;

/** A device registration is built from VK, so it carries the epoch of the VK it was built from. */
export const DeviceApprovalSchema = z.strictObject({ ...DeviceRegistrationSchema.shape, epoch });

export const BootstrapSchema = z.strictObject({
  device: DeviceRegistrationSchema,
  /** Ed25519 public key, raw 32 bytes, base64url. */
  recovery_pubkey: b64(32),
  /** X25519 public key, raw 32 bytes, base64url: the recovery envelope is HPKE-sealed to it. */
  recovery_enc_pubkey: b64(32),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
  /** Ed25519 public key derived from VK: the vault-admin key (second signature on destructive routes). */
  admin_pubkey: b64(32),
});

export const RecoverySessionSchema = z.strictObject({ device: DeviceRegistrationSchema, epoch });

export const RecoveryRotateSchema = z.strictObject({
  recovery_pubkey: b64(32),
  recovery_enc_pubkey: b64(32),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
  epoch,
});

/** Tombstone: a marker sealed under VK (AAD id|rev|tomb), so other devices can tell a real delete from a forged one. */
const marker = b64(256);

export const DeleteItemSchema = z.strictObject({ epoch, marker });

export const PutItemSchema = z.strictObject({
  base_rev: uint,
  /** Epoch of the VK this blob's item key is wrapped under; a stale epoch is refused (409 stale_epoch). */
  epoch,
  blob: z.string().check(z.minLength(1), z.refine(isB64url, "must be unpadded base64url")),
});

const ID_RE = /^[A-Za-z0-9_-]{16,64}$/;
const isRev = (v: unknown) => typeof v === "number" && Number.isSafeInteger(v) && v >= 1;
const keyCount = (o: object) => {
  let n = 0;
  for (const _ in o) n++;
  return n;
};

/**
 * Rotate's `items` / `tombstones` arrays are up to MAX_ROTATE_ITEMS long. Running a zod object schema per element costs
 * ~1 ms per 1,000 elements of the Worker's 10 ms CPU budget, so these are checked with one plain loop (same rules: strict
 * keys, id shape, rev >= 1, base64url payload, unique ids).
 */
function rotateList<T extends { id: string }>(name: string, valueKey: string, validValue: (v: unknown) => boolean) {
  return z.custom<T[]>((input) => {
    if (!Array.isArray(input) || input.length > MAX_ROTATE_ITEMS) return false;
    const seen = new Set<string>();
    for (const e of input) {
      if (typeof e !== "object" || e === null || keyCount(e) !== 3) return false;
      const { id, rev: r, [valueKey]: v } = e as Record<string, unknown>;
      if (typeof id !== "string" || !ID_RE.test(id) || !isRev(r) || !validValue(v)) return false;
      if (seen.has(id)) return false;
      seen.add(id);
    }
    return true;
  }, `invalid ${name}`);
}

const tombstoneList = rotateList<{ id: string; rev: number; marker: string }>(
  "tombstones",
  "marker",
  (v) => typeof v === "string" && v.length > 0 && isB64url(v) && b64urlByteLength(v) <= 256,
);
const rotateItemList = rotateList<{ id: string; rev: number; key: string }>(
  "items",
  "key",
  /** New wrapped item key: exactly 60 bytes, replaces the first 60 bytes of the stored blob. */
  (v) => typeof v === "string" && v.length === WRAPPED_KEY_CHARS && isB64url(v),
);

const unique = (ids: string[]) => new Set(ids).size === ids.length;

/**
 * POST /v1/rotate. Everything for the new VK in one request: the new wrapped item key of every live
 * item (at its current rev), a new envelope for every device that stays, the new recovery envelope.
 */
export const RotateSchema = z.strictObject({
  base_epoch: epoch,
  /** head_seq the client's item snapshot is at. Any write since then makes the rotation fail (409). */
  base_seq: uint,
  /** Revoke this device in the same transaction (null = rotate only). */
  revoke: z.nullable(IdSchema),
  /** Ed25519 public key derived from the new VK. The request's admin signature (made with the old key) authorises it. */
  new_admin_pubkey: b64(32),
  /** Every tombstone, re-sealed under the new VK. */
  tombstones: tombstoneList,
  items: rotateItemList,
  devices: z
    .array(z.strictObject({ id: IdSchema, envelope: b64(MAX_KEY_ENVELOPE_BYTES) }))
    .check(z.minLength(1), z.maxLength(MAX_DEVICES), z.refine((a) => unique(a.map((d) => d.id)), "duplicate device id")),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
});

const digits = z.string().check(z.regex(/^\d{1,15}$/));
const intParam = (def: number) =>
  z.pipe(
    z.optional(z.pipe(digits, z.transform(Number))),
    z.transform((v) => v ?? def),
  );
const boundedInt = (min: number, max: number) => z.int().check(z.minimum(min), z.maximum(max));

export const SyncQuerySchema = z.strictObject({
  since: intParam(0),
  /** Only events with a larger id (omit: the latest 50). */
  events_since: z.optional(z.pipe(digits, z.transform(Number))),
  limit: z.pipe(intParam(200), boundedInt(1, 500)),
});

export const DeleteQuerySchema = z.strictObject({
  base_rev: z.pipe(digits, z.transform(Number)),
});

export const HistoryQuerySchema = z.strictObject({
  id: z.optional(IdSchema),
  /** History row id cursor: only rows after it. */
  after: intParam(0),
  limit: z.pipe(intParam(100), boundedInt(1, 500)),
});

export const EmptyQuerySchema = z.strictObject({});

/** Device-code connect (DESIGN-accounts.md §6.3). */
export const ConnectStartSchema = z.strictObject({ device_name: deviceName });
/** 32 random bytes, base64url: the secret only the requesting Mac holds. */
export const DeviceCodeSchema = z.string().check(z.regex(/^[A-Za-z0-9_-]{43}$/));
export const ConnectPollSchema = z.strictObject({ device_code: DeviceCodeSchema });
