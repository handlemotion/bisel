import { z } from "zod";
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
export const MAX_ROTATE_ITEMS = 20_000;
export const MAX_DEVICES = 64;

const b64 = (maxBytes: number) =>
  z
    .string()
    .min(1)
    .refine(isB64url, "must be unpadded base64url")
    .refine((s) => b64urlByteLength(s) <= maxBytes, "too large");

const uint = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const epoch = z.number().int().min(1).max(Number.MAX_SAFE_INTEGER);

/** Client-chosen opaque ids (devices, items). E.g. 16 random bytes as base64url, or a UUID. */
export const IdSchema = z.string().regex(/^[A-Za-z0-9_-]{16,64}$/);

export const DeviceRegistrationSchema = z.strictObject({
  id: IdSchema,
  name: z.string().min(1).max(100),
  kind: z.string().regex(/^[a-z0-9_-]{1,32}$/),
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
});

export const RecoverySessionSchema = z.strictObject({ device: DeviceRegistrationSchema, epoch });

export const RecoveryRotateSchema = z.strictObject({
  recovery_pubkey: b64(32),
  recovery_enc_pubkey: b64(32),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
  epoch,
});

export const PutItemSchema = z.strictObject({
  base_rev: uint,
  /** Epoch of the VK this blob's item key is wrapped under; a stale epoch is refused (409 stale_epoch). */
  epoch,
  blob: z.string().min(1).refine(isB64url, "must be unpadded base64url"),
});

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
  revoke: IdSchema.nullable(),
  items: z
    .array(
      z.strictObject({
        id: IdSchema,
        rev: z.number().int().min(1).max(Number.MAX_SAFE_INTEGER),
        /** New wrapped item key: exactly 60 bytes, replaces the first 60 bytes of the stored blob. */
        key: z.string().length(WRAPPED_KEY_CHARS).refine(isB64url, "must be unpadded base64url"),
      }),
    )
    .max(MAX_ROTATE_ITEMS)
    .refine((a) => unique(a.map((i) => i.id)), "duplicate item id"),
  devices: z
    .array(z.strictObject({ id: IdSchema, envelope: b64(MAX_KEY_ENVELOPE_BYTES) }))
    .min(1)
    .max(MAX_DEVICES)
    .refine((a) => unique(a.map((d) => d.id)), "duplicate device id"),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
});

const intParam = (def: number) =>
  z
    .string()
    .regex(/^\d{1,15}$/)
    .transform(Number)
    .optional()
    .transform((v) => v ?? def);

export const SyncQuerySchema = z.strictObject({
  since: intParam(0),
  limit: intParam(200).pipe(z.number().int().min(1).max(500)),
});

export const DeleteQuerySchema = z.strictObject({
  base_rev: z.string().regex(/^\d{1,15}$/).transform(Number),
});

export const EmptyQuerySchema = z.strictObject({});
