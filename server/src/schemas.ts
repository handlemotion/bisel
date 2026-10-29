import { z } from "zod";
import { b64urlByteLength, isB64url } from "./encoding";

export const MAX_BLOB_BYTES = 256 * 1024;
const MAX_KEY_ENVELOPE_BYTES = 4 * 1024;

const b64 = (maxBytes: number) =>
  z
    .string()
    .min(1)
    .refine(isB64url, "must be unpadded base64url")
    .refine((s) => b64urlByteLength(s) <= maxBytes, "too large");

/** Client-chosen opaque ids (devices, items). E.g. 16 random bytes as base64url, or a UUID. */
export const IdSchema = z.string().regex(/^[A-Za-z0-9_-]{16,64}$/);

export const DeviceRegistrationSchema = z.object({
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

export const BootstrapSchema = z.object({
  device: DeviceRegistrationSchema,
  /** Ed25519 public key, raw 32 bytes, base64url. */
  recovery_pubkey: b64(32),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
});

export const RecoverySessionSchema = z.object({ device: DeviceRegistrationSchema }).partial();

export const RecoveryRotateSchema = z.object({
  recovery_pubkey: b64(32),
  recovery_envelope: b64(MAX_KEY_ENVELOPE_BYTES),
});

export const PutItemSchema = z.object({
  base_rev: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  blob: z.string().min(1).refine(isB64url, "must be unpadded base64url"),
});

const intParam = (def: number) =>
  z
    .string()
    .regex(/^\d{1,15}$/)
    .transform(Number)
    .optional()
    .transform((v) => v ?? def);

export const SyncQuerySchema = z.object({
  since: intParam(0),
  limit: intParam(200).pipe(z.number().int().min(1).max(500)),
});

export const DeleteQuerySchema = z.object({
  base_rev: z.string().regex(/^\d{1,15}$/).transform(Number),
});
