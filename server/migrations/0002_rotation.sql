-- Vault-key rotation (SPEC §4/§6): an epoch counter that moves every time VK changes, the
-- recovery encryption public key (so any device can re-seal VK for the recovery phrase without
-- knowing it), per-device envelope epoch, and an assertion table used to abort D1 batches.

-- epoch: starts at 1, +1 on every POST /v1/rotate. Anything derived from VK carries the epoch it was built for.
ALTER TABLE meta ADD COLUMN epoch INTEGER NOT NULL DEFAULT 1;
-- X25519 public key derived from the recovery phrase; the recovery envelope is HPKE-sealed to it. Opaque to the server.
ALTER TABLE meta ADD COLUMN recovery_enc_pubkey TEXT NOT NULL DEFAULT '';
-- The epoch of the VK inside devices.envelope. Every active device must be at meta.epoch.
ALTER TABLE devices ADD COLUMN envelope_epoch INTEGER NOT NULL DEFAULT 1;

-- A batch statement `INSERT INTO assertions SELECT CASE WHEN <condition> THEN 1 ELSE 0 END` violates
-- the CHECK when the condition is false, which makes D1 roll the whole batch back. Rows are deleted
-- again by the same batch; the table is empty at rest.
CREATE TABLE assertions (ok INTEGER NOT NULL CHECK (ok = 1));

CREATE INDEX auth_failures_window ON auth_failures (window_start);
CREATE INDEX events_ts ON events (ts);
