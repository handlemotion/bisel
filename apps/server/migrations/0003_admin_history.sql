-- Vault-admin key, server-side retention, recovery activation delay (SECURITY-REVIEW H1, M4).

-- Ed25519 public key derived from VK (HKDF "bisel/v1/admin-sig"). Destructive routes need a second signature by it.
ALTER TABLE meta ADD COLUMN admin_pubkey TEXT NOT NULL DEFAULT '';

-- NULL = active. A device registered through recovery can be held back until this time (unix seconds)
-- so the owner's other devices get a chance to see "recovery used" and cancel it.
ALTER TABLE devices ADD COLUMN activates_at INTEGER;

-- Previous state of an item at the moment it was overwritten, tombstoned or re-keyed, kept for HISTORY_RETENTION_DAYS.
-- kind: 'overwrite' | 'delete' (blob = the whole previous blob) | 'rotate' (blob = the previous 80-char wrapped item key only).
CREATE TABLE item_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  item_id     TEXT    NOT NULL,
  rev         INTEGER NOT NULL,
  kind        TEXT    NOT NULL,
  blob        TEXT    NOT NULL,
  deleted     INTEGER NOT NULL,
  epoch       INTEGER NOT NULL,
  replaced_at INTEGER NOT NULL
);
CREATE INDEX item_history_item ON item_history (item_id, id);
CREATE INDEX item_history_replaced ON item_history (replaced_at);
