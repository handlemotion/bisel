-- Multi-tenant boxes (DESIGN-accounts.md §3, §4). One D1 now holds many boxes; every box-scoped row carries box_id.
-- The existing single box becomes box 'legacy_box_00000000', unowned until an account links it.
-- SQLite cannot change a primary key, so the box-scoped tables are rebuilt (copy, drop, rename).

-- meta (one row, id = 1) -> boxes (one row per box).
CREATE TABLE boxes (
  id                  TEXT PRIMARY KEY,
  recovery_alg        TEXT    NOT NULL,
  recovery_pubkey     TEXT    NOT NULL,
  recovery_enc_pubkey TEXT    NOT NULL DEFAULT '',
  recovery_envelope   TEXT    NOT NULL,
  admin_pubkey        TEXT    NOT NULL DEFAULT '',
  head_seq            INTEGER NOT NULL DEFAULT 0,
  epoch               INTEGER NOT NULL DEFAULT 1,
  created_at          INTEGER NOT NULL,
  -- The account that owns the box (user.id from Better Auth). NULL = unowned. UNIQUE = one box per account
  -- (SQLite allows any number of NULLs).
  owner_id            TEXT UNIQUE,
  -- Rows in `items` (live and tombstones): the per-box cap is checked against this, not by counting.
  item_count          INTEGER NOT NULL DEFAULT 0,
  -- Operator kill switch: a disabled box answers like a revoked device.
  disabled_at         INTEGER
);

INSERT INTO boxes (id, recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, head_seq, epoch, created_at, item_count)
SELECT 'legacy_box_00000000', recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, head_seq, epoch, created_at,
       (SELECT COUNT(*) FROM items)
FROM meta;

DROP TABLE meta;

-- devices: box_id added; the id stays globally unique because it is the authentication lookup key.
CREATE TABLE devices_new (
  id             TEXT PRIMARY KEY,
  box_id         TEXT    NOT NULL,
  name           TEXT    NOT NULL,
  kind           TEXT    NOT NULL,
  sig_alg        TEXT    NOT NULL,
  sig_pubkey     TEXT    NOT NULL,
  enc_pubkey     TEXT    NOT NULL,
  envelope       TEXT    NOT NULL,
  envelope_epoch INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL,
  last_seen_at   INTEGER,
  revoked_at     INTEGER,
  activates_at   INTEGER
);
INSERT INTO devices_new (id, box_id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, envelope_epoch, created_at, last_seen_at, revoked_at, activates_at)
SELECT id, 'legacy_box_00000000', name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, envelope_epoch, created_at, last_seen_at, revoked_at, activates_at
FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
CREATE INDEX devices_box ON devices (box_id, created_at, id);

-- items: (box_id, id) is the key, so two boxes can never touch each other's rows. seq is unique per box.
CREATE TABLE items_new (
  box_id     TEXT    NOT NULL,
  id         TEXT    NOT NULL,
  rev        INTEGER NOT NULL,
  seq        INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  blob       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (box_id, id),
  UNIQUE (box_id, seq)
);
INSERT INTO items_new (box_id, id, rev, seq, deleted, blob, updated_at)
SELECT 'legacy_box_00000000', id, rev, seq, deleted, blob, updated_at FROM items;
DROP TABLE items;
ALTER TABLE items_new RENAME TO items;

CREATE TABLE item_history_new (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  box_id      TEXT    NOT NULL,
  item_id     TEXT    NOT NULL,
  rev         INTEGER NOT NULL,
  kind        TEXT    NOT NULL,
  blob        TEXT    NOT NULL,
  deleted     INTEGER NOT NULL,
  epoch       INTEGER NOT NULL,
  replaced_at INTEGER NOT NULL
);
INSERT INTO item_history_new (id, box_id, item_id, rev, kind, blob, deleted, epoch, replaced_at)
SELECT id, 'legacy_box_00000000', item_id, rev, kind, blob, deleted, epoch, replaced_at FROM item_history;
DROP TABLE item_history;
ALTER TABLE item_history_new RENAME TO item_history;
CREATE INDEX item_history_item ON item_history (box_id, item_id, id);
CREATE INDEX item_history_replaced ON item_history (replaced_at);

CREATE TABLE events_new (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  box_id     TEXT    NOT NULL,
  ts         INTEGER NOT NULL,
  device_id  TEXT,
  type       TEXT    NOT NULL,
  subject_id TEXT
);
INSERT INTO events_new (id, box_id, ts, device_id, type, subject_id)
SELECT id, 'legacy_box_00000000', ts, device_id, type, subject_id FROM events;
DROP TABLE events;
ALTER TABLE events_new RENAME TO events;
CREATE INDEX events_box ON events (box_id, id);
CREATE INDEX events_ts ON events (ts);

-- item_count follows the row count by trigger, so the write path needs no bookkeeping of its own (an upsert that
-- updates an existing row fires no insert trigger). Items are only ever removed together with their box.
CREATE TRIGGER items_count_insert AFTER INSERT ON items
BEGIN
  UPDATE boxes SET item_count = item_count + 1 WHERE id = NEW.box_id;
END;
