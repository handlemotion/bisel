-- bisel server schema. All binary values are stored as unpadded base64url TEXT.
-- All timestamps are unix seconds.

-- Single row, created by POST /v1/bootstrap. Its existence is what makes bootstrap 404 forever.
CREATE TABLE meta (
  id                INTEGER PRIMARY KEY CHECK (id = 1),
  recovery_alg      TEXT    NOT NULL,
  recovery_pubkey   TEXT    NOT NULL,
  recovery_envelope TEXT    NOT NULL,
  head_seq          INTEGER NOT NULL DEFAULT 0,
  created_at        INTEGER NOT NULL
);

CREATE TABLE devices (
  id           TEXT PRIMARY KEY,
  name         TEXT    NOT NULL,
  kind         TEXT    NOT NULL,
  sig_alg      TEXT    NOT NULL,
  sig_pubkey   TEXT    NOT NULL,
  enc_pubkey   TEXT    NOT NULL,
  envelope     TEXT    NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER,
  revoked_at   INTEGER
);

-- seq UNIQUE: a duplicate seq aborts the whole write batch instead of silently corrupting the log.
CREATE TABLE items (
  id         TEXT PRIMARY KEY,
  rev        INTEGER NOT NULL,
  seq        INTEGER NOT NULL UNIQUE,
  deleted    INTEGER NOT NULL DEFAULT 0,
  blob       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE nonces (
  nonce TEXT PRIMARY KEY,
  ts    INTEGER NOT NULL
);
CREATE INDEX nonces_ts ON nonces (ts);

CREATE TABLE events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  ts         INTEGER NOT NULL,
  device_id  TEXT,
  type       TEXT    NOT NULL,
  subject_id TEXT
);

-- Worker-side failed-auth counter, per client IP, fixed window.
CREATE TABLE auth_failures (
  ip           TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count        INTEGER NOT NULL
);
