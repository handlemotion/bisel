-- Device-code connect (DESIGN-accounts.md §6.3): a Mac asks for a code, the person approves it on the dashboard while
-- signed in, and the Mac redeems its secret to create (or, for 'claim', to link) a box. No token is ever typed.
CREATE TABLE connect_requests (
  id               TEXT PRIMARY KEY,
  -- SHA-256 (hex) of the 256-bit secret only the requesting Mac holds. The secret itself is never stored.
  device_code_hash TEXT NOT NULL UNIQUE,
  -- What the person sees and confirms: 8 characters from an unambiguous alphabet. Useless without the secret.
  user_code        TEXT NOT NULL UNIQUE,
  -- 'create': the approving account gets a new box made by the Mac. 'claim': link the existing, unowned box_id to the account.
  kind             TEXT NOT NULL CHECK (kind IN ('create', 'claim')),
  box_id           TEXT,
  device_name      TEXT NOT NULL,
  ip_hash          TEXT NOT NULL,
  country          TEXT,
  created_at       INTEGER NOT NULL,
  expires_at       INTEGER NOT NULL,
  status           TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
  -- The approving account (user.id).
  account_id       TEXT
);
CREATE INDEX connect_requests_ip ON connect_requests (ip_hash, created_at);
CREATE INDEX connect_requests_expires ON connect_requests (expires_at);
