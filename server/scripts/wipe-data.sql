-- Empties every table the Worker writes to and leaves the schema and the migration history alone,
-- so the next POST /v1/bootstrap starts a brand-new box. DESTROYS ALL DATA in the database it runs against.
-- Used once, to remove the throwaway data of the post-deploy check (DEPLOY.md step 9). No foreign keys exist.
DELETE FROM item_history;
DELETE FROM items;
DELETE FROM devices;
DELETE FROM events;
DELETE FROM nonces;
DELETE FROM auth_failures;
DELETE FROM assertions;
DELETE FROM meta;
