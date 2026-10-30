-- Empties every box table the Worker writes to (boxes, devices, items, history, events, connect requests, counters) and leaves the
-- schema, the migration history and the dashboard accounts (Better Auth tables) alone. DESTROYS EVERY BOX in the database it runs
-- against: for a throwaway database only, never for one that holds a real box (use a Time Travel restore there, see DEPLOY.md).
DELETE FROM item_history;
DELETE FROM items;
DELETE FROM devices;
DELETE FROM events;
DELETE FROM connect_requests;
DELETE FROM nonces;
DELETE FROM auth_failures;
DELETE FROM assertions;
DELETE FROM boxes;
