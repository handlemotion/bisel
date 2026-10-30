-- Per-box storage quota. MAX_ITEMS_PER_BOX bounds the row count, but a row is up to 256 KiB, so 5,000 rows are over a gigabyte:
-- with open sign-up one account could fill the shared database. `stored_bytes` is the size of the box's item blobs in characters
-- (the blobs are base64url text), kept by triggers like `item_count`; PUT refuses a write that would take the box past MAX_BOX_BYTES.
ALTER TABLE boxes ADD COLUMN stored_bytes INTEGER NOT NULL DEFAULT 0;

UPDATE boxes SET stored_bytes = COALESCE((SELECT SUM(length(blob)) FROM items WHERE items.box_id = boxes.id), 0);

CREATE TRIGGER items_bytes_insert AFTER INSERT ON items
BEGIN
  UPDATE boxes SET stored_bytes = stored_bytes + length(NEW.blob) WHERE id = NEW.box_id;
END;

CREATE TRIGGER items_bytes_update AFTER UPDATE OF blob ON items
BEGIN
  UPDATE boxes SET stored_bytes = stored_bytes + length(NEW.blob) - length(OLD.blob) WHERE id = NEW.box_id;
END;

CREATE TRIGGER items_bytes_delete AFTER DELETE ON items
BEGIN
  UPDATE boxes SET stored_bytes = stored_bytes - length(OLD.blob) WHERE id = OLD.box_id;
END;
