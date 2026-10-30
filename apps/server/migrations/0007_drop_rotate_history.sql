-- A rotation used to keep each item's previous wrapped item key (kind 'rotate') for the retention period. The item payload and
-- its key are unchanged by a rotation, so those rows let a holder of the old vault key (a revoked device) plus a copy of the
-- database open items it never synced. Nothing reads them and the rotation no longer writes them.
DELETE FROM item_history WHERE kind = 'rotate';
