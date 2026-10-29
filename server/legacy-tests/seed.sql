-- A pre-accounts database (schema 0001-0003) with the kind of rows a real single box has. Throwaway test keys only.
INSERT INTO meta (id, recovery_alg, recovery_pubkey, recovery_enc_pubkey, recovery_envelope, admin_pubkey, head_seq, epoch, created_at)
VALUES (1, 'ed25519', 'yveNSL4xKJXKeM46BhJz7ugfaOE_wG0qtI9diFRHO3M', 'RNAVirXbO_DwvMMZ-Aq318rIc4V447vKrYoT2jeKcm4',
        'cmVjb3ZlcnktZW52ZWxvcGU', 'dxnG_VmnHvYsYjHz3eAJQTRKQYjww_W71psCFbguK0M', 3, 2, 1700000000);

INSERT INTO devices (id, name, kind, sig_alg, sig_pubkey, enc_pubkey, envelope, envelope_epoch, created_at, last_seen_at, revoked_at, activates_at) VALUES
  ('legacy-device-0000000001', 'Legacy Mac', 'mac', 'p256',
   'BAPvXd5VvqwOXB6JnSgxTVjmYmakTcBxbidN2He8cMoGZhAAyDEN120qI0AUAbQWGLg21QgD7h0Mt1s_6hoGiBQ',
   'BDTUo3Vvfudwihomnd7CfG3W2XVTov4HkKy2cg5W1BVUYj593JUIjg2FZhak103OeK486g9P7t8CIM2QuEInFpg',
   'ZGV2aWNlLWVudmVsb3Bl', 2, 1700000000, 1700003600, NULL, NULL),
  ('legacy-device-0000000002', 'Old iPhone', 'iphone', 'p256',
   'BAPvXd5VvqwOXB6JnSgxTVjmYmakTcBxbidN2He8cMoGZhAAyDEN120qI0AUAbQWGLg21QgD7h0Mt1s_6hoGiBQ',
   'BDTUo3Vvfudwihomnd7CfG3W2XVTov4HkKy2cg5W1BVUYj593JUIjg2FZhak103OeK486g9P7t8CIM2QuEInFpg',
   '', 1, 1700000100, NULL, 1700000200, NULL);

INSERT INTO items (id, rev, seq, deleted, blob, updated_at) VALUES
  ('legacy-item-00000000001', 2, 3, 0, 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB', 1700000300),
  ('legacy-item-00000000002', 2, 2, 1, 'bWFya2Vy', 1700000200);

INSERT INTO item_history (item_id, rev, kind, blob, deleted, epoch, replaced_at) VALUES
  ('legacy-item-00000000001', 1, 'overwrite', 'b2xkLWJsb2I', 0, 2, 1700000300);

INSERT INTO events (ts, device_id, type, subject_id) VALUES
  (1700000000, 'legacy-device-0000000001', 'bootstrap', 'legacy-device-0000000001'),
  (1700000200, 'legacy-device-0000000001', 'revoke', 'legacy-device-0000000002');
