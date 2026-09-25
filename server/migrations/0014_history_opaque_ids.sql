-- Opt-in history backup: older clients keyed each contact sidecar as
-- "contact:<px_id>" in the clear, so history_blobs held every backup user's
-- contact list in readable form (a social graph the server must never have).
-- Current clients name every blob with an opaque HMAC under a key derived from
-- the user's master seed, and the server now refuses ':' in blob ids.
--
-- Relabel those rows with random ids, so the readable contact list is gone, but
-- KEEP their ciphertext. Restore reads records by content, not by id, so a user
-- whose device can't re-upload first (a lost phone, restoring later) keeps the
-- saved contact names and verification marks. Each updated device re-uploads under
-- its opaque ids and then deletes these relabelled rows (migrateBackupIds).
-- Message rows are left alone - their ids carry no contact identity.
UPDATE history_blobs
   SET blob_id = replace(gen_random_uuid()::text, '-', '')
 WHERE blob_id LIKE 'contact:%';
