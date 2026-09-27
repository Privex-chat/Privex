-- Keep only the DAY of key events (key_event_day in src/lib.rs). New writes are
-- rounded as they're stored; this rounds what was stored before, once. Exact
-- seconds recorded when an account registered or was recovered, and when its
-- device was online (rotations run as the device connects). Nothing needs more
-- than the day.
--
-- key_directory: these times aren't hashed or served, so nothing else changes.
--
-- kt_log: each entry's time is inside its leaf hash, so this rewrites the log's
-- history and its root, once. That's safe now: clients pin no roots - each proof
-- is checked against the freshly signed root, and leaves are rebuilt from these
-- values on server start - and roots aren't yet published anywhere outside that
-- could disagree. (The log is UNLOGGED and is rebuilt from key_directory after
-- any unclean shutdown anyway.) prev_hash chains bundle hashes, not times.
--
-- Irreversible by design: the exact seconds are gone.

UPDATE key_directory
   SET created_at     = created_at     - (created_at     % 86400),
       spk_created_at = spk_created_at - (spk_created_at % 86400)
 WHERE created_at % 86400 <> 0
    OR spk_created_at % 86400 <> 0;

UPDATE kt_log
   SET timestamp = timestamp - (timestamp % 86400)
 WHERE timestamp % 86400 <> 0;
