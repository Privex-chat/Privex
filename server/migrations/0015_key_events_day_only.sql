-- Keep only the DAY of key events. The key directory and the KT log stored the
-- exact second of every registration, signed-prekey rotation, recovery and "log
-- out everywhere" - a record of when an account was created or recovered and,
-- since rotations run as the device connects, of when its device was online.
-- Nothing needs more than the day.
--
-- Enforced HERE, at the shared write boundary, rather than in app code: every
-- writer stores only the day from the moment this runs - any server version
-- (including the old binary still serving while a deploy runs), the KT repair
-- after an unclean shutdown, and any future code path.

CREATE FUNCTION kt_log_day_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.timestamp := NEW.timestamp - (NEW.timestamp % 86400);
    RETURN NEW;
END
$$;

CREATE TRIGGER kt_log_day_only
    BEFORE INSERT OR UPDATE OF timestamp ON kt_log
    FOR EACH ROW EXECUTE FUNCTION kt_log_day_only();

CREATE FUNCTION key_directory_day_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.created_at     := NEW.created_at     - (NEW.created_at     % 86400);
    NEW.spk_created_at := NEW.spk_created_at - (NEW.spk_created_at % 86400);
    RETURN NEW;
END
$$;

CREATE TRIGGER key_directory_day_only
    BEFORE INSERT OR UPDATE OF created_at, spk_created_at ON key_directory
    FOR EACH ROW EXECUTE FUNCTION key_directory_day_only();

-- Round what was stored before, once. key_directory's times aren't hashed or
-- served. kt_log's time is inside each leaf hash, so this rewrites the log's
-- history and root once. That's safe now: clients pin no roots (each proof is
-- checked against the root signed with it), roots aren't yet published anywhere
-- outside, and prev_hash chains bundle hashes, not times. A server process
-- already running keeps serving proofs from its in-memory tree until it's
-- replaced - self-consistent, and only times it was already serving; a process
-- started after this builds its tree from the rounded rows. Irreversible by
-- design: the exact seconds are gone.
UPDATE key_directory
   SET created_at     = created_at     - (created_at     % 86400),
       spk_created_at = spk_created_at - (spk_created_at % 86400)
 WHERE created_at % 86400 <> 0 OR spk_created_at % 86400 <> 0;

UPDATE kt_log
   SET timestamp = timestamp - (timestamp % 86400)
 WHERE timestamp % 86400 <> 0;
