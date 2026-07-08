-- KT log scope: the transparency log covers ONLY identity/SPK/Kyber bundle
-- state (operations 'register' and 'spk_rotate'). One-time prekeys are
-- ephemeral, single-use, and NOT part of bundle_hash, so replenishment is
-- deliberately NOT logged. Drop the unused 'opk_replenish' operation so the
-- schema stops advertising a capability the server does not implement.
ALTER TABLE kt_log
    DROP CONSTRAINT IF EXISTS kt_log_operation_check,
    ADD CONSTRAINT kt_log_operation_check
        CHECK (operation IN ('register', 'spk_rotate'));
