-- 002b_identity_orderby_swap.sql — PHASE 2 of 2: swap the replacement identity
-- tables into place.
--
-- DO NOT RUN THIS until 002_identity_orderby.sql has completed AND you have
-- read its two count results and confirmed old == new in both. This file is
-- separate precisely so the swap cannot execute in the same batch as the copy:
-- the verification in 002 only prints, so nothing but you stops a bad copy from
-- being promoted.
--
--     clickhouse-client --database <db> --queries-file migrations/002b_identity_orderby_swap.sql
--
-- WHY EXCHANGE AND NOT RENAME
--   `RENAME TABLE a TO b, c TO d` is NOT atomic across the pairs and can
--   partially execute. A failure partway through would leave a table absent
--   entirely and `cmd/trace -who` failing outright — the worst outcome here,
--   because the forensic tool is exactly what someone reaches for under time
--   pressure. `EXCHANGE TABLES a AND b` is atomic for its pair, so each
--   statement below either fully happens or does not happen at all, and neither
--   table name is ever missing at any instant.
--
--   Requires the Atomic database engine (the default since ClickHouse 20.10;
--   `SELECT engine FROM system.databases WHERE name = currentDatabase()` to
--   confirm). On a non-Atomic database EXCHANGE is unavailable — in that case
--   do the two renames ONE PAIR AT A TIME, checking between them, and see the
--   recovery note below.
--
-- PARTIAL-FAILURE RECOVERY
--   The two statements are individually atomic but are not atomic together. If
--   the first succeeds and the second fails, the database is left with DHCP
--   migrated and RADIUS not. That state is CONSISTENT and queryable — both
--   table names exist and hold correct data — it is merely half-migrated. To
--   recover, simply re-run this file: EXCHANGE is idempotent in the sense that
--   re-running the already-swapped pair would swap it BACK, so instead run only
--   the statement that did not complete. Verify which is which with:
--
--     SELECT name, sorting_key FROM system.tables
--     WHERE name IN ('identity_dhcp_events', 'identity_radius_events');
--
--   The migrated table's sorting_key ends in host_token (dhcp) or nas_ip
--   (radius). Run only the EXCHANGE for the table whose key is still short.

-- After each EXCHANGE, the live name holds the NEW (correctly-keyed) data and
-- the _new name holds the PRE-MIGRATION rows — i.e. _new becomes the rollback
-- copy. Roll back a pair by running its EXCHANGE again.
EXCHANGE TABLES identity_dhcp_events AND identity_dhcp_events_new;

EXCHANGE TABLES identity_radius_events AND identity_radius_events_new;

-- ------------------------------------------------------------------
-- Confirm the live tables now carry the full-row keys. dhcp must end in
-- host_token; radius must end in user_token, nas_ip.
-- ------------------------------------------------------------------
SELECT name, sorting_key
FROM system.tables
WHERE database = currentDatabase()
  AND name IN ('identity_dhcp_events', 'identity_radius_events');

-- ------------------------------------------------------------------
-- Drop the rollback copies only after the swapped tables have been sanity-
-- checked against live queries (`cmd/trace -who` over a known-good window).
-- Uncomment deliberately — this is the point of no return.
-- ------------------------------------------------------------------
-- DROP TABLE identity_dhcp_events_new;
-- DROP TABLE identity_radius_events_new;
