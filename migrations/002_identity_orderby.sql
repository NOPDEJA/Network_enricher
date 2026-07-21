-- 002_identity_orderby.sql — PHASE 1 of 2: build and populate the replacement
-- identity event tables. This file does NOT swap anything. The swap is a
-- separate file (002b_identity_orderby_swap.sql) that you run only after
-- reading the verification output below with your own eyes.
--
-- WHY
--   identity_radius_events was ORDER BY (mac_token, event_time, session_id,
--   acct_status) — user_token and nas_ip were NOT in the key. event_time is
--   second-resolution, so two real accounting events in the same second for the
--   same session that differ only by user_token (or by NAS) were treated as
--   duplicates and collapsed on merge / under FINAL. Same defect class in
--   identity_dhcp_events, which omitted host_token.
--   These tables are the forensic source of truth, so that is raw evidence loss.
--
-- FORWARD-ONLY — READ THIS BEFORE RUNNING
--   This migration fixes the schema going forward. It does NOT recover anything.
--   Rows that were already collapsed under the old, narrower key are gone: the
--   surviving row is the only copy that exists, and the lost variants cannot be
--   reconstructed from it. There is no backfill and no down-migration that
--   restores them. Expect the post-copy count to EQUAL the pre-copy count.
--
-- ORDER BY is part of a MergeTree table's on-disk layout and cannot be widened
-- with ALTER TABLE, so this is a create-new / copy / swap.
--
-- Note the running enricher CANNOT fix a deployed table by itself: its
-- bootstrap DDL (batchwriter.go, schemaStatements) is CREATE TABLE IF NOT
-- EXISTS, a no-op once the table exists. Fresh installs get the correct key
-- from that DDL; existing boxes need this migration.
--
-- HOW TO RUN
--   Stop the enricher first, or accept that events written between the copy and
--   the swap land in the old table and are lost when it is dropped.
--
--     clickhouse-client --database <db> --queries-file migrations/002_identity_orderby.sql
--
--   Then READ the two count results printed at the end. Continue to
--   002b_identity_orderby_swap.sql ONLY if old and new match in both.

-- ------------------------------------------------------------------
-- identity_dhcp_events: + host_token
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_dhcp_events_new (
    event_time DateTime,
    event_id   UInt16,   -- 10 assign, 11 renew, 12 release
    ip         String,
    mac_token  String,
    host_token String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (ip, event_time, event_id, mac_token, host_token)
TTL event_time + INTERVAL 90 DAY DELETE;

INSERT INTO identity_dhcp_events_new
SELECT event_time, event_id, ip, mac_token, host_token
FROM identity_dhcp_events FINAL;

-- ------------------------------------------------------------------
-- identity_radius_events: + user_token, nas_ip
-- ------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_radius_events_new (
    event_time  DateTime,
    acct_status LowCardinality(String), -- Start, Interim-Update, Stop
    session_id  String,
    user_token  String,
    mac_token   String,
    nas_ip      String
)
ENGINE = ReplacingMergeTree()
PARTITION BY toYYYYMMDD(event_time)
ORDER BY (mac_token, event_time, session_id, acct_status, user_token, nas_ip)
TTL event_time + INTERVAL 90 DAY DELETE;

INSERT INTO identity_radius_events_new
SELECT event_time, acct_status, session_id, user_token, mac_token, nas_ip
FROM identity_radius_events FINAL;

-- ------------------------------------------------------------------
-- MANUAL GATE — this does NOT fail closed.
--
-- These SELECTs only PRINT. Nothing here aborts the migration and nothing
-- downstream is conditional on them: a --queries-file batch has no control
-- flow, so THE OPERATOR IS THE GATE. Read both results before going further.
--
-- In each result the two rows must be EQUAL. If they are not, STOP — do not run
-- 002b. Investigate, then DROP the two _new tables and start over. The original
-- tables are still live and untouched at this point, so a failed copy costs
-- nothing; that is the whole reason the swap lives in a separate file.
--
-- (The source is read with FINAL, so it is already deduped under the OLD key;
-- the new table under the WIDER key can hold the same rows, never fewer. A
-- mismatch means the copy went wrong, NOT that evidence was recovered.)
-- ------------------------------------------------------------------
SELECT 'dhcp_old' AS which, count() FROM identity_dhcp_events FINAL
UNION ALL
SELECT 'dhcp_new', count() FROM identity_dhcp_events_new FINAL;

SELECT 'radius_old' AS which, count() FROM identity_radius_events FINAL
UNION ALL
SELECT 'radius_new', count() FROM identity_radius_events_new FINAL;
