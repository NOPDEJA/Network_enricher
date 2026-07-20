-- 002_identity_orderby.sql — widen the identity event tables' ORDER BY to the
-- full row, so ReplacingMergeTree stops collapsing genuinely distinct events.
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
--   restores them. Expect the post-migration count to EQUAL the pre-migration
--   count — the verification below asserts exactly that, and a mismatch means
--   something went wrong in the copy, not that data was recovered.
--
-- ORDER BY is part of a MergeTree table's on-disk layout and cannot be widened
-- with ALTER TABLE, so this is a create-new / copy / RENAME swap.
--
-- HOW TO RUN (writers should be stopped, or accept that events written between
-- the INSERT and the RENAME land in the old table and are dropped with it):
--   clickhouse-client --database <db> --queries-file migrations/002_identity_orderby.sql
-- Run the verification SELECTs and confirm the counts match BEFORE the final
-- DROPs at the bottom, which are commented out on purpose.

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
-- Verify BEFORE the swap. Both rows of each result must be equal.
-- (The source is read with FINAL, so it is already deduped under the OLD key;
-- the new table under the WIDER key can only hold the same rows or more.)
-- ------------------------------------------------------------------
SELECT 'dhcp_old' AS which, count() FROM identity_dhcp_events FINAL
UNION ALL
SELECT 'dhcp_new', count() FROM identity_dhcp_events_new FINAL;

SELECT 'radius_old' AS which, count() FROM identity_radius_events FINAL
UNION ALL
SELECT 'radius_new', count() FROM identity_radius_events_new FINAL;

-- ------------------------------------------------------------------
-- Atomic swap.
-- ------------------------------------------------------------------
RENAME TABLE
    identity_dhcp_events       TO identity_dhcp_events_old,
    identity_dhcp_events_new   TO identity_dhcp_events,
    identity_radius_events     TO identity_radius_events_old,
    identity_radius_events_new TO identity_radius_events;

-- ------------------------------------------------------------------
-- Drop the originals only after the swapped tables have been sanity-checked
-- against live queries (cmd/trace -who). Uncomment deliberately.
-- ------------------------------------------------------------------
-- DROP TABLE identity_dhcp_events_old;
-- DROP TABLE identity_radius_events_old;
