# ualforge

Parse Microsoft 365 **Unified Audit Log (UAL)** CSV exports into a single 
SQLite database optimised for digital-forensic and **business-email-compromise
(BEC)** investigations.

Every row of every CSV export is preserved verbatim, the JSON `auditData`
blob is stored both raw (byte-for-byte) and in canonical form, and a wide
set of BEC-relevant fields are promoted into **indexed and normalized**
columns for fast querying.  Re-ingesting the same data is safe: full-row
SHA-256 hashes are used as the deduplication key.

The companion script `bec-triage` consumes this database to produce a BEC triage report.
See the `bec-triage` repo [`here`](https://github.com/ForensicFoundry/bec-triage)

## What's new in v2 (schema_version = 2)

Database `user_version = 2`.  See [Migrating from v1](#migrating-from-v1).

- **Comprehensive promoter** - every field whose name varies across
  Microsoft `RecordType` schemas (`ClientIP` vs `ClientIPAddress` vs
  `IPAddress`; `ApplicationId` vs `AppId`; `UserAgent` top-level vs
  `ExtendedProperties[Name='UserAgent'].Value` vs embedded inside
  `ActorInfoString`) is now resolved through alias chains and per-RecordType
  specialisers.  This closes the gap on `MailItemsAccessed` (RecordType 50)
  events that on v1 would land with NULL `client_ip` / `user_agent` /
  `application_id` despite the data being present in the canonical JSON.
- **Normalized identity columns at ingest:**
  - `client_ip` is port-stripped (IPv4 `1.2.3.4:54321` -> `1.2.3.4`) and
    IPv6-bracket-stripped; the original verbatim value is preserved in
    the new `client_ip_raw` column.
  - `user_principal_name` is lowercased; the original casing is preserved
    in the new `user_principal_name_raw` column.  `bec-triage` v2 no
    longer needs `LOWER(user_principal_name) = LOWER(?)` predicates.
- **Two new structured child tables**, populated at ingest:
  - `mail_items_accessed` - one row per accessed mail item from
    `auditData.Folders[].FolderItems[]` (Microsoft aggregates many reads
    per audit row).  This lets analysts answer "exactly which
    InternetMessageIds did the actor read?" with a normal `SELECT`.
  - `consent_grants` - one row per (event, target app) for OAuth consent
    and service-principal events.  `app_id`, `app_display_name`,
    `consent_type`, `is_admin_consent`, and `permission_scope` are
    first-class indexed columns instead of buried inside
    `ModifiedProperties` JSON.
- **Coverage diagnostic.**  Every ingest / `--reextract` run computes and
  persists the `client_ip` / `user_agent` / `application_id` /
  `user_principal_name` populated-percentage and the per-message /
  consent-grant counts in `ingest_runs.coverage_json`.  `bec-triage`
  surfaces these in its report banner so the analyst knows up-front how
  complete the data is.
- **`--reextract <DB>` subcommand** to re-run the promoter against a
  database in place, without re-reading any source CSV.  This is how you
  upgrade a v1 database to v2 (or refresh promoted columns after a future
  promoter improvement) - every event row is re-derived from the
  canonical JSON that ualforge has always preserved.

---

## Requirements

- Python **3.13+** (uses `from __future__ import annotations` and modern stdlib
  features only - no third-party dependencies)
- SQLite 3.35+ (any modern Linux/macOS/Windows ships this)

## Optional, but suggested
- [`uv`](https://docs.astral.sh/uv/)
  `uv` is my prefered Python package and project manager. I encourage you to 
  consider using it also. Since I use `uv` the installation structions will 
  assume `uv` is used to create and sync the Python venv.

## Installation

```bash
git clone https://github.com/ForensicFoundry/ualforge.git
cd ualforge
uv venv --python 3.13 ./.venv
uv sync
chmod +x ualforge
sed -i "1c#!$(pwd)/.venv/bin/python" ualforge
# no runtime dependencies; nothing else to install
```

## Quick start

```bash
# Ingest all UAL CSVs found anywhere under ./input/ into ./out/ualforge-YYYYMMDD.sqlite
./ualforge -o ./out ./input/

# Same, but also write a ualforge-YYYYMMDD-HHMMSS.log next to the database
./ualforge -o ./out -l ./input/

# Append more CSVs into a pre-existing ualforge database
./ualforge -a ./out/ualforge-20260427.sqlite ./more-input/
```

If you re-run the same input on the same day, rows are deduplicated and the
on-disk database is unchanged for any row already present.

## Usage reference

```
usage: ualforge [-h] [-v] (-o DIR | -a DB | --reextract DB) [-l] [INPUT_DIR]

positional arguments:
  INPUT_DIR             directory to recursively scan for UAL CSV files
                        (required for -o / -a; ignored for --reextract)

options:
  -h, --help            show this help message and exit
  -v, --version         print version and exit

target (mutually exclusive, exactly one required):
  -o, --output DIR      write to <DIR>/ualforge-YYYYMMDD.sqlite (creates DIR if needed;
                        same-day re-runs append to the same file)
  -a, --append DB       append to a pre-existing ualforge database at PATH (must be a
                        valid ualforge database, verified via PRAGMA application_id +
                        ualforge_meta table + user_version)
  --reextract DB        rebuild promoted columns + child tables in place from the
                        preserved auditData JSON, without re-reading any source CSV.
                        Used to upgrade a v1 database to v2, or to refresh promoted
                        values after a future promoter improvement.

logging:
  -l, --log             write a ualforge-YYYYMMDD-HHMMSS.log next to the database
                        capturing all stdout output for the run
```

Exit codes:

- `0` success (even if some rows had JSON parse errors; those are recorded in
  `parse_errors`)
- `1` runtime error (cannot read input, cannot write database, etc.)
- `2` invalid CLI usage / append target failed verification

## Output: database files

`./out/ualforge-YYYYMMDD.sqlite` is a standard SQLite database with WAL mode
enabled.  Open it with:

- the `sqlite3` CLI
- DB Browser for SQLite (`sqlitebrowser`)
- any client that supports SQLite (DBeaver, JetBrains DataGrip, DuckDB, etc.)
- the companion **`bec-triage`** script - See the `bec-triage` repo [`here`](https://github.com/ForensicFoundry/bec-triage)

Same-day re-runs append into the same file; the date in the filename is when
the **first** ingest happened.  Use `-a / --append` to add data to a database
created on a different day.

The database carries an SQLite `application_id` of `0x55414C48` (ASCII `UALH`)
and a `user_version` of `2` (since v2026.05.01; v1 databases can be upgraded
in place via `--reextract`).  These are checked in append mode and by
`bec-triage`.


## Companion script: bec-triage

`bec-triage` consumes the database produced by `ualforge` to generate a
colorised, BEC triage report covering: caveats / methodology,
tooling fingerprints, behavioural anomaly screening (UA-independent
heuristics), candidate compromised UPNs, OAuth application abuse,
source-IP analysis, auth pivots, exfil timeline, persistence (inbox-rule,
transport-rule, and mailbox-permission) indicators, OAuth consent-grant
timeline, per-message exfil deep-dive, and an optional `--per-upn` focused
report.

`bec-triage` v2 expects a v2 database (`PRAGMA user_version == 2`) and
will refuse to run against a v1 database with a clear error pointing at
`--reextract`.

See `bec-triage`'s own README for usage and methodology.

## Companion script: ual-normalize

`ualforge` enforces a strict 13-column header (the canonical Microsoft 365 /
Purview Audit portal export schema).  See the `ual-normalize` repo [`here`](https://github.com/ForensicFoundry/ual-normalize)

UAL evidence in the wild often arrives in **other** shapes:

| Source format | Typical origin | What it looks like |
|---|---|---|
| **Canonical** (13 cols) | Purview portal CSV download / Microsoft Graph audit export converter | `id, createdDateTime, ..., auditData` |
| **PowerShell** (~13 cols) | `Search-UnifiedAuditLog` cmdlet output piped to `Export-Csv` | `RunspaceId, PSComputerName, CreationDate, UserIds, Operations, RecordType, AuditData, ResultIndex, ResultCount, Identity, IsValid, ObjectState` |
| **Splunk re-export** (40+ cols) | Splunk `outputcsv` of an indexed PowerShell UAL feed | PowerShell columns + `_bkt, _cd, _raw, _si, _sourcetype, _time, splunk_server, ...` |
| **AuditData-only** | Custom tooling, third-party SIEM dump | A single `AuditData` column (or that plus arbitrary unrelated columns) |

All of these embed the same per-event JSON in an `AuditData` column, and that
JSON is what `ualforge`'s promoted columns and `bec-triage`'s analytics
actually depend on.  `ual-normalize` reads any of the four shapes, re-projects
each row into the canonical 13 columns (deriving `id`, `createdDateTime`,
`auditLogRecordType`, `operation`, `organizationId`, `userType`, `userId`,
`service`, `objectId`, `userPrincipalName`, and `clientIp` from the JSON when
the surrounding columns are missing or differently named), and writes a clean
CSV that `ualforge` accepts unchanged.

## Example queries

Following are some example queries executed by `bec-triage`.

```sql
-- All FileDownloaded events for a UPN, sorted by time
SELECT created_at_utc, client_ip, user_agent, object_id
FROM events
WHERE user_principal_name = 'user@example.com'
  AND operation = 'FileDownloaded'
ORDER BY created_at_utc;

-- Top user agents by event count
SELECT user_agent, COUNT(*) AS hits
FROM events
WHERE user_agent IS NOT NULL
GROUP BY user_agent ORDER BY hits DESC LIMIT 20;

-- Inbox rule changes per UPN per day
SELECT user_principal_name,
       substr(created_at_utc, 1, 10) AS day,
       operation,
       COUNT(*) AS hits
FROM events
WHERE operation IN ('New-InboxRule','Set-InboxRule','Remove-InboxRule')
GROUP BY user_principal_name, day, operation
ORDER BY day, hits DESC;

-- Drill into the raw rule contents
SELECT created_at_utc, user_principal_name, operation,
       json_extract(audit_data_canonical, '$.Parameters')
FROM events
WHERE operation IN ('New-InboxRule','Set-InboxRule')
ORDER BY created_at_utc DESC LIMIT 50;

-- Verify provenance for a specific row
SELECT source_file, source_line, export_batch, ingested_at, parse_error
FROM events
WHERE id = '...the GUID from the original CSV...';

-- Audit the ingest run history
SELECT run_id, started_at, ended_at,
       files_processed, rows_inserted, rows_duplicate, rows_with_errors, status
FROM ingest_runs ORDER BY run_id;
```
## Further information

For additional, and more in-depth information, please read the `MANUAL.md`.

## License

GPL-3.0-or-later