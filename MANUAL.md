# ualforge

Parse Microsoft 365 **Unified Audit Log (UAL)** CSV exports into a single
SQLite database optimised for digital-forensic and **business-email-compromise
(BEC)** investigations.

Every row of every CSV export is preserved verbatim, the JSON `auditData`
blob is stored both raw (byte-for-byte) and in canonical form, and a wide
set of BEC-relevant fields are promoted into **indexed and normalized**
columns for fast querying.  Re-ingesting the same data is safe: full-row
SHA-256 hashes are used as the deduplication key.

The companion script [`bec-triage`](#companion-script-bec-triage) consumes
this database to produce a BEC triage report. See the `bec-triage` repo [`here`](https://github.com/ForensicFoundry/bec-triage)

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [CLI reference](#cli-reference)
- [Output: database files](#output-database-files)
- [Database schema](#database-schema)
  - [`events` (the table you query)](#events-the-table-you-query)
  - [`mail_items_accessed` (v2)](#mail_items_accessed-v2)
  - [`consent_grants` (v2)](#consent_grants-v2)
  - [`ualforge_meta`](#ualforge_meta)
  - [`ingest_runs`](#ingest_runs)
  - [`ingest_files`](#ingest_files)
  - [`parse_errors`](#parse_errors)
  - [Indexes](#indexes)
- [`--reextract`: in-place promoter refresh](#--reextract-in-place-promoter-refresh)
- [Migrating from v1](#migrating-from-v1)
- [Coverage diagnostic](#coverage-diagnostic)
- [Methodology](#methodology)
  - [File discovery (Plan A -> Plan B)](#file-discovery-plan-a--plan-b)
  - [Header validation](#header-validation)
  - [Timestamp normalisation](#timestamp-normalisation)
  - [JSON canonicalisation](#json-canonicalisation)
  - [Promoted columns (38 of them)](#promoted-columns-38-of-them)
  - [Deduplication (SHA-256 row hash)](#deduplication-sha-256-row-hash)
  - [Provenance (per-row, per-file, per-run)](#provenance-per-row-per-file-per-run)
  - [Append mode](#append-mode)
  - [Error handling (parse errors are still ingested)](#error-handling-parse-errors-are-still-ingested)
- [Caveats and known limitations](#caveats-and-known-limitations)
- [Companion script: bec-triage](#companion-script-bec-triage)
- [Companion script: ual-normalize](#companion-script-ual-normalize)
- [Example queries](#example-queries)

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
on-disk database is unchanged for any row already present (see
[Deduplication](#deduplication-sha-256-row-hash)).

## CLI reference

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

## Database schema

### `events` (the table you query)

The main table, ~70 columns.  Every CSV row produces exactly one event row.

| Group | Columns | Notes |
|---|---|---|
| **Provenance** | `row_hash` (PK), `source_file`, `source_line`, `export_batch`, `ingested_at`, `ingest_run_id`, `parse_error` | `row_hash` is the SHA-256 dedup key.  `source_file` is the path relative to `INPUT_DIR`.  `export_batch` is the export-run folder name (e.g. `20260417-222228`). |
| **CSV columns (verbatim)** | `id`, `created_at_raw`, `created_at_utc`, `audit_log_record_type`, `operation`, `organization_id`, `user_type`, `user_id`, `service`, `object_id`, `user_principal_name`, `user_principal_name_raw` (v2), `client_ip_csv`, `administrative_units` | Exact M365 UAL column names, snake-cased.  `created_at_utc` is normalised (see below); `created_at_raw` is the original string.  In v2 `user_principal_name` is **lowercased** for join correctness; the original casing is preserved verbatim in `user_principal_name_raw`. |
| **Raw + canonical JSON** | `audit_data_raw`, `audit_data_canonical` | `_raw` is byte-for-byte; `_canonical` is `json.dumps(json.loads(raw), sort_keys=True, separators=(",",":"))` for deterministic hashing and clean `json_extract()`. |
| **Promoted (universal)** | `workload`, `client_ip`, `client_ip_raw` (v2), `user_agent`, `geo_location`, `event_source`, `result_status`, `result_status_detail` (v2), `correlation_id`, `application_id`, `user_key`, `record_type_int` | Pulled from the JSON for indexing.  In v2 `client_ip` is **port-stripped and IPv6-bracket-stripped** (so `1.2.3.4:54321` and `[2603:10a6:610:254::16]:51112` both store as just the address); the original verbatim value is preserved in `client_ip_raw`.  `user_agent` is now resolved from `UserAgent`, `ExtendedProperties[Name='UserAgent']`, **and** `ActorInfoString` -- closing the gap on `MailItemsAccessed` events that previously had a NULL UA.  `application_id` falls back through `AppId` and `ClientAppId`. |
| **Promoted (Mail / Exchange)** | `mailbox_owner_upn`, `mailbox_guid`, `logon_type`, `client_info_string`, `internet_message_id`, `item_subject`, `item_parent_folder_path`, `mail_item_count` (v2) | Surfaces mail-related TTPs (BEC core).  `mail_item_count` is `auditData.OperationCount` for `MailItemsAccessed` rows -- the number of items aggregated into that single audit row (see [`mail_items_accessed`](#mail_items_accessed-v2) for the unrolled per-item view). |
| **Promoted (Auth / sign-in)** | `session_id`, `logon_user_sid`, `authentication_type`, `request_type` (v2), `user_authentication_method` (v2), `device_properties` (raw JSON), `extended_properties` (v2; canonical JSON), `actor_ip_address` | For tracing token acquisition / replay.  `request_type` and `user_authentication_method` are pulled from `ExtendedProperties` for AAD STS-logon events (MFA factor, OAuth flow type). |
| **Promoted (Inbox/transport rule changes)** | `modified_properties`, `parameters`, `operation_properties` | Stored as JSON text; query via `json_extract()`. |
| **Promoted (Azure AD)** | `actor_upn`, `target_upn` | Flattened from `Actor[].ID` and `Target[].ID` arrays.  Lowercased in v2. |
| **Promoted (SharePoint / OneDrive)** | `site`, `web_id`, `list_id`, `list_item_unique_id`, `source_file_name`, `source_relative_url`, `item_type` | For exfil reconstruction. |
| **Promoted (Client app fingerprint)** | `client_app_id`, `client_app_name`, `browser_name`, `browser_version`, `platform`, `is_managed_device`, `device_display_name` | Useful for attribution and OAuth-app misuse detection. |

If `auditData` JSON failed to parse, every promoted column is `NULL` and
`parse_error` carries a one-line description.  The row is still inserted
(see [Error handling](#error-handling-parse-errors-are-still-ingested)).

### `mail_items_accessed` (v2)

```sql
CREATE TABLE mail_items_accessed (
    mia_id                INTEGER PRIMARY KEY AUTOINCREMENT,
    event_row_hash        TEXT NOT NULL REFERENCES events(row_hash) ON DELETE CASCADE,
    event_id              TEXT,
    ingest_run_id         INTEGER,

    -- denormalized from the parent event for fast filtering
    user_principal_name   TEXT,    -- lowercased
    client_ip             TEXT,    -- port + IPv6-brackets stripped
    created_at_utc        TEXT,
    operation             TEXT,
    mailbox_owner_upn     TEXT,

    -- per-item fields from auditData.Folders[].FolderItems[]
    folder_id             TEXT,
    folder_path           TEXT,
    item_internal_id      TEXT,
    internet_message_id   TEXT,
    subject               TEXT,
    size_in_bytes         INTEGER,
    client_request_id     TEXT,
    immutable_id          TEXT
);
```

A single `MailItemsAccessed` (RecordType 50) audit row aggregates many
mail accesses inside `auditData.Folders[].FolderItems[]`.  This child
table unrolls those into one row per individual message accessed, so the
analyst can pivot directly on `internet_message_id` / `subject` /
`folder_path` and answer questions that on v1 required custom SQL against
`audit_data_canonical`:

- "Which specific InternetMessageIds did the threat actor read?"
- "How many distinct messages did each candidate-compromised UPN access?"
- "Are there messages that were accessed from multiple IPs (token replay)?"
- "Which folders were targeted, in what order?"

A NULL-safe unique index on
`(event_row_hash, COALESCE(folder_id,''), COALESCE(item_internal_id, internet_message_id, ''))`
makes `INSERT OR IGNORE` correctly idempotent across re-ingests of the
same source CSV (a real-world scenario when M365's paged exports
overlap).

### `consent_grants` (v2)

```sql
CREATE TABLE consent_grants (
    cg_id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    event_row_hash        TEXT NOT NULL REFERENCES events(row_hash) ON DELETE CASCADE,
    event_id              TEXT,
    ingest_run_id         INTEGER,

    -- denormalized from parent event
    user_principal_name   TEXT,
    client_ip             TEXT,
    created_at_utc        TEXT,
    operation             TEXT,

    -- target app being granted access
    app_id                TEXT,
    app_display_name      TEXT,

    -- consent details
    consent_type          TEXT,    -- 'Principal' / 'AllPrincipals' / 'AdminConsent'
    is_admin_consent      INTEGER, -- 0 / 1 / NULL
    permission_scope      TEXT,    -- '; '-joined permission strings
    granted_to_id         TEXT,
    granted_to_name       TEXT
);
```

One row per (event, target app) for the AAD audit operations through
which an actor typically establishes an OAuth-token foothold:

```
Consent to application.
Add OAuth2PermissionGrant.
Add delegated permission grant.
Add app role assignment grant to user.
Add app role assignment to service principal.
Add service principal.
Add service principal credentials.
Update application - Certificates and secrets management
```

`app_id`, `app_display_name`, `consent_type`, `is_admin_consent`, and
`permission_scope` are first-class indexed columns instead of buried
inside a stringified `ModifiedProperties` array, so `bec-triage`'s
consent-timeline section (Section 14) and any analyst-written SQL can
just `SELECT` from this table directly.

### `ualforge_meta`

```sql
CREATE TABLE ualforge_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

Holds `app=ualforge`, `created_by_version`, `schema_version`, `created_at`.
Used by `bec-triage` and by `--append` to verify the file is a real ualforge
database before writing.

### `ingest_runs`

One row per `ualforge` invocation.  Tracks start/end timestamps, version,
input dir, output `mode` (`create|append (same-day)|append (explicit)|reextract`),
files processed, rows inserted / duplicate / errored, child-table emit
counts (`mia_rows_emitted`, `consent_rows_emitted`), the
[coverage diagnostic](#coverage-diagnostic) (as `coverage_json`), and final
status.

### `ingest_files`

One row per CSV file ingested.  Tracks `path` (relative), `sha256` (file
content), `mtime`, byte size, row counts (read/inserted/duplicate/errors),
and links to `ingest_runs(run_id)`.  Re-ingesting the same file (same sha256)
is detected and skipped per-file inside a run.

### `parse_errors`

One row for every CSV row that could not be parsed cleanly (bad JSON, malformed
CSV cell, etc.).  Stores the run id, source file, source line, and the error
message.  Cross-reference with the `events.row_hash` of the same row (the row
is still inserted with `parse_error` populated).

### Indexes

Indexed columns on `events` include: `id`, `created_at_utc`,
`user_principal_name`, `user_id`, `operation`, `audit_log_record_type`,
`record_type_int` (v2), `service`, `client_ip`, `correlation_id`,
`internet_message_id`, `mailbox_owner_upn`, `session_id`, `application_id`,
`actor_upn`, `target_upn`, `export_batch`, `source_file`, plus composite
`(user_principal_name, created_at_utc)` for timeline queries and (v2)
`(user_principal_name, operation)` for op-mix queries.

`mail_items_accessed` is indexed on `event_row_hash`, `user_principal_name`,
`internet_message_id`, `subject`, and `created_at_utc`, with a NULL-safe
unique index for dedup.  `consent_grants` is indexed on `event_row_hash`,
`user_principal_name`, `app_id`, and `created_at_utc`, with a NULL-safe
unique index on `(event_row_hash, COALESCE(app_id, app_display_name, ''))`.

## `--reextract`: in-place promoter refresh

```bash
./ualforge --reextract /path/to/ualforge-YYYYMMDD.sqlite
```

Walks every event row, re-runs `extract_promoted()` against the canonical
JSON that ualforge has always preserved in `audit_data_canonical`, and
rebuilds the `mail_items_accessed` and `consent_grants` child tables from
scratch.  No source CSV is re-read.

Use cases:

- **Upgrade a v1 database to v2** - `ALTER TABLE events ADD COLUMN ...`
  for the new columns happens automatically; child tables are created
  fresh and populated.  After a successful run, `PRAGMA user_version`
  is `2` and `bec-triage` is happy to run against the database.
- **Refresh promoted columns after a future promoter improvement** -
  same script, same database, takes minutes (vs hours to re-ingest from
  a multi-GB CSV tree).
- **Diagnose a coverage regression** - re-extracting on a known-good
  database should never lower coverage; if it does, the promoter has
  regressed.

Performance notes (the implementation is tuned for big DBs):

- Two SQLite connections (read + write) so the cursor and the writer
  don't contend for page-cache.
- One `BEGIN IMMEDIATE ... COMMIT` around the whole rebuild + temporary
  `PRAGMA synchronous = OFF` for the duration (safe -- a crash rolls back
  the entire transaction; the original database is untouched).
- Secondary child-table indexes are dropped and rebuilt at the end.
  The two NULL-safe **unique** indexes (`uq_mia_event_item`,
  `uq_cg_event_app`) are intentionally **kept** during the bulk insert,
  because they are the dedup mechanism that lets `INSERT OR IGNORE`
  collapse near-duplicate rows Microsoft emits when the same item appears
  in multiple folders or the same event is paged across export files.

Real-world throughput: a 9 GB / 965 k-event database completes in ~9
minutes on a workstation, producing ~2 M `mail_items_accessed` rows.

## Migrating from v1

`bec-triage` v2 enforces `PRAGMA user_version = 2` at startup and refuses
to run against a v1 database.  You have two choices:

```bash
# Option 1 (recommended for big cases): re-extract in place
./ualforge --reextract ./out/ualforge-20260427.sqlite

# Option 2 (for fresh cases or when you want the cleanest dedup):
# delete the v1 DB and re-ingest from the source CSVs
rm ./out/ualforge-20260427.sqlite*
./ualforge -o ./out ./input
```

Either path produces an identical v2 database.  `--reextract` uses the
canonical JSON stored in `audit_data_canonical` -- which has been part
of the schema since v1 -- so no data is lost or invented along the way.

## Coverage diagnostic

At the end of every ingest / `--reextract` run, ualforge computes:

| Metric | Why it matters |
|---|---|
| `events_total` | sanity-check the row count against your CSV totals |
| `client_ip_pct` | how often the actor's source IP could be promoted; >90% is healthy on most modern tenants, lower indicates a tenant-logging gap |
| `user_agent_pct` | proportion of events with an extractable UA; lower than `client_ip_pct` is normal -- service-token / app-only events legitimately have no browser UA |
| `application_id_pct` | proportion of events with an extractable AppId |
| `user_principal_name_pct` | proportion of events with a UPN; low means lots of system-driven activity (admin operations, audit-pump events) which is fine |
| `mia_events`, `mia_rows`, `mia_avg_items` | how many `MailItemsAccessed` events ingested and how many per-message rows they produced |
| `consent_events`, `consent_rows` | how many consent / SP-grant events ingested and how many `consent_grants` rows they produced |

The numbers are echoed at the end of the run, persisted in
`ingest_runs.coverage_json`, and surfaced by `bec-triage`'s report banner.

## Methodology

### File discovery (Plan A -> Plan B)

`ualforge` walks `INPUT_DIR` recursively and applies two strategies in order:

- **Plan A** (preferred): files matching the regex
  `.*UnifiedAuditLog.*part\d+\.csv$`.  This is the canonical filename pattern
  produced by Get-UnifiedAuditLog / the M365 Compliance portal.
- **Plan B** (fallback): any other `*.csv` file is opened and its header is
  validated against the [exact 13-column UAL header](#header-validation).
  Files that match are ingested; files that don't are silently skipped.

This means you can point `ualforge` at a messy export directory containing
report PDFs, README.txt, screenshots, etc. and only the actual UAL CSVs will
be ingested.

### Header validation

Plan A and Plan B both require the CSV header to be **exactly**:

```
id, createdDateTime, auditLogRecordType, operation, organizationId, userType,
userId, service, objectId, userPrincipalName, clientIp, administrativeUnits,
auditData
```

(in that order, BOM-tolerant).  Anything else is rejected with a logged warning.

> **Got a non-canonical export?**  Legacy exports from the PowerShell
> `Search-UnifiedAuditLog` cmdlet, Splunk re-exports of that PowerShell output,
> and raw `AuditData`-only dumps all use a different surrounding column set
> and will be rejected here.  Run them through the
> [`ual-normalize`](#companion-script-ual-normalize) companion script first;
> it auto-detects the source format and emits canonical CSVs that this
> validator accepts.

### Timestamp normalisation

Microsoft's `createdDateTime` is parsed (multiple formats accepted, including
`M/D/YYYY h:mm:ss AM/PM`) and stored twice:

- `created_at_raw`: original string verbatim
- `created_at_utc`: ISO-8601 with explicit `+00:00` UTC suffix (e.g.
  `2026-04-11T09:28:45+00:00`)

`bec-triage` and all examples in this README use `created_at_utc`.

### JSON canonicalisation

The `auditData` JSON blob is parsed once and re-serialised with
`sort_keys=True, separators=(",", ":")` into `audit_data_canonical`.  This:

1. Makes the dedup hash stable regardless of Microsoft's whitespace/key-order
   variations.
2. Makes `json_extract(audit_data_canonical, '$.GeoLocation')` etc. robust.

The original bytes are preserved in `audit_data_raw`.

### Promoted columns (38 of them)

Rather than force every query to use `json_extract()`, BEC-critical fields
are pulled out at ingest time and stored in indexed columns.  See the
[`events` schema table](#events-the-table-you-query) for the full list.
Promotion is best-effort: missing keys produce NULL, never errors.

### Deduplication (SHA-256 row hash)

The primary key is `row_hash`, defined as:

```
SHA-256(
  id || createdDateTime || auditLogRecordType || operation ||
  organizationId || userType || userId || service || objectId ||
  userPrincipalName || clientIp || administrativeUnits ||
  audit_data_canonical
)
```

(NUL-separated.)  Inserts use `INSERT OR IGNORE`, so re-ingesting the same
data is a no-op at the row level.  The `id` GUID alone is **not** unique
(Microsoft can re-emit a row with a corrected `clientIp`, for example), which
is why we hash the full row.

### Provenance (per-row, per-file, per-run)

Every event row carries:

- `source_file` - path relative to `INPUT_DIR` (e.g.
  `UnifiedAuditLog/20260301/tenant90DayUal_user@example.com-UnifiedAuditLog-part12.csv`)
- `source_line` - 1-based line number inside that CSV
- `export_batch` - the immediate parent folder of the CSV (typically the
  Microsoft export run timestamp like `20260301-111118`)
- `ingested_at` - UTC ISO-8601 of the insert
- `ingest_run_id` - FK to `ingest_runs`

Plus per-file in `ingest_files` (path, sha256, mtime, size, counts) and
per-run in `ingest_runs` (start/end, totals, status).  This is enough to
fully reconstruct what was ingested when, from where, by which version of
the script.

### Append mode

`-a / --append <DB>` requires `<DB>` to:

1. Exist and open as a SQLite database
2. Have `PRAGMA application_id == 0x55414C48` (`UALH`)
3. Contain a `ualforge_meta` table with `app == 'ualforge'`

If any check fails, ualforge aborts with exit code 2 - it will **not**
overwrite or "convert" a foreign SQLite file.  Append also requires
`PRAGMA user_version == SCHEMA_VERSION` (currently `2`); a v1 database
must be upgraded first via [`--reextract`](#--reextract-in-place-promoter-refresh).

### Error handling (parse errors are still ingested)

Rows whose `auditData` cannot be parsed as JSON are **still inserted** into
`events` with:

- All 13 CSV columns intact
- `audit_data_raw` populated (the bytes Microsoft sent)
- `audit_data_canonical` set to NULL
- All 38 promoted columns set to NULL
- `parse_error` populated with a one-line error description

Plus a row in `parse_errors` for the audit trail.

This means a single bad row never aborts the file or the run, and you never
lose data - you can still query and audit problem rows.

## Caveats and known limitations

- **Schema is single-tenant in spirit.** Nothing prevents you from ingesting
  multiple tenants' data into one DB; just be aware that grouping queries
  (and `bec-triage`) will conflate them unless you filter by
  `organization_id`.
- **`client_ip` is normalized at ingest in v2.**  Microsoft emits some IPv4
  inbox-rule and IPv6 sign-in events with `:port` suffixes (and IPv6
  addresses in `[brackets]`).  v2 strips the port and brackets at ingest
  time and stores the normalized address in `client_ip`; the original
  verbatim value is preserved in `client_ip_raw` for forensic fidelity.
  If you upgrade an older database with `--reextract`, the normalization
  happens then.
- **`geo_location`** in `audit_data_canonical` is Microsoft's tenant region
  code (`NAM`, `EUR`, `GBR`, `APC`, ...), **not** the actor's geographic
  location.  For real geolocation, enrich `client_ip` with an external geo-IP
  data source.
- **No automatic compression / archiving.**  WAL files can be large during
  long ingests; `ualforge` checkpoints at the end of each run.
- **Single-process.**  No concurrent appends; SQLite locks the file.
- **No rotation of old `ingest_runs` / `parse_errors`.**  These accumulate;
  prune manually if needed.

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
[`--reextract`](#--reextract-in-place-promoter-refresh).

See `bec-triage`'s own README for usage and methodology.

## Companion script: ual-normalize

`ualforge` enforces a strict 13-column header (the canonical Microsoft 365 /
Purview Audit portal export schema). See the `ual-normalize` repo [`here`](https://github.com/ForensicFoundry/ual-normalize)

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

### Quick start

```bash
# Single file
./ual-normalize ./o365_dataset/auditrecords.csv -O ./normalized

# Whole directory tree (mirrors layout under -O)
./ual-normalize ./incoming-ual -O ./normalized -l

# Then ingest the normalized output as if it were a native UAL portal export
./ualforge -o ./out ./normalized
```

### CLI

```
ual-normalize [-h] [-v] [-l] [-O DIR] [-f] INPUT

positional:
  INPUT             CSV file or directory to recursively normalize

options:
  -O, --out-dir DIR destination directory for normalized CSVs (default: ./normalized)
  -f, --force       overwrite existing normalized output files
  -l, --log         write a ualforge-yyyymmdd-hhmmss.log next to OUT_DIR
  -v, --version     show version and exit
```

### How it works

1. **Auto-detection.** Reads the header of each `*.csv` and classifies it as
   `canonical`, `powershell`, `splunk`, `auditdata`, or `unknown` based on the
   set of column names present (case-insensitive).  Anything without an
   `AuditData` column is rejected (the source format truly is incompatible);
   everything else is convertible.
2. **Canonical-format pass-through.** Files already in the canonical 13-column
   shape are streamed through unchanged (just renamed to
   `*.normalized.csv`) so a directory mix of formats can be normalized in one
   shot.
3. **JSON-driven re-projection.** For non-canonical inputs, every row is
   rewritten by parsing its `AuditData` JSON and pulling out:
   - `Id` -> `id`
   - `CreationTime` -> `createdDateTime`
   - `RecordType` -> `auditLogRecordType` (well-known integers are mapped to
     names, e.g. `1` -> `ExchangeAdmin`, `15` -> `AzureActiveDirectoryStsLogon`,
     `8` -> `AzureActiveDirectory`; unknown integers pass through as strings)
   - `Operation` -> `operation`
   - `OrganizationId` -> `organizationId`
   - `UserType` -> `userType` (also int->name where known: `2` -> `Admin`,
     `3` -> `DcAdmin`, etc.)
   - `UserId` -> `userId`, and copied to `userPrincipalName` when it actually
     looks like a UPN (`MailboxOwnerUPN` is consulted as a fallback)
   - `Workload` -> `service`
   - `ObjectId` -> `objectId`
   - `ClientIP` -> `clientIp` (with `ClientIPAddress` and `ActorIpAddress` as
     fallbacks)
   - `administrativeUnits` is left blank (older shapes don't carry it; this is
     fine - `ualforge`'s queries don't depend on it)
   - The original `AuditData` text is preserved verbatim in `auditData` so the
     full evidence trail is intact and `ualforge`'s SHA-256 dedup still works.
4. **Robust to malformed evidence.** Rows with **blank** `AuditData` are
   skipped (and counted).  Rows with **unparseable** `AuditData` JSON are
   passed through with empty derived columns; `ualforge` will then ingest
   them and log them to its `parse_errors` table - the original bytes are not
   lost.
5. **Output filename convention.** Outputs are named `*.normalized.csv` so
   `ualforge`'s Plan B structural scan picks them up automatically and won't
   confuse them with future raw inputs.

### What it will *not* do

- It is not a JSON-to-CSV converter for arbitrary audit feeds.  If the input
  has no `AuditData` column anywhere, it is rejected.
- It does not invent fields that weren't in the source JSON.  Older
  PowerShell exports often have empty `ClientIP` for service-principal events;
  those rows will still have empty `clientIp` after normalization (correctly).
- It does not deduplicate.  `ualforge` does that downstream via the SHA-256
  row hash, which works correctly across normalized and native files alike.

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

## License

GPL-3.0-or-later