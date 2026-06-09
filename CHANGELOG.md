# Changelog

All notable changes to `utopia-php/audit` are documented in this file.

## 2.4.0

### ClickHouse adapter — actor terminology

The ClickHouse adapter now stores its principal columns under "actor" terminology:
`actorId`, `actorType`, `actorInternalId`. The shared SQL base, the Database adapter,
and the public `Audit` API are unchanged — Database-backed audit logs continue to use
`userId`.

This is a non-breaking change for callers of the public API. `Audit::log($userId, ...)`,
`Audit::getLogsByUser(...)`, `Audit::countLogsByUser(...)`, and the equivalent
`*ByUserAndEvents` methods all keep their original signatures. The ClickHouse adapter
translates the legacy `userId` array key and `Query::equal('userId', ...)` filter
internally to the renamed `actorId` column.

#### Added

- `Log::getActorId()`, `Log::getActorType()`, `Log::getActorInternalId()` getters for
  ClickHouse-backed log reads.
- `Log` instances returned by the ClickHouse adapter expose both `actorId` / `actorType`
  / `actorInternalId` (canonical) and `userId` / `userType` / `userInternalId` (legacy
  mirror) attribute keys so existing code paths continue to work.

#### ClickHouse schema changes

- Column `userId` → `actorId`
- Column `userType` → `actorType`
- Column `userInternalId` → `actorInternalId`
- Index `idx_userId_event` → `idx_actorId_event`
- Index `_key_user_type` → `_key_actor_type`
- Index `_key_user_internal_id` → `_key_actor_internal_id`
- Index `_key_user_internal_and_event` → `_key_actor_internal_and_event`

#### Migration

ClickHouse audit tables will be recreated by `setup()` with the new column names.
Existing ClickHouse audit data is not preserved automatically — this is acceptable
because the activity-events surface backed by this schema is not yet in public use.
If preservation is needed, run `ALTER TABLE ... RENAME COLUMN` for each renamed
column before redeploying.

No migration is required for Database-backed audit logs. The Database adapter
continues to write and read `userId` columns and indexes unchanged.

## 2.3.2 and earlier

See git history.
