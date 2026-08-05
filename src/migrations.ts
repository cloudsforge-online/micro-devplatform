/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * ---------------------------------------------------------------------------------------------
 * **THE CONSTRAINTS THAT ARE THE SERVICE, AND WHAT EACH REFUSES.**
 *
 *   `api_keys` HAS NO             There is no column a secret could go in. Not "we are careful not
 *   SECRET COLUMN.                to write it" — there is nowhere to write it. `secret_algo`,
 *                                 `secret_salt` and `secret_hash` are a one-way function of it,
 *                                 and `api_keys_no_plaintext_algo` refuses any row whose recorded
 *                                 algorithm is not a scrypt encoding, so a future change that
 *                                 quietly swapped in SHA-256 fails at the database rather than at
 *                                 review. `micro-custody` deleted its reveal endpoint (SD-08);
 *                                 this schema makes the equivalent unimplementable.
 *
 *   `api_keys.lookup_id`          UNIQUE, and the access path for every authenticated request. A
 *   IS UNIQUE AND INDEXED.        key must be identifiable without being usable — see keys.ts.
 *                                 Without this column, verifying a presented key means running
 *                                 scrypt against every row.
 *
 *   `api_keys_scopes_no_wildcard` A CHECK, not a validation. `scopes` is `text[]`, and an entry
 *                                 containing `*` is refused by the database. The application also
 *                                 refuses it (scopes.ts) — two layers because the schema outlives
 *                                 any particular write path, and the day someone adds a bulk
 *                                 import is the day the application layer is bypassed.
 *
 *   `quota_windows` HOLDS         A quota counted in a process variable is a quota multiplied by
 *   THE COUNTER.                  the replica count. The counter is a row, incremented by one
 *                                 conditional UPDATE, and `quota_windows_within_limit` makes
 *                                 exceeding it a constraint violation rather than a race that
 *                                 usually does not happen. Proven with concurrent requests in
 *                                 `quotas.test.ts`.
 *
 *   THERE IS NO BALANCE           04-domain-model §11 and the estate rule: this service holds no
 *   COLUMN, ANYWHERE.             money. Metered usage that costs money is a `micro-billing`
 *                                 entitlement or a `micro-ledger` entry, and what lives here is a
 *                                 COUNT of calls. A column named for an amount here is the first
 *                                 row of a second ledger. CI greps for one.
 *
 *   `quotas_max_within_ceiling`   A quota has a TOP as well as a bottom. `quotas_max_positive`
 *                                 already refused zero; without this, `setQuota` accepted any
 *                                 integer at all, so the only thing between a customer and an
 *                                 unlimited plan was a handler. A CHECK holds against a caller
 *                                 holding a database connection — a backfill, a psql session, a
 *                                 write path written next year — and a handler does not. See
 *                                 migration 9.
 *
 *   `applications_slug_not_      An application whose slug is `pending` would sit at
 *   reserved`                     `/v1/apps/pending`, which is the operator's review queue, and
 *                                 would therefore be unreachable at its own public address. The
 *                                 collision is made UNREPRESENTABLE rather than documented: a
 *                                 route ordering that has to be remembered is one that will be
 *                                 reordered.
 *
 *   `webhook_secrets` STORES      The one place in this service where a secret is stored
 *   PLAINTEXT, AND SAYS SO.       recoverably, because HMAC is not a one-way function of an input
 *                                 we do not have: signing a delivery requires the secret itself.
 *                                 It is shown once, never returned by any route afterwards, and
 *                                 rotation keeps two rows live so a subscriber can verify against
 *                                 either during the overlap. The full argument is in webhooks.ts
 *                                 and in the README — this is the honest exception to "shown once
 *                                 and stored hashed", and pretending otherwise would be worse.
 * ---------------------------------------------------------------------------------------------
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Verbatim from the runtime package, so the table the claim query assumes and the table that
    // exists cannot drift.
    up: JOBS_SCHEMA_SQL,
  },

  {
    version: 2,
    name: 'developer-orgs-projects-environments',
    up: `
      -- A developer organisation's ENROLMENT in the developer platform.
      --
      -- Organisations and their memberships are identity's (07-dependency-map.md:143 — a hard
      -- dependency, fast-read). This table is not a copy of that: it holds the enrolment, the
      -- plan and the status, keyed by identity's organisation id. Membership is asked of
      -- identity on the request that needs it and is never mirrored here, because a mirrored
      -- membership is a membership that can be stale at exactly the moment someone is removed.
      create table if not exists developer_orgs (
        id                 uuid        primary key default gen_random_uuid(),
        identity_org_id    text        not null,
        name               text        not null,
        slug               text        not null,
        -- active | suspended. A suspended org's keys stop authenticating; the rows survive so
        -- that reinstatement is a state change rather than a re-issue of every credential.
        status             text        not null default 'active',
        created_at         timestamptz not null default now(),
        updated_at         timestamptz not null default now(),
        constraint developer_orgs_identity_uniq unique (identity_org_id),
        constraint developer_orgs_slug_uniq unique (slug),
        constraint developer_orgs_status_known check (status in ('active','suspended')),
        constraint developer_orgs_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$')
      );

      create table if not exists projects (
        id                 uuid        primary key default gen_random_uuid(),
        org_id             uuid        not null references developer_orgs (id) on delete cascade,
        name               text        not null,
        slug               text        not null,
        status             text        not null default 'active',
        created_at         timestamptz not null default now(),
        updated_at         timestamptz not null default now(),
        -- Scoped to the org, not global: two organisations may both have a project called
        -- 'checkout' and neither should have to discover the other's naming.
        constraint projects_slug_uniq unique (org_id, slug),
        constraint projects_status_known check (status in ('active','archived')),
        constraint projects_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$')
      );

      create index if not exists projects_org_idx on projects (org_id);

      -- Exactly two per project, created with it: 'live' and 'test'. They are rows rather than an
      -- enum column because quotas, keys, webhook endpoints and usage all hang off an
      -- environment, and a foreign key to a row is the only version of that which the database
      -- can enforce.
      create table if not exists environments (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        name               text        not null,
        created_at         timestamptz not null default now(),
        constraint environments_name_uniq unique (project_id, name),
        constraint environments_name_known check (name in ('live','test'))
      );

      create index if not exists environments_project_idx on environments (project_id);
    `,
  },

  {
    version: 3,
    name: 'api-keys-and-service-accounts',
    up: `
      -- A machine principal inside a project. A key may belong to one, which is how "this key is
      -- the nightly reconciliation job" survives the key being rotated.
      create table if not exists service_accounts (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        name               text        not null,
        description        text        not null default '',
        disabled_at        timestamptz,
        created_at         timestamptz not null default now(),
        constraint service_accounts_name_uniq unique (project_id, name)
      );

      create index if not exists service_accounts_project_idx on service_accounts (project_id);

      -- ═══════════════════════════════════════════════════════════════════════════════════════
      -- THE CREDENTIAL TABLE. Read keys.ts before changing anything below.
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists api_keys (
        id                 uuid        primary key default gen_random_uuid(),
        environment_id     uuid        not null references environments (id) on delete cascade,
        service_account_id uuid        references service_accounts (id) on delete set null,
        -- Denormalised from environments deliberately: authentication reads this row and nothing
        -- else, so a key check is one indexed lookup rather than a three-table join on the hot
        -- path. Kept honest by api_keys_environment_matches below.
        project_id         uuid        not null references projects (id) on delete cascade,
        environment        text        not null,

        -- The identifiable half. Stored in the clear, because it grants nothing.
        lookup_id          text        not null,
        -- 'cfk_live_<lookup>'. What a log line, a list view and a revocation request carry.
        display            text        not null,

        -- The usable half, one-way. There is no column for the secret itself.
        secret_algo        text        not null,
        secret_salt        text        not null,
        secret_hash        text        not null,

        name               text        not null,
        -- Exact-match scopes, no wildcard, empty allowed and inert. See scopes.ts.
        scopes             text[]      not null default '{}',

        created_by         text        not null,
        created_at         timestamptz not null default now(),
        last_used_at       timestamptz,
        expires_at         timestamptz,
        revoked_at         timestamptz,
        revoked_by         text,
        revoked_reason     text,

        constraint api_keys_lookup_uniq unique (lookup_id),
        constraint api_keys_lookup_shape check (lookup_id ~ '^[a-z2-7]{16}$'),
        constraint api_keys_environment_known check (environment in ('live','test')),
        constraint api_keys_display_shape check (display = 'cfk_' || environment || '_' || lookup_id),

        -- The algorithm must be a scrypt encoding. A row recording 'sha256' — or anything else
        -- fast — is refused by the database. An API key table is a password table, and the day
        -- someone reaches for createHash because it is one line shorter, this is what stops it.
        constraint api_keys_slow_kdf_only check (secret_algo ~ '^scrypt\\$N=[0-9]+,r=[0-9]+,p=[0-9]+,keyLen=[0-9]+$'),
        constraint api_keys_hash_is_hex check (secret_hash ~ '^[0-9a-f]{32,}$' and secret_salt ~ '^[0-9a-f]{16,}$'),

        -- No wildcard reaches a row. scopes.ts refuses one at issuance; this refuses one however
        -- it arrived. \`*\` is not a LIKE metacharacter, so this matches it literally, and an empty
        -- array joins to '' and passes — an empty scope set is legal and inert, not a wildcard.
        constraint api_keys_scopes_no_wildcard check (array_to_string(scopes, ',') not like '%*%'),

        -- A revocation is a fact with a time. A row claiming to be revoked without saying when
        -- cannot be reasoned about during an incident, which is the only time anyone reads it.
        constraint api_keys_revoked_has_time check ((revoked_at is null) = (revoked_by is null))
      );

      -- The authentication path: one equality on a unique index. Nothing else is on this path.
      create index if not exists api_keys_project_idx on api_keys (project_id, created_at desc);
      create index if not exists api_keys_environment_idx on api_keys (environment_id);
      -- Partial, on the live set: the revoked set grows for ever and never needs scanning.
      create index if not exists api_keys_live_idx on api_keys (project_id) where revoked_at is null;
    `,
  },

  {
    version: 4,
    name: 'oauth-clients',
    up: `
      -- An OAuth client. The secret is hashed exactly as an API key's is, and for the same reason:
      -- a client secret dumped from this table must not be a working credential.
      create table if not exists oauth_clients (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        client_id          text        not null,
        name               text        not null,
        secret_algo        text        not null,
        secret_salt        text        not null,
        secret_hash        text        not null,
        redirect_uris      text[]      not null default '{}',
        scopes             text[]      not null default '{}',
        created_at         timestamptz not null default now(),
        revoked_at         timestamptz,
        constraint oauth_clients_client_id_uniq unique (client_id),
        constraint oauth_clients_slow_kdf_only check (secret_algo ~ '^scrypt\\$N=[0-9]+,r=[0-9]+,p=[0-9]+,keyLen=[0-9]+$'),
        constraint oauth_clients_scopes_no_wildcard check (array_to_string(scopes, ',') not like '%*%'),
        -- Every redirect URI is absolute https, or an http loopback for local development. A
        -- wildcard or a relative URI here is an open redirect that hands an authorisation code to
        -- whoever asked for it.
        --
        -- Written as one anchored regex over the newline-joined array rather than the obvious
        -- \`unnest(...)\` form, because a CHECK constraint may not contain a subquery — the
        -- readable version parses and then fails at CREATE TABLE with 0A000.
        constraint oauth_clients_redirects_absolute check (
          cardinality(redirect_uris) = 0
          or array_to_string(redirect_uris, E'\\n') ~
             '^(https://[^\\n*[:space:]]+|http://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?(/[^\\n*[:space:]]*)?)(\\n(https://[^\\n*[:space:]]+|http://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?(/[^\\n*[:space:]]*)?))*$'
        )
      );

      create index if not exists oauth_clients_project_idx on oauth_clients (project_id);
    `,
  },

  {
    version: 5,
    name: 'webhooks',
    up: `
      create table if not exists webhook_endpoints (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        environment_id     uuid        not null references environments (id) on delete cascade,
        url                text        not null,
        -- Topics this endpoint wants. Empty means none, and none means no delivery — an endpoint
        -- that receives everything by default is an endpoint nobody meant to subscribe.
        topics             text[]      not null default '{}',
        description        text        not null default '',
        disabled_at        timestamptz,
        created_at         timestamptz not null default now(),
        constraint webhook_endpoints_url_uniq unique (environment_id, url),
        -- https only, and no wildcards. A plaintext delivery carries a signed payload over a wire
        -- anyone can read; the signature proves origin, it does not provide confidentiality.
        constraint webhook_endpoints_url_https check (url ~ '^https://[^*[:space:]]+$')
      );

      create index if not exists webhook_endpoints_project_idx on webhook_endpoints (project_id);

      -- The signing secret. See webhooks.ts: this is the ONE recoverable secret in the service,
      -- because HMAC requires the key material. Shown once, never returned afterwards.
      --
      -- Two rows may be live at once. Rotation signs with the newest and keeps the previous valid
      -- for an overlap window, so a subscriber updates its configuration without dropping a
      -- delivery. \`verifyDelivery\` in @cloudsforge/contracts-events accepts a list of secrets for
      -- exactly this reason (contracts/packages/events/src/index.ts:718).
      create table if not exists webhook_secrets (
        id                 uuid        primary key default gen_random_uuid(),
        endpoint_id        uuid        not null references webhook_endpoints (id) on delete cascade,
        secret             text        not null,
        created_at         timestamptz not null default now(),
        -- When this secret stops being accepted. Null means live.
        retires_at         timestamptz,
        constraint webhook_secrets_secret_length check (length(secret) >= 32)
      );

      create index if not exists webhook_secrets_endpoint_idx on webhook_secrets (endpoint_id, created_at desc);

      -- One delivery attempt record per (endpoint, event). The unique constraint is what makes a
      -- retry a retry rather than a second delivery.
      create table if not exists webhook_deliveries (
        id                 uuid        primary key default gen_random_uuid(),
        endpoint_id        uuid        not null references webhook_endpoints (id) on delete cascade,
        event_id           text        not null,
        topic              text        not null,
        payload            jsonb       not null,
        attempts           integer     not null default 0,
        delivered_at       timestamptz,
        last_status        integer,
        last_error         text,
        next_attempt_at    timestamptz not null default now(),
        created_at         timestamptz not null default now(),
        constraint webhook_deliveries_uniq unique (endpoint_id, event_id),
        constraint webhook_deliveries_attempts_nonneg check (attempts >= 0)
      );

      create index if not exists webhook_deliveries_pending_idx
        on webhook_deliveries (next_attempt_at)
        where delivered_at is null;
    `,
  },

  {
    version: 6,
    name: 'usage-and-quotas',
    up: `
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      -- THE COUNTER IS A ROW. An in-memory counter is per-replica and therefore not a quota.
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      create table if not exists quotas (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        environment_id     uuid        not null references environments (id) on delete cascade,
        -- What is being limited. 'api_requests' today; the column exists so a second meter is a
        -- row rather than a migration.
        meter              text        not null,
        -- minute | hour | day | month. The window the limit applies over.
        period             text        not null,
        max_units          bigint      not null,
        created_at         timestamptz not null default now(),
        updated_at         timestamptz not null default now(),
        constraint quotas_uniq unique (environment_id, meter, period),
        constraint quotas_period_known check (period in ('minute','hour','day','month')),
        constraint quotas_max_positive check (max_units > 0)
      );

      -- One row per (quota, window). Incremented by a single conditional UPDATE, so two replicas
      -- racing produce two serialised increments and never two winners past the limit.
      create table if not exists quota_windows (
        quota_id           uuid        not null references quotas (id) on delete cascade,
        window_start       timestamptz not null,
        used_units         bigint      not null default 0,
        max_units          bigint      not null,
        updated_at         timestamptz not null default now(),
        constraint quota_windows_pk primary key (quota_id, window_start),
        -- The belt to the UPDATE's braces. If a future write path ever increments without the
        -- guard, this refuses the row rather than silently allowing an overage.
        constraint quota_windows_within_limit check (used_units <= max_units),
        constraint quota_windows_nonneg check (used_units >= 0)
      );

      -- Raw metered calls. Rolled up by a leased job and pruned; this is a COUNT of requests, and
      -- there is deliberately no amount, price or balance column anywhere near it. Anything that
      -- costs money is a micro-billing entitlement or a micro-ledger entry, never a column here.
      create table if not exists usage_events (
        id                 bigserial   primary key,
        project_id         uuid        not null references projects (id) on delete cascade,
        environment_id     uuid        not null references environments (id) on delete cascade,
        api_key_id         uuid        references api_keys (id) on delete set null,
        route              text        not null,
        method             text        not null,
        status             integer     not null,
        occurred_at        timestamptz not null default now(),
        constraint usage_events_status_range check (status >= 100 and status < 600)
      );

      create index if not exists usage_events_rollup_idx on usage_events (occurred_at);
      create index if not exists usage_events_project_idx on usage_events (project_id, occurred_at desc);

      create table if not exists usage_rollups (
        project_id         uuid        not null references projects (id) on delete cascade,
        environment_id     uuid        not null references environments (id) on delete cascade,
        route              text        not null,
        bucket             timestamptz not null,
        calls              bigint      not null,
        errors             bigint      not null,
        constraint usage_rollups_pk primary key (environment_id, route, bucket),
        constraint usage_rollups_nonneg check (calls >= 0 and errors >= 0)
      );

      create index if not exists usage_rollups_bucket_idx on usage_rollups (bucket desc);
    `,
  },

  {
    version: 7,
    name: 'application-directory',
    up: `
      -- The public application directory. A project may publish one listing; the listing is what
      -- a user sees on the consent screen when the project's OAuth client asks for authority.
      create table if not exists applications (
        id                 uuid        primary key default gen_random_uuid(),
        project_id         uuid        not null references projects (id) on delete cascade,
        slug               text        not null,
        name               text        not null,
        tagline            text        not null default '',
        description        text        not null default '',
        homepage_url       text,
        -- draft | in_review | listed | delisted. A listing is not public until someone said so.
        status             text        not null default 'draft',
        listed_at          timestamptz,
        created_at         timestamptz not null default now(),
        updated_at         timestamptz not null default now(),
        constraint applications_slug_uniq unique (slug),
        constraint applications_project_uniq unique (project_id),
        constraint applications_slug_shape check (slug ~ '^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$'),
        constraint applications_status_known check (status in ('draft','in_review','listed','delisted')),
        -- A listed application has a time it was listed. Same shape as the revocation check
        -- above, same reason: a state that cannot be dated cannot be audited.
        constraint applications_listed_has_time check ((status = 'listed') = (listed_at is not null)),
        constraint applications_homepage_https check (homepage_url is null or homepage_url ~ '^https://[^*[:space:]]+$')
      );
    `,
  },

  {
    version: 8,
    name: 'outbox-inbox-idempotency',
    up: `
      -- Rule 5: every state change others care about writes an outbox row IN THE SAME TRANSACTION
      -- as the change. No broker — Postgres already has transactions and SKIP LOCKED (AD-10).
      create table if not exists outbox (
        id                 uuid        primary key default gen_random_uuid(),
        topic              text        not null,
        key                text        not null,
        producer           text        not null,
        version            integer     not null default 1,
        actor              text,
        correlation_id     text,
        payload            jsonb       not null,
        occurred_at        timestamptz not null default now(),
        published_at       timestamptz
      );

      create index if not exists outbox_unpublished_idx on outbox (occurred_at) where published_at is null;

      create table if not exists event_subscriptions (
        id                 uuid        primary key default gen_random_uuid(),
        topic              text        not null,
        url                text        not null,
        active             boolean     not null default true,
        created_at         timestamptz not null default now(),
        constraint event_subscriptions_uniq unique (topic, url)
      );

      create table if not exists outbox_deliveries (
        event_id           uuid        not null references outbox (id) on delete cascade,
        subscription_id    uuid        not null references event_subscriptions (id) on delete cascade,
        attempts           integer     not null default 0,
        delivered_at       timestamptz,
        last_error         text,
        constraint outbox_deliveries_pk primary key (event_id, subscription_id)
      );

      -- The inbox. Deduped on the SOURCE's event id, which is what makes at-least-once delivery
      -- effectively-once here: the insert and the handler share one transaction, so a handler
      -- that fails leaves no row and the redelivery is processed rather than swallowed.
      create table if not exists inbox (
        topic              text        not null,
        source_event_id    text        not null,
        received_at        timestamptz not null default now(),
        constraint inbox_pk primary key (topic, source_event_id)
      );

      -- Route-level idempotency. The claim INSERT and the work share ONE transaction, so the
      -- stored response can never disagree with what actually committed.
      create table if not exists idempotency_keys (
        key                text        primary key,
        route              text        not null,
        request_hash       text        not null,
        response           jsonb,
        artefact_id        text,
        created_at         timestamptz not null default now()
      );

      create index if not exists idempotency_keys_created_idx on idempotency_keys (created_at);
    `,
  },

  {
    version: 9,
    name: 'quota-ceiling-and-application-review',
    up: `
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      -- A QUOTA HAS A TOP. Until this migration it had only a bottom.
      --
      -- quotas_max_positive refused zero from the first day. Nothing refused ten billion, so
      -- setQuota accepted any whole number a caller sent and the only thing standing between a
      -- customer and an unlimited plan was one line in a handler. The authority rule that says
      -- who may RAISE a quota is in src/server.ts, where it has to be; this is the bound that
      -- holds regardless of which write path arrives, because a CHECK holds against a caller
      -- with a database connection and a handler does not. It is the same argument as
      -- quota_windows_within_limit, one table over.
      --
      -- The numbers are not a judgement about what a plan should be. Each is the largest value
      -- this service's OWN configuration already permits to be seeded into these rows —
      -- src/env.ts:210 bounds DEVPLATFORM_DEFAULT_QUOTA_PER_MINUTE at 10,000,000 and :211 bounds
      -- DEVPLATFORM_DEFAULT_QUOTA_PER_MONTH at 10,000,000,000 — so a legal configuration can
      -- never be refused by the constraint guarding the rows it seeds. A per-minute allowance of
      -- ten billion is not a limit anybody chose; it is a number nobody bounded.
      --
      -- ADDING THIS VALIDATES EVERY EXISTING ROW. If a quota is already above its ceiling this
      -- statement fails with 23514 and the deploy stops, which is the intended behaviour: a
      -- migration that silently rewrote somebody's limit would destroy the only record of what
      -- it had been. The repair is a deliberate UPDATE, decided by a person, before the deploy.
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      alter table quotas add constraint quotas_max_within_ceiling check (
        max_units <= case when period = 'minute' then 10000000 else 10000000000 end
      );

      -- ═══════════════════════════════════════════════════════════════════════════════════════
      -- A REJECTED APPLICATION IS NOT A DELISTED ONE.
      --
      -- The original vocabulary was draft | in_review | listed | delisted, so an application an
      -- operator refused had nowhere to go but 'delisted' — the same value as a listing that WAS
      -- public and was taken down. Those are different facts about a developer ("we looked and
      -- said no" against "you were live and we removed you"), they are answered differently by
      -- support, and one of them is a resubmission and the other is an appeal.
      --
      -- 'rejected' is added rather than 'delisted' being redefined, because a delisted row today
      -- genuinely was listed once: applications_listed_has_time forced a listed_at onto it.
      -- ═══════════════════════════════════════════════════════════════════════════════════════
      alter table applications drop constraint if exists applications_status_known;
      alter table applications add constraint applications_status_known
        check (status in ('draft','in_review','listed','rejected','delisted'));

      -- The operator's review queue is served at /v1/apps/pending, in front of /v1/apps/:slug.
      -- A listing that took 'pending' as its slug would be shadowed by that route and could never
      -- be fetched at its own public address. Refused here rather than remembered in the router:
      -- an ordering that has to be preserved by hand is one that will be reordered by hand.
      alter table applications add constraint applications_slug_not_reserved
        check (slug <> 'pending');
    `,
  },

  {
    version: 10,
    name: 'erased-attribution-is-final',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- AN ERASED KEY ATTRIBUTION MAY NOT BE GIVEN BACK TO A REAL ACCOUNT.
      --
      -- \`identity.user.deleted\` overwrites \`created_by\` and \`revoked_by\` with
      -- \`user:erased-<uuid>\` wherever they named the deleted person, and deliberately leaves the
      -- key itself LIVE: the credential is the organisation's, and revoking it would take a
      -- customer's production integration down because an employee closed their account.
      --
      -- That choice is what creates the hazard this trigger closes. The row stays in every list,
      -- every rotation and every support tool, looking exactly like a normal key — so the natural
      -- thing for a later repair script, a re-import or a "fix the orphaned attribution" ticket to
      -- do is to write a real \`user:<uuid>\` back into it. Nothing about the value would look
      -- wrong. It would simply re-attribute a live credential to somebody who asked to be
      -- forgotten, and the erasure would silently un-happen.
      --
      -- One direction only: an erased attribution may not stop being erased. Nothing here says
      -- which rows must be erased, because almost none ever will be.
      --
      -- A CHECK cannot express this — it sees one row, not the transition — so it is a trigger.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create or replace function devplatform_refuse_reattribution() returns trigger
        language plpgsql
      as $$
      begin
        if old.created_by like 'user:erased-%' and new.created_by is distinct from old.created_by then
          raise exception
            'api key % has an erased creator; it may not be re-attributed to %', old.id, new.created_by
            using errcode = 'check_violation';
        end if;
        if old.revoked_by like 'user:erased-%' and new.revoked_by is distinct from old.revoked_by then
          raise exception
            'api key % has an erased revoker; it may not be re-attributed to %', old.id, new.revoked_by
            using errcode = 'check_violation';
        end if;
        return new;
      end;
      $$;

      drop trigger if exists api_keys_erased_attribution_is_final on api_keys;
      create trigger api_keys_erased_attribution_is_final
        before update on api_keys
        for each row execute function devplatform_refuse_reattribution();

      -- Erasure looks keys up by the person who created them, which had no index: the existing
      -- ones are on project, environment and lookup id. Without this, every erasure — including
      -- the overwhelming majority that match nothing — is a sequential scan of the key table.
      create index if not exists api_keys_created_by_idx on api_keys (created_by);
      create index if not exists api_keys_revoked_by_idx on api_keys (revoked_by)
        where revoked_by is not null;
    `,
  },
]

/** Every table this service owns. The truncate list for the test harness, and nothing else. */
export const TABLES: readonly string[] = Object.freeze([
  'developer_orgs',
  'projects',
  'environments',
  'service_accounts',
  'api_keys',
  'oauth_clients',
  'webhook_endpoints',
  'webhook_secrets',
  'webhook_deliveries',
  'quotas',
  'quota_windows',
  'usage_events',
  'usage_rollups',
  'applications',
  'outbox',
  'event_subscriptions',
  'outbox_deliveries',
  'inbox',
  'idempotency_keys',
])

/**
 * The version `index.ts` asserts before it serves.
 *
 * Derived rather than written down, so adding a migration cannot leave the assertion behind — the
 * failure that produces is a service running happily against a schema missing the CHECK it
 * depends on, and here that CHECK is `api_keys_slow_kdf_only`.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce(
  (highest, migration) => Math.max(highest, migration.version),
  0,
)

/** No baseline. This service is new; there is no pre-existing schema to adopt. */
export const BASELINE_VERSION = 0
