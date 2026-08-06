/**
 * The credential store: issuing, listing, revoking and authenticating an API key.
 *
 * `keys.ts` owns the FORMAT and the CRYPTOGRAPHY and knows nothing about a database. This file owns
 * the ROWS, and the split is deliberate: every property that matters — the constant-cost verify,
 * the decoy KDF run, the exact-match scope rule — is proven in `keys.test.ts` without a Postgres,
 * and cannot be quietly undone here by an early return.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE SECRET IS RETURNED ONCE, BY THIS FUNCTION, AND BY NOTHING ELSE.**
 *
 * `issueApiKey` is the only function in this service whose return value contains a usable
 * credential, and it is a value that has never been in a column: `issueKey` mints it in memory,
 * hands back a one-way `stored`, and the INSERT below writes `stored`. Every other function here
 * returns `ApiKeySummary`, which has no field a secret could occupy — not "we are careful", but
 * "the type has nowhere to put it". `server.test.ts` proves it over the wire, on every route, by
 * enumeration.
 *
 * `micro-custody` deleted its admin-reveal endpoint rather than guard it (SD-08). There is no
 * equivalent here and there is nothing to guard: the plaintext does not exist after the response
 * is written.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **AUTHENTICATION CONSULTS THE ORGANISATION, AND STILL COSTS ONE KDF RUN.**
 *
 * A suspended organisation's keys stop working immediately (`orgs.ts` — suspension is a status, not
 * a mass revocation). The status is fetched by the SAME query that fetches the key, so it changes
 * neither the shape nor the cost of the lookup, and it is applied AFTER `verifyPresentedKey` has
 * already spent its KDF run. Checking it earlier would hand back a fast "no" for a real key
 * belonging to a suspended org, which is a membership oracle.
 */

import { randomUUID } from 'node:crypto'
import type { Actor } from '@cloudsforge/contracts-events'
import type { Db, Emit, Tx } from './outbox.ts'
import { TOPICS } from './outbox.ts'
import { NotFoundError, ValidationError } from './orgs.ts'
import { validateScopes, type Scope } from './scopes.ts'
import {
  CURRENT_PARAMS,
  hashSecret,
  issueKey,
  keyDisplay,
  parseKey,
  verifyPresentedKey,
  type Kdf,
  type KeyEnvironment,
  type KeyRefusal,
  type ScryptParams,
  type VerifiableKey,
} from './keys.ts'

/* ------------------------------------------------------------------ service accounts */

export interface ServiceAccount {
  readonly id: string
  readonly projectId: string
  readonly name: string
  readonly description: string
  readonly disabledAt: Date | null
  readonly createdAt: Date
}

interface ServiceAccountRow {
  readonly id: string
  readonly project_id: string
  readonly name: string
  readonly description: string
  readonly disabled_at: Date | null
  readonly created_at: Date
}

function toServiceAccount(row: ServiceAccountRow): ServiceAccount {
  return {
    id: row.id,
    projectId: row.project_id,
    name: row.name,
    description: row.description,
    disabledAt: row.disabled_at,
    createdAt: row.created_at,
  }
}

/**
 * A machine principal inside a project.
 *
 * `on conflict do nothing` then read, so a retried creation is the first creation. The natural key
 * is `(project_id, name)` and a second POST naming the same account is not a second account.
 */
export async function createServiceAccount(
  sql: Tx | Db,
  input: { readonly projectId: string; readonly name: string; readonly description?: string },
): Promise<ServiceAccount> {
  const name = input.name.trim()
  if (name.length < 1 || name.length > 200) {
    throw new ValidationError('a service account name must be 1 to 200 characters')
  }
  const description = (input.description ?? '').trim().slice(0, 2_000)

  const inserted = await sql<ServiceAccountRow[]>`
    insert into service_accounts (project_id, name, description)
    values (${input.projectId}, ${name}, ${description})
    on conflict (project_id, name) do nothing
    returning id, project_id, name, description, disabled_at, created_at
  `
  const row = inserted[0]
  if (row) return toServiceAccount(row)

  const existing = await sql<ServiceAccountRow[]>`
    select id, project_id, name, description, disabled_at, created_at
      from service_accounts where project_id = ${input.projectId} and name = ${name}
  `
  const found = existing[0]
  if (!found) throw new NotFoundError('no such project')
  return toServiceAccount(found)
}

export async function listServiceAccounts(
  sql: Tx | Db,
  projectId: string,
): Promise<readonly ServiceAccount[]> {
  const rows = await sql<ServiceAccountRow[]>`
    select id, project_id, name, description, disabled_at, created_at
      from service_accounts where project_id = ${projectId} order by created_at
  `
  return rows.map(toServiceAccount)
}

/* ------------------------------------------------------------------ keys */

/**
 * What a key looks like to everyone after the moment it is created.
 *
 * There is no `secret`, no `secretKey` and no `hash` field. `IssuedApiKey` below is the only type
 * that carries the credential, it is returned by exactly one function, and it is never stored.
 */
export interface ApiKeySummary {
  readonly id: string
  readonly projectId: string
  readonly environmentId: string
  readonly environment: KeyEnvironment
  readonly serviceAccountId: string | null
  /** `cfk_live_<lookup>`. Safe in a log, a list and a support ticket. Revoke by this. */
  readonly display: string
  readonly lookupId: string
  readonly name: string
  readonly scopes: readonly string[]
  readonly createdBy: string
  readonly createdAt: Date
  readonly lastUsedAt: Date | null
  readonly expiresAt: Date | null
  readonly revokedAt: Date | null
  readonly revokedReason: string | null
}

/** The one shape in this service that carries a usable credential. Never persisted, never logged. */
export interface IssuedApiKey {
  readonly key: ApiKeySummary
  /** The full `cfk_…` string. This is the only copy that will ever exist. */
  readonly secretKey: string
}

interface ApiKeyRow {
  readonly id: string
  readonly project_id: string
  readonly environment_id: string
  readonly environment: string
  readonly service_account_id: string | null
  readonly display: string
  readonly lookup_id: string
  readonly name: string
  readonly scopes: readonly string[]
  readonly created_by: string
  readonly created_at: Date
  readonly last_used_at: Date | null
  readonly expires_at: Date | null
  readonly revoked_at: Date | null
  readonly revoked_reason: string | null
}

const SUMMARY_COLUMNS = `id, project_id, environment_id, environment, service_account_id, display,
  lookup_id, name, scopes, created_by, created_at, last_used_at, expires_at, revoked_at, revoked_reason`

function toSummary(row: ApiKeyRow): ApiKeySummary {
  return {
    id: row.id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    environment: row.environment === 'live' ? 'live' : 'test',
    serviceAccountId: row.service_account_id,
    display: row.display,
    lookupId: row.lookup_id,
    name: row.name,
    scopes: row.scopes,
    createdBy: row.created_by,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    expiresAt: row.expires_at,
    revokedAt: row.revoked_at,
    revokedReason: row.revoked_reason,
  }
}

export interface IssueApiKeyInput {
  readonly projectId: string
  readonly environment: KeyEnvironment
  readonly name: string
  /** Validated against the registry. An unknown scope or a wildcard is refused, never filtered. */
  readonly scopes: readonly string[]
  readonly createdBy: string
  readonly serviceAccountId?: string | null
  readonly expiresAt?: Date | null
}

/**
 * Mint a key.
 *
 * Takes a transaction because the row and the `devplatform.key.issued` outbox entry are one fact.
 * `params` and `kdf` are seams so a test can run at a low work factor and count KDF invocations —
 * a full-cost scrypt run per key would make the database suite take minutes, and a slow suite is a
 * suite that gets `--test-concurrency` raised until it deadlocks.
 */
export async function issueApiKey(
  tx: Tx,
  input: IssueApiKeyInput,
  options: { readonly params?: ScryptParams; readonly kdf?: Kdf } = {},
): Promise<IssuedApiKey> {
  const name = input.name.trim()
  if (name.length < 1 || name.length > 200) {
    throw new ValidationError('a key name must be 1 to 200 characters')
  }
  // Refuses rather than filters — see scopes.ts. A caller told "created" for a key missing an
  // authority it asked for finds out at the worst possible moment.
  const scopes: readonly Scope[] = validateScopes(input.scopes)

  const environments = await tx<{ id: string }[]>`
    select id from environments where project_id = ${input.projectId} and name = ${input.environment}
  `
  const environment = environments[0]
  if (!environment) throw new NotFoundError('no such project environment')

  if (input.serviceAccountId) {
    const accounts = await tx<{ id: string }[]>`
      select id from service_accounts
       where id = ${input.serviceAccountId} and project_id = ${input.projectId}
    `
    // Checked rather than left to the foreign key: `service_accounts.id` alone is a valid
    // reference, so without this a key could be attached to another project's service account.
    if (!accounts[0]) throw new NotFoundError('no such service account in this project')
  }

  const minted = await issueKey(input.environment, options.params ?? CURRENT_PARAMS, options.kdf)

  const rows = await tx<ApiKeyRow[]>`
    insert into api_keys (
      environment_id, service_account_id, project_id, environment,
      lookup_id, display, secret_algo, secret_salt, secret_hash,
      name, scopes, created_by, expires_at
    ) values (
      ${environment.id}, ${input.serviceAccountId ?? null}, ${input.projectId}, ${input.environment},
      ${minted.lookupId}, ${minted.display},
      ${minted.stored.algo}, ${minted.stored.salt}, ${minted.stored.hash},
      ${name}, ${tx.array(scopes as string[])}, ${input.createdBy}, ${input.expiresAt ?? null}
    )
    returning ${tx.unsafe(SUMMARY_COLUMNS)}
  `
  const row = rows[0]
  if (!row) throw new Error('api key insert returned no row')
  return { key: toSummary(row), secretKey: minted.secretKey }
}

/**
 * The event that goes with an issuance. Carries the DISPLAY, never the key.
 *
 * `actor` is a parameter of the contract's `Actor` type rather than `key.createdBy`, and the
 * difference is not style. `createdBy` is `string` because it is read back out of Postgres, and a
 * column read is where a type guarantee is laundered: whatever the compiler proved about the value
 * on its way IN is gone by the time it comes back OUT. Taking it from the caller keeps the one
 * value the compiler can still vouch for. The two are the same string — `server.ts` passes
 * `actorOf(caller)` to both `issueApiKey`'s `createdBy` and to here — so this changes what is
 * PROVEN, not what is emitted.
 */
export function emitKeyIssued(emit: Emit, key: ApiKeySummary, actor: Actor): void {
  emit({
    topic: TOPICS.keyIssued,
    key: key.id,
    actor,
    payload: {
      keyId: key.id,
      projectId: key.projectId,
      environment: key.environment,
      display: key.display,
      scopes: [...key.scopes],
    },
  })
}

export async function listApiKeys(
  sql: Tx | Db,
  projectId: string,
  options: { readonly includeRevoked?: boolean } = {},
): Promise<readonly ApiKeySummary[]> {
  const rows = options.includeRevoked
    ? await sql<ApiKeyRow[]>`
        select ${sql.unsafe(SUMMARY_COLUMNS)} from api_keys
         where project_id = ${projectId} order by created_at desc
      `
    : await sql<ApiKeyRow[]>`
        select ${sql.unsafe(SUMMARY_COLUMNS)} from api_keys
         where project_id = ${projectId} and revoked_at is null order by created_at desc
      `
  return rows.map(toSummary)
}

export async function findApiKey(sql: Tx | Db, id: string): Promise<ApiKeySummary | null> {
  const rows = await sql<ApiKeyRow[]>`
    select ${sql.unsafe(SUMMARY_COLUMNS)} from api_keys where id = ${id}
  `
  const row = rows[0]
  return row ? toSummary(row) : null
}

/**
 * Revoke a key.
 *
 * Immediate: the next `authenticateKey` in this service reads `revoked_at` and refuses. The outbox
 * event (`devplatform.key.revoked`) is what makes it immediate everywhere else —
 * `11-data-and-contract-strategy.md` records that key validation is cached 30 s at the edge, so
 * the event is the mechanism by which that cache is invalidated rather than waited out.
 *
 * Idempotent by claim: `where revoked_at is null` means the second revocation matches no row and
 * the first revocation's time and reason are preserved. A second call is not an error — a client
 * retrying a revocation must not be told it failed — but it emits no second event.
 */
export async function revokeApiKey(
  tx: Tx,
  input: { readonly id: string; readonly revokedBy: string; readonly reason?: string },
): Promise<{ readonly key: ApiKeySummary; readonly alreadyRevoked: boolean }> {
  const reason = (input.reason ?? '').trim().slice(0, 500)
  const claimed = await tx<ApiKeyRow[]>`
    update api_keys
       set revoked_at = now(), revoked_by = ${input.revokedBy}, revoked_reason = ${reason}
     where id = ${input.id} and revoked_at is null
    returning ${tx.unsafe(SUMMARY_COLUMNS)}
  `
  const row = claimed[0]
  if (row) return { key: toSummary(row), alreadyRevoked: false }

  const existing = await tx<ApiKeyRow[]>`
    select ${tx.unsafe(SUMMARY_COLUMNS)} from api_keys where id = ${input.id}
  `
  const found = existing[0]
  if (!found) throw new NotFoundError('no such api key')
  return { key: toSummary(found), alreadyRevoked: true }
}

/** Revoke by the display string — the value an operator finds in a log line. See keys.ts. */
export async function revokeByDisplay(
  tx: Tx,
  input: { readonly display: string; readonly revokedBy: string; readonly reason?: string },
): Promise<{ readonly key: ApiKeySummary; readonly alreadyRevoked: boolean }> {
  const rows = await tx<{ id: string }[]>`select id from api_keys where display = ${input.display}`
  const row = rows[0]
  if (!row) throw new NotFoundError('no api key with that identifier')
  return revokeApiKey(tx, { ...input, id: row.id })
}

const USER_ACTOR =
  /^user:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/

/**
 * The person whose credential this is, or null when no person holds it.
 *
 * `created_by` is written as `actorOf(caller)` (`server.ts`), so it is `user:<uuid>` for a
 * developer who pressed the button and `service:<display>` for a key that minted a key. Only the
 * first names somebody, and the uuid is required rather than assumed: `activity` files a record
 * against `activity_records.user_id`, and a subject that is not a uuid is a value no feed query
 * can ever match — a record filed against a user who does not exist reads exactly like a record
 * that was delivered.
 *
 * **This reads a column, and `emitKeyIssued` two hundred lines up refuses to.** The difference is
 * what is being carried. `actor` is an `Actor`, a type the compiler proved on the way in and that
 * a column round-trip launders back to `string` — so that one is taken from the caller. This is an
 * IDENTIFIER, it is validated here at the point of use rather than trusted, and there is no caller
 * to take it from: on the erasure path the caller is `identity`, and the whole point is that the
 * owner is somebody else.
 */
export function ownerUserIdOf(createdBy: string): string | null {
  return USER_ACTOR.exec(createdBy)?.[1] ?? null
}

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`userId` IS WHOSE KEY IT WAS. `actor` IS WHO REVOKED IT. THEY ARE NOT THE SAME QUESTION.**
 *
 * Until this field existed, they were forced to be. Every consumer in the estate derives the owner
 * of an event from the ENVELOPE ACTOR when the payload names nobody — `activity`'s `userFromActor`
 * (`activity/src/classify.ts`) and `notify`'s `userIdOf` (`notify/src/catalogue.ts`) both
 * fall back to it — and that is right for the route at `server.ts`, where a developer presses
 * DELETE and the actor is that developer.
 *
 * It is wrong for the other caller, and wrong in the case that matters most. `server.ts`
 * handles `identity.organisation.deleted`: it suspends the organisation and revokes EVERY live key
 * it holds, as `service:identity`, because that IS who acted. So the actor named a service, both
 * consumers correctly answered "no user on this envelope", `activity` filed the record internal as
 * `api.key_revoked_by_platform` and `notify` answered `no_recipient`. A company's entire production
 * integration stopped at whatever hour identity processed the erasure and **nobody was told**.
 * Both consumers wrote the gap down and both refused to close it themselves, correctly: neither may
 * read a database to find out whose keys those were, so the fan-out has to come from the payload.
 *
 * ## Why one event per key, and not one event carrying every affected user
 *
 * `worlds/src/heraldry.ts` faced this fan-out and put the whole membership on one payload, because
 * a season has one seal and many victors. This is the opposite shape, for two reasons:
 *
 *   1. **This service could not build that list.** devplatform holds no membership table on
 *      purpose (`membership.ts`: "IDENTITY IS ASKED. NOTHING IS MIRRORED"), and it asks identity
 *      with the CALLER'S OWN token — which does not exist on an erasure the caller is a service.
 *      `api_keys.created_by` is the only user this service knows, and it is already on the row
 *      `revokeOrgKeys` returns.
 *   2. **A revoked key is per-key news whatever revoked it.** The registry keys this topic by
 *      `key_id` and `11-data-and-contract-strategy.md` names it as the estate's key-cache
 *      flush, so a per-key event has to exist regardless. Collapsing N keys into one event would
 *      break the flush to save a field.
 *
 * That answers the hazard heraldry records — one shared synthetic id let exactly one alliance
 * member win an insert and handed every other member a silent null — **structurally rather than by
 * a convention a consumer has to keep.** One event per key means one event id per key, the estate's
 * inbox dedupes on `(topic, event_id)`, and `notify`'s dedupe key for this rule is already
 * `api.key_revoked:<key_id>`. Two users' keys can never collide on either, so per-user idempotency
 * is not something the consumers must remember to do; it is what they already do.
 *
 * ## One payload shape, both callers
 *
 * The field is added HERE rather than at either call site, so `emitKeyRevoked` still has exactly
 * one payload shape. `micro-contracts` checked precisely that before registering this topic ("One
 * payload shape each", `contracts/packages/events/src/index.ts`) — a `TopicSpec` gives a topic
 * one `payloadType`, and a payload that differs by which path produced it is unregisterable by
 * construction, which is what made `identity.mfa.changed` impossible to adopt. `userId` is absent,
 * never null or empty, when no person holds the key: an absent field and a null read identically
 * to every consumer, and absent is the one that does not claim to have answered.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function emitKeyRevoked(emit: Emit, key: ApiKeySummary, actor: Actor): void {
  const owner = ownerUserIdOf(key.createdBy)
  emit({
    topic: TOPICS.keyRevoked,
    key: key.id,
    actor,
    payload: {
      keyId: key.id,
      projectId: key.projectId,
      environment: key.environment,
      display: key.display,
      lookupId: key.lookupId,
      reason: key.revokedReason ?? '',
      ...(owner === null ? {} : { userId: owner }),
    },
  })
}

/** Revoke every live key in an organisation. Used by the `identity.organisation.deleted` handler. */
export async function revokeOrgKeys(
  tx: Tx,
  orgId: string,
  revokedBy: string,
  reason: string,
): Promise<readonly ApiKeySummary[]> {
  const rows = await tx<ApiKeyRow[]>`
    update api_keys
       set revoked_at = now(), revoked_by = ${revokedBy}, revoked_reason = ${reason.slice(0, 500)}
     where revoked_at is null
       and project_id in (select id from projects where org_id = ${orgId})
    returning ${tx.unsafe(SUMMARY_COLUMNS)}
  `
  return rows.map(toSummary)
}

/* ------------------------------------------------------------------ authentication */

export type AuthOutcome =
  | { readonly ok: true; readonly key: ApiKeySummary; readonly orgId: string }
  | { readonly ok: false; readonly reason: KeyRefusal | 'org_suspended'; readonly display: string | null }

interface VerifyRow extends ApiKeyRow {
  readonly secret_algo: string
  readonly secret_salt: string
  readonly secret_hash: string
  readonly org_id: string
  readonly org_status: string
}

/**
 * Resolve a presented key string to the row that issued it, or to a refusal.
 *
 * **Every refusal answers the same 401 with the same message.** The `reason` is for this service's
 * own logs and for `devplatform_key_refusals_total`, and `server.ts` never renders it. A caller who
 * can tell `revoked` from `unknown` can tell "this account exists and someone noticed" from "this
 * key never existed", which is the difference between a dead end and a target.
 *
 * The constant-cost property is `keys.ts`'s and is proven there. What this function must not do is
 * put a cheap decision in front of it — so the row load is one query, its result is handed to
 * `verifyPresentedKey` as a callback, and the organisation status is applied to the *result*.
 */
export async function authenticateKey(
  sql: Db,
  presented: string,
  options: { readonly now?: Date; readonly kdf?: Kdf; readonly params?: ScryptParams } = {},
): Promise<AuthOutcome> {
  let loaded: VerifyRow | null = null

  const verification = await verifyPresentedKey(
    presented,
    async (lookupId) => {
      const rows = await sql<VerifyRow[]>`
        select k.id, k.project_id, k.environment_id, k.environment, k.service_account_id,
               k.display, k.lookup_id, k.name, k.scopes, k.created_by, k.created_at,
               k.last_used_at, k.expires_at, k.revoked_at, k.revoked_reason,
               k.secret_algo, k.secret_salt, k.secret_hash,
               p.org_id, o.status as org_status
          from api_keys k
          join projects p on p.id = k.project_id
          join developer_orgs o on o.id = p.org_id
         where k.lookup_id = ${lookupId}
      `
      loaded = rows[0] ?? null
      if (!loaded) return null
      const row: VerifiableKey = {
        algo: loaded.secret_algo,
        salt: loaded.secret_salt,
        hash: loaded.secret_hash,
        environment: loaded.environment === 'live' ? 'live' : 'test',
        revokedAt: loaded.revoked_at,
        expiresAt: loaded.expires_at,
      }
      return row
    },
    options,
  )

  if (!verification.ok) {
    const parsed = parseKey(presented)
    return {
      ok: false,
      reason: verification.reason,
      display: parsed ? keyDisplay(parsed.environment, parsed.lookupId) : null,
    }
  }

  // Narrowing: `loaded` is assigned inside the callback above, which has already run by here, but
  // TypeScript's control-flow analysis cannot see across the closure.
  const row = loaded as VerifyRow | null
  if (!row) return { ok: false, reason: 'unknown', display: null }

  if (row.org_status !== 'active') {
    // After the KDF, deliberately. A pre-check would answer in microseconds for a genuine key
    // belonging to a suspended organisation and hand back the fact that the key is genuine.
    return { ok: false, reason: 'org_suspended', display: row.display }
  }

  // A key hashed under a lower work factor is re-hashed the moment the plaintext is in hand, which
  // is this instant and no other. Best-effort: a failed re-hash must not fail an authentication
  // that already succeeded, and the next successful use will try again.
  if (verification.needsRehash) {
    const parsed = parseKey(presented)
    if (parsed) {
      const stored = await hashSecret(parsed.secret, options.params ?? CURRENT_PARAMS, options.kdf)
      await sql`
        update api_keys
           set secret_algo = ${stored.algo}, secret_salt = ${stored.salt}, secret_hash = ${stored.hash}
         where id = ${row.id} and secret_algo = ${row.secret_algo}
      `.catch(() => undefined)
    }
  }

  return { ok: true, key: toSummary(row), orgId: row.org_id }
}

/**
 * Record that a key was used.
 *
 * Deliberately separate from `authenticateKey` and deliberately not awaited on the hot path by the
 * server: an UPDATE per authenticated request serialises every concurrent caller of one key on one
 * row, which converts a read-heavy API into a single-row write contention benchmark. Coarsened to
 * one write a minute per key by the `where` clause, so a busy key writes 1,440 times a day rather
 * than millions.
 */
export async function touchLastUsed(sql: Db, keyId: string): Promise<void> {
  await sql`
    update api_keys set last_used_at = now()
     where id = ${keyId}
       and (last_used_at is null or last_used_at < now() - interval '1 minute')
  `
}

/**
 * What `GET /v1/keys/self` answers — the whoami this estate did not have.
 *
 * See the README: `identity/src/server.ts` refuses a service token on `GET /auth/me`, and an
 * API key is not a JWT at all, so identity could not answer this even if it wanted to. The service
 * that issued the credential is the service that can introspect it.
 */
export interface KeyIntrospection {
  readonly display: string
  readonly name: string
  readonly environment: KeyEnvironment
  readonly projectId: string
  readonly orgId: string
  readonly serviceAccountId: string | null
  readonly scopes: readonly string[]
  readonly createdAt: string
  readonly expiresAt: string | null
}

export function introspect(key: ApiKeySummary, orgId: string): KeyIntrospection {
  return {
    display: key.display,
    name: key.name,
    environment: key.environment,
    projectId: key.projectId,
    orgId,
    serviceAccountId: key.serviceAccountId,
    scopes: [...key.scopes],
    createdAt: key.createdAt.toISOString(),
    expiresAt: key.expiresAt ? key.expiresAt.toISOString() : null,
  }
}

/** A correlation id for one authenticated call, when the caller supplied none. */
export function newCallId(): string {
  return randomUUID()
}
