/**
 * Quotas and metered usage.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE COUNTER IS A ROW. AN IN-MEMORY COUNTER IS PER-REPLICA AND THEREFORE NOT A QUOTA.**
 *
 * The obvious implementation is a `Map<string, number>` in the process, reset on a timer. With one
 * replica it looks correct. With N replicas a customer on a 600/minute plan gets 600 × N, and the
 * number nobody can state is the one the sales page promised. It is also wrong in a subtler way
 * that survives a single replica: a deploy resets it, so the limit is "600 per minute, or per
 * deploy, whichever comes first".
 *
 * So the counter is `quota_windows`, and the increment is ONE statement:
 *
 *     update quota_windows set used_units = used_units + n
 *      where quota_id = … and window_start = … and used_units + n <= max_units
 *     returning used_units
 *
 * Postgres takes a row lock for the duration of the UPDATE, so two concurrent transactions
 * serialise on it: the second re-evaluates its `where` against the FIRST's committed value rather
 * than the value it read. No row returned means the limit was reached — by this caller or by the
 * one that beat it — and the two are the same answer. `quotas.test.ts` fires 40 concurrent requests
 * at a limit of 10 and asserts exactly 10 succeed; without the `where` clause that test yields
 * somewhere between 11 and 40 and is differently wrong every run.
 *
 * `quota_windows_within_limit` is the belt to that UPDATE's braces. If a future write path ever
 * increments without the guard, the CHECK refuses the row rather than allowing a silent overage.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **THERE IS NO MONEY HERE.** `usage_events` counts CALLS. There is no amount, no price and no
 * balance column anywhere in this file or the tables it touches — 04-domain-model §11 and the
 * estate rule. Metered usage that costs money is a `micro-billing` entitlement or a `micro-ledger`
 * entry, and a column named for an amount here would be the first row of a second ledger. CI greps
 * for one.
 *
 * **WHY `max_units` IS COPIED INTO THE WINDOW.** A quota raised mid-window applies to the NEXT
 * window, not retroactively to the one in progress. The alternative — joining `quotas` on every
 * increment — makes the hot path a two-table statement and makes "what was the limit when this
 * request was refused?" unanswerable after the fact. The copy is the audit trail.
 */

import type { Db, Emit, Tx } from './outbox.ts'
import { TOPICS } from './outbox.ts'
import { NotFoundError, ValidationError } from './orgs.ts'

/** The windows a quota may be counted over. `minute` is the burst control; `month` is the plan. */
export const PERIODS = Object.freeze(['minute', 'hour', 'day', 'month'] as const)
export type Period = (typeof PERIODS)[number]

export function isPeriod(value: string): value is Period {
  return (PERIODS as readonly string[]).includes(value)
}

/** The only meter today. A column rather than a constant so a second meter is a row, not a migration. */
export const API_REQUESTS = 'api_requests'

/**
 * The largest a quota may be, per period. **The same numbers are a CHECK — migration 9.**
 *
 * They are declared here as well so that a caller gets a 400 naming the ceiling rather than a 500
 * carrying 23514, and they are declared in the SCHEMA so that the bound survives a write path that
 * never comes through this function. `migrations.test.ts` fires the constraint and
 * `quotas.test.ts` asserts the two layers agree on the same number, which is the only thing that
 * stops them drifting apart.
 *
 * The values are not a judgement about what a plan should be. Each is the largest value this
 * service's own configuration already permits to be seeded into these rows (`env.ts` for a
 * minute window, `env.ts` for every longer one), so a legal configuration can never be refused
 * by the constraint guarding the rows it seeds.
 */
export const MAX_UNITS_CEILING: Readonly<Record<Period, number>> = Object.freeze({
  minute: 10_000_000,
  hour: 10_000_000_000,
  day: 10_000_000_000,
  month: 10_000_000_000,
})

export interface Quota {
  readonly id: string
  readonly projectId: string
  readonly environmentId: string
  readonly meter: string
  readonly period: Period
  readonly maxUnits: number
}

interface QuotaRow {
  readonly id: string
  readonly project_id: string
  readonly environment_id: string
  readonly meter: string
  readonly period: string
  readonly max_units: string | number
}

function toQuota(row: QuotaRow): Quota {
  return {
    id: row.id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    meter: row.meter,
    period: isPeriod(row.period) ? row.period : 'minute',
    // `bigint` arrives from postgres.js as a string. `Number` is exact to 2^53, and a quota above
    // nine quadrillion requests a month is not a number this service has to be right about.
    maxUnits: Number(row.max_units),
  }
}

/**
 * The start of the window a moment falls in.
 *
 * Computed here rather than in SQL so that the value is a parameter — which is what lets a test
 * drive two windows without waiting a minute, and what keeps the increment statement free of a
 * function call the planner would have to evaluate per row.
 */
export function windowStart(period: Period, at: Date): Date {
  const d = new Date(at.getTime())
  d.setUTCMilliseconds(0)
  d.setUTCSeconds(0)
  if (period === 'minute') return d
  d.setUTCMinutes(0)
  if (period === 'hour') return d
  d.setUTCHours(0)
  if (period === 'day') return d
  d.setUTCDate(1)
  return d
}

/**
 * Set a quota. Upsert on `(environment_id, meter, period)` — the natural key — so a plan change is
 * one statement and a retried plan change is the same statement.
 */
export async function setQuota(
  sql: Tx | Db,
  input: {
    readonly projectId: string
    readonly environmentId: string
    readonly meter?: string
    readonly period: Period
    readonly maxUnits: number
  },
): Promise<Quota> {
  if (!Number.isInteger(input.maxUnits) || input.maxUnits < 1) {
    // Zero is not expressible, and `quotas_max_positive` refuses it at the database too. A quota of
    // zero is a project that cannot make a request, which is a suspension — and a suspension is a
    // status on the organisation, not a limit on a meter.
    throw new ValidationError('maxUnits must be a whole number of at least 1; a quota of zero is a suspension, not a limit')
  }
  const ceiling = MAX_UNITS_CEILING[input.period]
  if (input.maxUnits > ceiling) {
    // The database refuses this too — `quotas_max_within_ceiling`, migration 9. Refused here as
    // well so the caller gets a 400 naming the number rather than a 500 carrying 23514.
    throw new ValidationError(
      `maxUnits for a ${input.period} quota may not exceed ${ceiling}; a limit above that is not a limit`,
    )
  }
  const rows = await sql<QuotaRow[]>`
    insert into quotas (project_id, environment_id, meter, period, max_units)
    values (${input.projectId}, ${input.environmentId}, ${input.meter ?? API_REQUESTS}, ${input.period}, ${input.maxUnits})
    on conflict (environment_id, meter, period)
      do update set max_units = excluded.max_units, updated_at = now()
    returning id, project_id, environment_id, meter, period, max_units
  `
  const row = rows[0]
  if (!row) throw new Error('quota upsert returned no row')
  return toQuota(row)
}

/**
 * One quota, by its natural key, or null.
 *
 * The read `PUT /v1/projects/:id/quotas` makes before it decides whether the request is a RAISE.
 * It is a separate function from `quotasFor` because the comparison has to be against exactly the
 * row the upsert is about to overwrite — one period, one meter — and a caller that filtered a list
 * would eventually filter it wrong.
 */
export async function findQuota(
  sql: Tx | Db,
  environmentId: string,
  period: Period,
  meter: string = API_REQUESTS,
): Promise<Quota | null> {
  const rows = await sql<QuotaRow[]>`
    select id, project_id, environment_id, meter, period, max_units
      from quotas
     where environment_id = ${environmentId} and meter = ${meter} and period = ${period}
  `
  const row = rows[0]
  return row ? toQuota(row) : null
}

export async function listQuotas(sql: Tx | Db, projectId: string): Promise<readonly Quota[]> {
  const rows = await sql<QuotaRow[]>`
    select id, project_id, environment_id, meter, period, max_units
      from quotas where project_id = ${projectId} order by environment_id, period
  `
  return rows.map(toQuota)
}

/** Give a new project the defaults. Called inside the project-creation transaction. */
export async function seedDefaultQuotas(
  tx: Tx,
  input: {
    readonly projectId: string
    readonly environmentIds: readonly string[]
    readonly perMinute: number
    readonly perMonth: number
  },
): Promise<void> {
  for (const environmentId of input.environmentIds) {
    await setQuota(tx, {
      projectId: input.projectId,
      environmentId,
      period: 'minute',
      maxUnits: input.perMinute,
    })
    await setQuota(tx, {
      projectId: input.projectId,
      environmentId,
      period: 'month',
      maxUnits: input.perMonth,
    })
  }
}

export type ConsumeOutcome =
  | { readonly allowed: true; readonly period: Period; readonly used: number; readonly limit: number }
  | { readonly allowed: false; readonly period: Period; readonly used: number; readonly limit: number }

/**
 * Consume `units` against ONE quota. The statement the whole file exists for.
 *
 * Two statements, not one, and the order matters: the window row is created with
 * `on conflict do nothing` so that N concurrent first-requests produce one row rather than N-1
 * errors, and only then is the guarded increment run. Merging them into a single upsert with the
 * limit in a `where` would silently insert a fresh row every time the guard failed, because
 * `on conflict … do update … where` skips the update but still counts the insert as handled.
 */
export async function consumeQuota(
  sql: Db | Tx,
  quota: Quota,
  units: number,
  at: Date = new Date(),
): Promise<ConsumeOutcome> {
  const start = windowStart(quota.period, at)

  await sql`
    insert into quota_windows (quota_id, window_start, used_units, max_units)
    values (${quota.id}, ${start}, 0, ${quota.maxUnits})
    on conflict (quota_id, window_start) do nothing
  `

  const updated = await sql<{ used_units: string | number; max_units: string | number }[]>`
    update quota_windows
       set used_units = used_units + ${units}, updated_at = now()
     where quota_id = ${quota.id}
       and window_start = ${start}
       and used_units + ${units} <= max_units
    returning used_units, max_units
  `
  const row = updated[0]
  if (row) {
    return {
      allowed: true,
      period: quota.period,
      used: Number(row.used_units),
      limit: Number(row.max_units),
    }
  }

  // Refused. Read back the current state so the caller can report how much was available — the
  // read is outside the guard and may therefore be a moment stale, which is correct: the REFUSAL is
  // authoritative, the number in the message is a courtesy.
  const current = await sql<{ used_units: string | number; max_units: string | number }[]>`
    select used_units, max_units from quota_windows
     where quota_id = ${quota.id} and window_start = ${start}
  `
  const state = current[0]
  return {
    allowed: false,
    period: quota.period,
    used: state ? Number(state.used_units) : 0,
    limit: state ? Number(state.max_units) : quota.maxUnits,
  }
}

export interface QuotaDecision {
  readonly allowed: boolean
  /** The window that refused, when one did. Null when every quota allowed. */
  readonly exceeded: ConsumeOutcome | null
  readonly outcomes: readonly ConsumeOutcome[]
}

/**
 * Consume against every quota on an environment.
 *
 * **The refusal is not rolled back, and that is deliberate.** If the minute window allows and the
 * month window refuses, the minute's increment stands. Compensating it would mean a transaction
 * around every metered request — real contention on the hot path — to make a counter of refused
 * requests one lower. A refused request DID consume rate-limiter capacity, and counting it is the
 * more honest of the two answers.
 */
export async function consumeAll(
  sql: Db | Tx,
  quotas: readonly Quota[],
  units = 1,
  at: Date = new Date(),
): Promise<QuotaDecision> {
  const outcomes: ConsumeOutcome[] = []
  for (const quota of quotas) {
    const outcome = await consumeQuota(sql, quota, units, at)
    outcomes.push(outcome)
    if (!outcome.allowed) return { allowed: false, exceeded: outcome, outcomes }
  }
  return { allowed: true, exceeded: null, outcomes }
}

/** Every quota that applies to an environment, for the meter given. */
export async function quotasFor(
  sql: Db | Tx,
  environmentId: string,
  meter = API_REQUESTS,
): Promise<readonly Quota[]> {
  const rows = await sql<QuotaRow[]>`
    select id, project_id, environment_id, meter, period, max_units
      from quotas where environment_id = ${environmentId} and meter = ${meter}
     order by max_units
  `
  return rows.map(toQuota)
}

export function emitQuotaExceeded(emit: Emit, quota: Quota, outcome: ConsumeOutcome): void {
  emit({
    topic: TOPICS.quotaExceeded,
    key: quota.environmentId,
    payload: {
      projectId: quota.projectId,
      environmentId: quota.environmentId,
      meter: quota.meter,
      period: outcome.period,
      used: outcome.used,
      limit: outcome.limit,
    },
  })
}

/* ------------------------------------------------------------------ usage */

export interface UsageEvent {
  readonly projectId: string
  readonly environmentId: string
  readonly apiKeyId: string | null
  readonly route: string
  readonly method: string
  readonly status: number
}

/**
 * Record one metered call.
 *
 * A plain INSERT with no unique constraint, on purpose: two identical calls a millisecond apart are
 * two calls, and deduplicating usage would under-report exactly the customer who is using the
 * platform hardest. Idempotency belongs on operations that create an artefact; a usage row is an
 * observation.
 */
export async function recordUsage(sql: Db | Tx, event: UsageEvent): Promise<void> {
  await sql`
    insert into usage_events (project_id, environment_id, api_key_id, route, method, status)
    values (${event.projectId}, ${event.environmentId}, ${event.apiKeyId}, ${event.route},
            ${event.method}, ${event.status})
  `
}

export interface UsageRollup {
  readonly environmentId: string
  readonly route: string
  readonly bucket: Date
  readonly calls: number
  readonly errors: number
}

/**
 * Fold raw events into hourly buckets.
 *
 * Re-runs over the last few hours rather than only the newest: the current hour is incomplete every
 * time it is written, so the upsert has to CORRECT it rather than assume it is final. The rollups
 * are what survive retention — 11-data-and-contract-strategy.md commits to notifying every
 * project that called an endpoint in the last 90 days before it is removed, and raw events are kept
 * for 35. That question is answerable only from this table.
 */
export async function rollupUsage(sql: Db, hours = 3): Promise<number> {
  const result = (await sql`
    insert into usage_rollups (project_id, environment_id, route, bucket, calls, errors)
    select project_id,
           environment_id,
           route,
           date_trunc('hour', occurred_at)                        as bucket,
           count(*)::bigint                                       as calls,
           count(*) filter (where status >= 400)::bigint          as errors
      from usage_events
     where occurred_at >= date_trunc('hour', now() - make_interval(hours => ${hours}))
     group by project_id, environment_id, route, bucket
    on conflict (environment_id, route, bucket)
      do update set calls = excluded.calls, errors = excluded.errors
  `) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}

export async function listUsage(
  sql: Db | Tx,
  projectId: string,
  options: { readonly since?: Date; readonly limit?: number } = {},
): Promise<readonly UsageRollup[]> {
  const since = options.since ?? new Date(Date.now() - 7 * 24 * 3_600_000)
  const limit = Math.min(Math.max(options.limit ?? 200, 1), 1_000)
  const rows = await sql<
    {
      environment_id: string
      route: string
      bucket: Date
      calls: string | number
      errors: string | number
    }[]
  >`
    select environment_id, route, bucket, calls, errors
      from usage_rollups
     where project_id = ${projectId} and bucket >= ${since}
     order by bucket desc
     limit ${limit}
  `
  return rows.map((row) => ({
    environmentId: row.environment_id,
    route: row.route,
    bucket: row.bucket,
    calls: Number(row.calls),
    errors: Number(row.errors),
  }))
}

/** The live window state for an environment, for the console and for `GET /v1/quotas`. */
export async function currentUsage(
  sql: Db | Tx,
  environmentId: string,
  at: Date = new Date(),
): Promise<ReadonlyArray<{ period: Period; used: number; limit: number }>> {
  const quotas = await quotasFor(sql, environmentId)
  const out: Array<{ period: Period; used: number; limit: number }> = []
  for (const quota of quotas) {
    const rows = await sql<{ used_units: string | number }[]>`
      select used_units from quota_windows
       where quota_id = ${quota.id} and window_start = ${windowStart(quota.period, at)}
    `
    out.push({
      period: quota.period,
      used: rows[0] ? Number(rows[0].used_units) : 0,
      limit: quota.maxUnits,
    })
  }
  return out
}

/**
 * Delete what is past its horizon.
 *
 * `quota_windows` is pruned on a fixed horizon rather than a configured one: a closed window is a
 * counter nothing will ever read again, and keeping a month of them is enough for an operator to
 * answer "was this customer throttled last week?".
 */
export async function sweepUsage(
  sql: Db,
  retention: { readonly eventDays: number; readonly rollupDays: number },
): Promise<{ events: number; rollups: number; windows: number }> {
  const events = await affected(
    sql`delete from usage_events where occurred_at < now() - make_interval(days => ${retention.eventDays})`,
  )
  const rollups = await affected(
    sql`delete from usage_rollups where bucket < now() - make_interval(days => ${retention.rollupDays})`,
  )
  const windows = await affected(
    sql`delete from quota_windows where window_start < now() - interval '35 days'`,
  )
  return { events, rollups, windows }
}

async function affected(promise: Promise<unknown>): Promise<number> {
  const result = (await promise) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}

/** Resolve an environment to the project that owns it. Used by the metering middleware. */
export async function environmentOwner(
  sql: Db | Tx,
  environmentId: string,
): Promise<{ projectId: string } | null> {
  const rows = await sql<{ project_id: string }[]>`
    select project_id from environments where id = ${environmentId}
  `
  const row = rows[0]
  if (!row) throw new NotFoundError('no such environment')
  return { projectId: row.project_id }
}
