/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no `setInterval`
 * doing domain work in this repository and CI greps for one.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT AN UNLEASED TIMER WOULD COST *HERE*, SPECIFICALLY.**
 *
 * The rule is easy to read as tidiness. It is not, and each of this service's four jobs fails
 * differently without a lease:
 *
 *   `webhook.deliver`  Two replicas both read the pending set and both POST. The customer's
 *                      endpoint receives every event TWICE, and a subscriber that dedupes on
 *                      `cf-event-id` is a subscriber we hoped they wrote. The delivery claim below
 *                      is `for update skip locked` at the ROW level as well as under the job lease,
 *                      because one worker is allowed to run deliveries concurrently with itself —
 *                      the contended resource is a delivery row, not the queue.
 *
 *   `usage.rollup`     Two upserts race on `usage_rollups`' primary key. One of them wins, which is
 *                      harmless, and both spend a full aggregate scan, which is not.
 *
 *   `retention`        Two DELETEs over the same range. Harmless, and doubles the load of the
 *                      heaviest statement this service runs.
 *
 *   `outbox.relay`     Every internal subscriber receives every event twice. This is the one that
 *                      matters most, because `devplatform.key.revoked` is the event that
 *                      invalidates a cached key at the edge, and a doubled relay is a doubled
 *                      write amplification on the thing that must be fast during an incident.
 *
 * The lease key is `global` for the three that contend on a shared range, which is the rule
 * `@cloudsforge/jobs` states at `index.ts:16` — **the key names the contended resource, not the
 * row.**
 *
 * `jobs.test.ts` proves the property directly: two runners, one due job, exactly one execution.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { HttpClient } from '@cloudsforge/http'
import { type JobQueue, type JobRunner, type RunnerEvent } from '@cloudsforge/jobs'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import type { Db } from './outbox.ts'
import { createRelay } from './outbox.ts'
import { rollupUsage, sweepUsage } from './quotas.ts'
import { claimDeliveries, deliverOne, pruneRetiredSecrets, type DeliverDeps } from './webhooks.ts'

export const RELAY_KIND = 'outbox.relay'
export const DELIVER_KIND = 'webhook.deliver'
export const ROLLUP_KIND = 'usage.rollup'
export const RETENTION_KIND = 'retention'

export interface Recurring {
  readonly kind: string
  readonly key: string
  readonly everyMs: number
}

/**
 * Every recurring job.
 *
 * The relay and the delivery loop tick fast because both are on the path of a user-visible latency:
 * a revocation that takes a minute to reach the edge is a revocation that did not work, and a
 * webhook that arrives a minute after the event is a webhook a customer will complain about.
 * Retention ticks hourly because it is a bulk DELETE and nothing waits on it.
 */
export const RECURRING: readonly Recurring[] = Object.freeze([
  { kind: RELAY_KIND, key: 'global', everyMs: 1_000 },
  { kind: DELIVER_KIND, key: 'global', everyMs: 1_000 },
  { kind: ROLLUP_KIND, key: 'global', everyMs: 300_000 },
  { kind: RETENTION_KIND, key: 'global', everyMs: 3_600_000 },
])

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep', payload: {} })
  }
}

/**
 * Re-arm a recurring job from its completion event — the only moment the row is gone.
 *
 * A dead-lettered recurring job is deliberately NOT re-armed: the row stays, `jobs_dead_total`
 * climbs, and that is how an operator learns the thing scheduling everything else has stopped. A
 * silent re-arm would turn a permanently failing job into an invisible one.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKey = new Map(RECURRING.map((job) => [`${job.kind} ${job.key}`, job]))
  return (event) => {
    if (event.type !== 'completed' || !event.kind || !event.key) return
    const job = byKey.get(`${event.kind} ${event.key}`)
    if (!job) return
    void queue
      .enqueue({
        kind: job.kind,
        key: job.key,
        runAt: new Date(Date.now() + job.everyMs),
        onConflict: 'earliest',
        payload: {},
      })
      .catch((err: unknown) => logger.error('failed to re-arm recurring job', { kind: job.kind, err }))
  }
}

export interface Retention {
  readonly usageEventDays: number
  readonly usageRollupDays: number
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly metrics: Metrics
  readonly retention: Retention
  readonly signingSecret: string
  readonly webhook: {
    readonly deadlineMs: number
    readonly maxAttempts: number
    readonly batchSize?: number
    readonly leaseMs?: number
    /** Test seam. Production builds one `HttpClient` per subscriber origin. */
    readonly clientFor?: (url: string) => Pick<HttpClient, 'request'>
  }
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  runner.register(RELAY_KIND, createRelay({
    sql: deps.sql,
    logger: deps.logger,
    signingSecret: deps.signingSecret,
  }))

  runner.register(DELIVER_KIND, async (_job, ctx) => {
    const outcome = await deliverPending(deliverDeps(deps), {
      batchSize: deps.webhook.batchSize ?? 25,
      leaseMs: deps.webhook.leaseMs ?? 60_000,
      heartbeat: ctx.heartbeat,
      aborted: () => ctx.signal.aborted,
    })
    for (const [result, count] of outcome) {
      deps.metrics.increment('devplatform_webhook_deliveries_total', { outcome: result }, count)
    }
  })

  runner.register(ROLLUP_KIND, async () => {
    await rollupUsage(deps.sql)
  })

  runner.register(RETENTION_KIND, async () => {
    const swept = await sweepUsage(deps.sql, {
      eventDays: deps.retention.usageEventDays,
      rollupDays: deps.retention.usageRollupDays,
    })
    const secrets = await pruneRetiredSecrets(deps.sql)
    deps.logger.info('retention sweep', { ...swept, retiredSecrets: secrets })
  })

  return runner
}

/**
 * Build the delivery client factory.
 *
 * Cached for the life of the process so a circuit breaker accumulates state across ticks. A fresh
 * client per tick has a permanently closed circuit and hammers a subscriber that is already down —
 * which is how a customer's outage becomes this service's outage.
 */
function deliverDeps(deps: JobDeps): DeliverDeps {
  const clients = new Map<string, Pick<HttpClient, 'request'>>()
  const clientFor =
    deps.webhook.clientFor ??
    ((url: string) => {
      const origin = new URL(url).origin
      const existing = clients.get(origin)
      if (existing) return existing
      const client = new HttpClient({
        baseUrl: origin,
        name: `subscriber:${new URL(url).host}`,
        // Zero retries at this layer. The delivery row IS the retry mechanism, with its own backoff
        // and its own attempt ceiling, and stacking an in-request retry on top means one claimed
        // delivery can hold its lease for `retries × deadline` — long enough for a second worker to
        // claim the same row.
        defaultRetries: 0,
      })
      clients.set(origin, client)
      return client
    })
  return {
    sql: deps.sql,
    deadlineMs: deps.webhook.deadlineMs,
    maxAttempts: deps.webhook.maxAttempts,
    clientFor,
  }
}

/**
 * One pass of the delivery loop. Exported so a test can drive it without a runner.
 *
 * Returns a count by outcome rather than a total, because "delivered 25" and "abandoned 25" are
 * very different mornings and a single number hides which one happened.
 */
export async function deliverPending(
  deps: DeliverDeps,
  options: {
    readonly batchSize: number
    readonly leaseMs: number
    readonly heartbeat?: () => Promise<boolean>
    readonly aborted?: () => boolean
  },
): Promise<ReadonlyMap<string, number>> {
  const counts = new Map<string, number>()
  const due = await claimDeliveries(deps.sql, options.batchSize, options.leaseMs)
  for (const delivery of due) {
    if (options.aborted?.()) break
    const outcome = await deliverOne(deps, delivery)
    counts.set(outcome, (counts.get(outcome) ?? 0) + 1)
    // A long batch must not outlive the lease and hand the remaining rows to a second replica.
    await options.heartbeat?.()
  }
  return counts
}

/** Refresh the queue-depth gauges. Called at scrape time, never on a timer. */
export async function sampleQueue(queue: JobQueue, metrics: Metrics): Promise<void> {
  const stats = await queue.stats()
  metrics.set('jobs_pending', stats.pending)
  metrics.set('jobs_overdue', stats.overdue)
}

/** Pending webhook deliveries, by whether they are still retriable. Sampled at scrape time. */
export async function sampleDeliveries(sql: Db, metrics: Metrics): Promise<void> {
  const rows = await sql<{ pending: number; stuck: number }[]>`
    select count(*) filter (where delivered_at is null and next_attempt_at <= now() + interval '1 hour')::int as pending,
           count(*) filter (where delivered_at is null and next_attempt_at > now() + interval '1 hour')::int as stuck
      from webhook_deliveries
  `
  const row = rows[0]
  metrics.set('devplatform_webhook_pending', row?.pending ?? 0)
  // `stuck` is the abandoned set: `markFailed` pushes an exhausted delivery a year out rather than
  // deleting it, so a climbing gauge here is customers who are silently missing events.
  metrics.set('devplatform_webhook_abandoned', row?.stuck ?? 0)
}
