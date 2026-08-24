/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a separate
 * one-shot process — AD-17 and rule 7. It matters concretely here: below `SCHEMA_VERSION` the
 * `api_keys_slow_kdf_only` CHECK may not exist, and a service that could create it at boot is a
 * service that could start without it — which is a service that would happily write a SHA-256 hash
 * into the credential table.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IDENTITY IS A SOFT PROBE, NOT A HARD ONE, AND THAT IS DELIBERATE.**
 *
 * `07-dependency-map.md` makes identity a HARD dependency for developer organisation and
 * membership — and it is, for the console routes, which answer 503 when it is unreachable
 * (`membership.ts`). But `/internal/keys/verify` needs no identity at all: verifying a `cfk_…`
 * string is a row in this database and a scrypt run, and nothing else.
 *
 * That route is the one every OTHER service in the estate calls to authenticate a third-party
 * request. Making identity a hard readiness probe would take devplatform out of the load balancer
 * whenever identity had a bad minute — and take every public API request in the estate down with
 * it, for a dependency that route does not have. So: Postgres is hard, identity is soft, and a
 * degraded devplatform still authenticates keys.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module via `NODE_OPTIONS`,
 * which reads `OTEL_EXPORTER_OTLP_ENDPOINT` from the environment itself. That is why no `OTEL_*`
 * variable appears in `src/env.ts`.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql , networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, httpProbe, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics, scrapeRefresh } from './server.ts'
import { registerHandlers, rescheduleRecurring, sampleDeliveries, sampleQueue, seedRecurring } from './jobs.ts'
import { identityMembership } from './membership.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder secret has already
//    exited with a structured line naming the variable.

// 2. Telemetry, before anything that can fail, so a pool failure is a structured line rather than a
//    bare V8 stack the collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  // Said at boot, because a rotation that is half-finished looks exactly like a rotation that is
  // finished until somebody counts the secrets.
  ingestSecrets: env.ingestSecrets.length,
  defaultQuotaPerMinute: env.defaultQuotaPerMinute,
})

// 3. The database pool. Opened before the schema assertion (which is a query) and before the
//    Lifecycle (whose readiness probe closes over it).
const poolOptions = {
  max: env.databasePoolMax,
  onnotice: () => {},
}
const sql = postgres(env.databaseUrl, poolOptions)

// ── ONE HANDLE PER NETWORK THIS DEPLOYMENT SERVES ────────────────────────────────────────────
//
// `DEVPLATFORM_DATABASE_URL_TESTNET` unset is the single-network case, which is every deployment until the
// consolidation reaches this service. `networkSql` then holds one handle and REFUSES a testnet
// request rather than answering it out of mainnet rows — substituting would be a query that
// SUCCEEDS against the other estate and says nothing.
const sqlTestnet = env.databaseUrlTestnet ? postgres(env.databaseUrlTestnet, poolOptions) : undefined
const db = sql as unknown as Sql

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point.
try {
  await assertSchemaAtLeast(db, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report. See the header for why identity is soft.
const lifecycle = new Lifecycle({
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})
lifecycle.addProbe(
  postgresProbe('postgres', (signal) =>
    Promise.race([
      sql`select 1`,
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
      }),
    ]),
  ),
)
lifecycle.addProbe(httpProbe('identity', env.identityJwksUrl, { kind: 'soft' }))

// 6. The queue and the runner's dependencies.
const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId, leaseMs: 120_000 })

// 7. Routes. After the Lifecycle so the health handlers report real state.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const refresh = scrapeRefresh({ sql, metrics })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier,
  // The membership client dials identity's ORIGIN, derived from the issuer. There is no separate
  // variable for it: two URLs that must always name the same service are two URLs that will one day
  // disagree, and the failure that produces is authorisation checked against the wrong estate.
  membership: identityMembership({ baseUrl: new URL(env.identityIssuer).origin }),
  // The SELECTOR, not a handle — routes use `ctx.sql`, resolved once per request.
  sql: networkSql({
    mainnet: sql as unknown as RuntimeSql,
    ...(sqlTestnet ? { testnet: sqlTestnet as unknown as RuntimeSql } : {}),
  }),
  ...(env.singleNetwork ? { singleNetwork: env.singleNetwork as 'mainnet' | 'testnet' } : {}),
  producer: SERVICE,
  ingestSecrets: env.ingestSecrets,
  defaultQuotaPerMinute: env.defaultQuotaPerMinute,
  defaultQuotaPerMonth: env.defaultQuotaPerMonth,
  webhookRotationOverlapMinutes: env.webhookRotationOverlapMinutes,
  // Gauges are sampled at scrape time rather than on a timer. There is no `setInterval` in this
  // repository and CI greps for one — rule 8.
  beforeScrape: async () => {
    await refresh()
    await sampleQueue(queue, metrics)
    await sampleDeliveries(sql, metrics)
  },
})

// 8. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving.
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})
registerHandlers(runner, {
  sql,
  logger,
  metrics,
  signingSecret: env.outboxSigningSecret,
  retention: {
    usageEventDays: env.usageEventRetentionDays,
    usageRollupDays: env.usageRollupRetentionDays,
  },
  webhook: {
    deadlineMs: env.webhookDeadlineMs,
    maxAttempts: env.webhookMaxAttempts,
  },
})
await seedRecurring(queue)
runner.start()

// 9. Listen. Last of the construction steps: a socket that accepts before its dependencies exist is
//    a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 10. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic.
lifecycle.markReady()

// 11. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and DRAINS, then the pool closes with nothing left.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
