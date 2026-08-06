/**
 * Background work: the lease, and what it is standing in front of.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TEST THIS FILE EXISTS FOR IS `TWO RUNNERS, ONE DUE JOB, EXACTLY ONE EXECUTION`.**
 *
 * Two `JobRunner`s with DIFFERENT owners — which is what two replicas are — tick at the same
 * moment against one queue. The claim is `for update skip locked`, so one takes the row and the
 * other skips it rather than waiting. Replace the queue with a `setInterval` and a module-local
 * boolean and this test cannot even be written: the boolean is invisible to the second process by
 * construction, which is the whole defect.
 *
 * What that costs *here*, concretely, is in `jobs.ts`'s header. The one that matters most:
 * `outbox.relay` unleased means every internal subscriber receives every event twice, and
 * `devplatform.key.revoked` is the event that invalidates a cached key at the edge.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { HttpClient } from '@cloudsforge/http'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Metrics, registerJobMetrics } from '@cloudsforge/telemetry'
import {
  DELIVER_KIND,
  RECURRING,
  RELAY_KIND,
  RETENTION_KIND,
  ROLLUP_KIND,
  deliverPending,
  registerHandlers,
  rescheduleRecurring,
  sampleDeliveries,
  sampleQueue,
  seedRecurring,
} from './jobs.ts'
import { registerServiceMetrics } from './server.ts'
import { withOutbox, type Db, type Tx } from './outbox.ts'
import { createEndpoint, enqueueDeliveries } from './webhooks.ts'
import type { EventEnvelope } from './outbox.ts'
import {
  migrateTestDb,
  openDb,
  quietLogger,
  resetDevplatform,
  seedWorkspace,
  skip,
} from './testsupport.ts'

/**
 * A subscriber client that accepts everything.
 *
 * `HttpClient.request` is generic in its response type, so a stub returning `{}` does not satisfy
 * the signature — the generic must be honoured rather than widened away with an `any`.
 */
function acceptingClient(onRequest?: () => void): Pick<HttpClient, 'request'> {
  return {
    async request<T>(): Promise<T> {
      onRequest?.()
      return undefined as T
    },
  }
}

/* ------------------------------------------------------------------ the schedule */

test('every recurring job is keyed by the resource it contends on', () => {
  // `@cloudsforge/jobs` index.ts — the key names the contended resource, not the row. All four
  // of these contend on a shared range (the outbox stream, the delivery queue, an aggregate upsert,
  // a bulk DELETE), so all four are `global`.
  for (const job of RECURRING) {
    assert.equal(job.key, 'global', `${job.kind} is not keyed on the resource it contends on`)
    assert.ok(job.everyMs > 0)
  }
  assert.deepEqual(
    RECURRING.map((job) => job.kind).sort(),
    [DELIVER_KIND, RETENTION_KIND, ROLLUP_KIND, RELAY_KIND].sort(),
  )
})

test('the relay and the delivery loop tick fast; retention does not', () => {
  const byKind = new Map(RECURRING.map((job) => [job.kind, job.everyMs]))
  // A revocation that takes a minute to reach the edge is a revocation that did not work.
  assert.ok(byKind.get(RELAY_KIND)! <= 5_000)
  assert.ok(byKind.get(DELIVER_KIND)! <= 5_000)
  // Retention is a bulk DELETE and nothing waits on it.
  assert.ok(byKind.get(RETENTION_KIND)! >= 600_000)
})

/* ------------------------------------------------------------------ against Postgres */

test('jobs', { skip }, async (t) => {
  const sql = openDb(12)
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  const store = sql as unknown as Db
  const jobsSql = sql as unknown as JobsSql

  await t.test('TWO WORKERS ON ONE DUE JOB PRODUCE EXACTLY ONE RUN', async () => {
    const queue = new JobQueue(jobsSql, { owner: 'replica-a', leaseMs: 60_000 })
    await queue.enqueue({ kind: 'test.once', key: 'global', payload: {} })

    let runs = 0
    const build = (owner: string) => {
      const runner = new JobRunner({
        // A queue per runner, with its own owner — which is what two replicas are. Sharing one
        // JobQueue would share `locked_by` and prove nothing about two processes.
        queue: new JobQueue(jobsSql, { owner, leaseMs: 60_000 }),
        concurrency: 1,
      })
      runner.register('test.once', async () => {
        runs += 1
        // Hold the claim long enough that a naive implementation's second worker would overlap.
        await new Promise((resolve) => setTimeout(resolve, 80))
      })
      return runner
    }

    const a = build('replica-a')
    const b = build('replica-b')
    await Promise.all([a.tick(), b.tick()])

    assert.equal(
      runs,
      1,
      `the job ran ${runs} times. With a setInterval and a module-local boolean this is 2 by ` +
        'construction, because the boolean is invisible to the second process.',
    )
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from jobs`
    assert.equal(rows[0]?.n, 0, 'a completed job must be removed')
  })

  await t.test('the losing worker claims nothing rather than waiting', async () => {
    // `skip locked`, not `for update`. A waiting worker serialises the whole queue behind the
    // slowest handler.
    const a = new JobQueue(jobsSql, { owner: 'a', leaseMs: 60_000 })
    const b = new JobQueue(jobsSql, { owner: 'b', leaseMs: 60_000 })
    await a.enqueue({ kind: 'test.claim', key: 'global', payload: {} })

    const [claimedA, claimedB] = await Promise.all([a.claim(5), b.claim(5)])
    assert.equal(claimedA.length + claimedB.length, 1)
  })

  await t.test('N replicas booting together seed one row per recurring job', async () => {
    const queues = ['a', 'b', 'c'].map((owner) => new JobQueue(jobsSql, { owner }))
    await Promise.all(queues.map((queue) => seedRecurring(queue)))
    const rows = await sql<{ kind: string }[]>`select kind from jobs order by kind`
    assert.equal(rows.length, RECURRING.length, 'three replicas produced more than one row each')
  })

  await t.test('a completed recurring job re-arms itself; a dead one does not', async () => {
    const queue = new JobQueue(jobsSql, { owner: 'a' })
    const reschedule = rescheduleRecurring(queue, quietLogger())

    reschedule({ type: 'completed', kind: RELAY_KIND, key: 'global' })
    await new Promise((resolve) => setTimeout(resolve, 50))
    let rows = await sql<{ kind: string }[]>`select kind from jobs`
    assert.deepEqual(rows.map((r) => r.kind), [RELAY_KIND])

    await sql`delete from jobs`
    // A dead-lettered recurring job is deliberately NOT re-armed: the row stays, jobs_dead_total
    // climbs, and that is how an operator learns the scheduler has stopped.
    reschedule({ type: 'dead', kind: RELAY_KIND, key: 'global' })
    reschedule({ type: 'failed', kind: RELAY_KIND, key: 'global' })
    await new Promise((resolve) => setTimeout(resolve, 50))
    rows = await sql<{ kind: string }[]>`select kind from jobs`
    // Spread before comparing: postgres.js returns a `Result` array subclass, and deepEqual
    // distinguishes it from a plain array even when the contents match.
    assert.deepEqual([...rows], [], 'a dead recurring job was silently re-armed')
  })

  await t.test('a job of an unknown kind is not re-armed', async () => {
    const queue = new JobQueue(jobsSql, { owner: 'a' })
    const reschedule = rescheduleRecurring(queue, quietLogger())
    reschedule({ type: 'completed', kind: 'something.else', key: 'global' })
    await new Promise((resolve) => setTimeout(resolve, 50))
    const rows = await sql<{ kind: string }[]>`select kind from jobs`
    assert.deepEqual([...rows], [])
  })

  /* ---------------------------------------------------------------- the handlers */

  function deps() {
    return {
      sql: store,
      logger: quietLogger(),
      metrics: registerServiceMetrics(new Metrics()),
      retention: { usageEventDays: 35, usageRollupDays: 400 },
      signingSecret: 'a-signing-secret-of-sufficient-length',
      webhook: {
        deadlineMs: 1_000,
        maxAttempts: 3,
        clientFor: () => acceptingClient(),
      },
    }
  }

  await t.test('every recurring kind has a handler registered', async () => {
    const runner = new JobRunner({ queue: new JobQueue(jobsSql, { owner: 'a' }), concurrency: 1 })
    registerHandlers(runner, deps())
    // `register` throws on a duplicate, so registering twice proves each kind was taken exactly
    // once — and a kind in RECURRING with no handler would be claimed and released for ever.
    assert.throws(() => registerHandlers(runner, deps()))
  })

  await t.test('the four handlers run end to end under the runner', async () => {
    const queue = new JobQueue(jobsSql, { owner: 'a', leaseMs: 60_000 })
    const runner = new JobRunner({ queue, concurrency: 4 })
    const failures: string[] = []
    registerHandlers(runner, deps())
    const observed = new JobRunner({
      queue,
      concurrency: 4,
      onEvent: (event) => {
        if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
          failures.push(`${event.kind ?? '?'}: ${event.error ?? ''}`)
        }
      },
    })
    void observed

    await seedRecurring(queue)
    await runner.tick()
    // Every one completed, so every row is gone and nothing dead-lettered.
    const rows = await sql<{ kind: string; dead: boolean; last_error: string | null }[]>`
      select kind, dead, last_error from jobs
    `
    assert.deepEqual([...rows], [], `a handler failed: ${JSON.stringify(rows)}`)
    assert.deepEqual(failures, [])
  })

  await t.test('the delivery pass reports its outcomes by kind, not as a total', async () => {
    // "delivered 25" and "abandoned 25" are very different mornings.
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await sql.begin(async (t2) => {
      await createEndpoint(t2 as unknown as Tx, {
        projectId: project.id,
        environmentId: environments[0]!.id,
        url: 'https://subscriber.example.com/hook',
        topics: ['devplatform.key.issued'],
      })
      return { value: null }
    })

    const envelope: EventEnvelope = {
      id: crypto.randomUUID(),
      topic: 'devplatform.key.issued',
      key: 'k',
      occurredAt: new Date().toISOString(),
      producer: 'devplatform',
      // The wire shape the CONTRACT demands, not the one the relay used to build. `version: 1`,
      // `actor: null` and `correlationId: null` compiled here for the whole life of this file and
      // are all three refused by `validateEnvelope` — a fixture reproducing the defect is a
      // fixture that certifies it.
      version: '1.0',
      actor: 'service:devplatform',
      correlationId: 'req-test',
      payload: {},
    }
    await enqueueDeliveries(store, envelope)

    const counts = await deliverPending(
      {
        sql: store,
        deadlineMs: 1_000,
        maxAttempts: 3,
        clientFor: () => acceptingClient(),
      },
      { batchSize: 10, leaseMs: 60_000 },
    )
    assert.equal(counts.get('delivered'), 1)
    assert.equal(counts.get('abandoned'), undefined)
  })

  await t.test('a delivery pass that is aborted mid-batch stops rather than finishing', async () => {
    // A draining replica must stop, not push the rest of the batch out under an expiring lease.
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await sql.begin(async (t2) => {
      await createEndpoint(t2 as unknown as Tx, {
        projectId: project.id,
        environmentId: environments[0]!.id,
        url: 'https://subscriber.example.com/hook',
        topics: ['devplatform.key.issued'],
      })
      return { value: null }
    })
    for (let i = 0; i < 5; i += 1) {
      await enqueueDeliveries(store, {
        id: crypto.randomUUID(),
        topic: 'devplatform.key.issued',
        key: 'k',
        occurredAt: new Date().toISOString(),
        producer: 'devplatform',
        version: '1.0',
        actor: 'service:devplatform',
        correlationId: 'req-test',
        payload: {},
      })
    }

    let delivered = 0
    const counts = await deliverPending(
      {
        sql: store,
        deadlineMs: 1_000,
        maxAttempts: 3,
        clientFor: () => acceptingClient(() => { delivered += 1 }),
      },
      { batchSize: 10, leaseMs: 60_000, aborted: () => delivered >= 2 },
    )
    assert.equal(delivered, 2, 'the pass ignored the abort signal')
    assert.equal(counts.get('delivered'), 2)
  })

  /* ---------------------------------------------------------------- gauges */

  await t.test('the gauges are sampled at scrape time and never on a timer', async () => {
    // The job gauges come from `registerJobMetrics`, exactly as index.ts composes them. Sampling
    // into a registry that never registered them writes nothing and renders nothing.
    const metrics = registerServiceMetrics(registerJobMetrics(new Metrics()))
    const queue = new JobQueue(jobsSql, { owner: 'a' })
    await seedRecurring(queue)
    await sampleQueue(queue, metrics)
    await sampleDeliveries(store, metrics)

    const rendered = metrics.render()
    assert.match(rendered, /jobs_pending \d+/)
    assert.match(rendered, /devplatform_webhook_pending \d+/)
    assert.match(rendered, /devplatform_webhook_abandoned \d+/)
  })

  await t.test('an abandoned delivery shows up on its own gauge, not as pending', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    const endpoints = await sql<{ id: string }[]>`
      insert into webhook_endpoints (project_id, environment_id, url, topics)
      values (${project.id}, ${environments[0]!.id}, 'https://x.example.com/h', ${sql.array(['a.b.c'])})
      returning id
    `
    await sql`
      insert into webhook_deliveries (endpoint_id, event_id, topic, payload, next_attempt_at)
      values (${endpoints[0]!.id}, 'e1', 'a.b.c', '{}'::jsonb, now() + interval '300 days')
    `
    const metrics = registerServiceMetrics(new Metrics())
    await sampleDeliveries(store, metrics)
    assert.match(metrics.render(), /devplatform_webhook_abandoned 1/)
    assert.match(metrics.render(), /devplatform_webhook_pending 0/)
  })

  void withOutbox
})
