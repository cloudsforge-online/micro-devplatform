/**
 * Quotas, and the race.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TEST THIS FILE EXISTS FOR IS `40 CONCURRENT REQUESTS AGAINST A LIMIT OF 10`.**
 *
 * It is written so that the tempting implementation fails it. Replace the guarded UPDATE with a
 * read-then-write —
 *
 *     const used = await read(); if (used < max) await write(used + 1)
 *
 * — and this test yields somewhere between 11 and 40, differently every run. Replace it with an
 * in-process counter and it passes here and fails in production the moment there are two replicas,
 * which is the failure mode this whole file is arranged to make visible in CI instead.
 *
 * The connection pool is opened wide on purpose. With `max: 1` every "concurrent" request would
 * queue on one connection and serialise in the CLIENT, so the test would pass without the database
 * guard doing anything — a green test proving nothing, which is worse than no test.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  API_REQUESTS,
  MAX_UNITS_CEILING,
  consumeAll,
  consumeQuota,
  currentUsage,
  findQuota,
  listQuotas,
  listUsage,
  quotasFor,
  recordUsage,
  rollupUsage,
  seedDefaultQuotas,
  setQuota,
  sweepUsage,
  windowStart,
  type Quota,
} from './quotas.ts'
import { ValidationError } from './orgs.ts'
import type { Db, Tx } from './outbox.ts'
import { migrateTestDb, openDb, resetDevplatform, seedWorkspace, skip } from './testsupport.ts'

/* ------------------------------------------------------------------ window arithmetic */

test('a window start truncates to its period, in UTC', () => {
  const at = new Date('2026-08-01T13:47:23.456Z')
  assert.equal(windowStart('minute', at).toISOString(), '2026-08-01T13:47:00.000Z')
  assert.equal(windowStart('hour', at).toISOString(), '2026-08-01T13:00:00.000Z')
  assert.equal(windowStart('day', at).toISOString(), '2026-08-01T00:00:00.000Z')
  assert.equal(windowStart('month', at).toISOString(), '2026-08-01T00:00:00.000Z')
})

test('two moments in one minute share a window; two minutes do not', () => {
  const a = new Date('2026-08-01T13:47:00.000Z')
  const b = new Date('2026-08-01T13:47:59.999Z')
  const c = new Date('2026-08-01T13:48:00.000Z')
  assert.deepEqual(windowStart('minute', a), windowStart('minute', b))
  assert.notDeepEqual(windowStart('minute', a), windowStart('minute', c))
})

test('a month window starts on the first, not on the same day', () => {
  assert.equal(windowStart('month', new Date('2026-08-31T23:59:59Z')).toISOString(), '2026-08-01T00:00:00.000Z')
})

/* ------------------------------------------------------------------ against Postgres */

test('quotas', { skip }, async (t) => {
  // Wide on purpose. See the file header: a narrow pool serialises in the client and the test
  // passes without the database guard doing anything.
  const sql = openDb(24)
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  const store = sql as unknown as Db

  async function workspaceWithQuota(maxUnits: number, period: 'minute' | 'month' = 'minute') {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} and name = 'live'
    `
    const environmentId = environments[0]!.id
    const quota = await setQuota(store, { projectId: project.id, environmentId, period, maxUnits })
    return { projectId: project.id, environmentId, quota }
  }

  /* ---------------------------------------------------------------- the race */

  await t.test('CONCURRENT REQUESTS CANNOT EXCEED A QUOTA', async () => {
    const { quota } = await workspaceWithQuota(10)

    const outcomes = await Promise.all(
      Array.from({ length: 40 }, () => consumeQuota(store, quota, 1)),
    )
    const allowed = outcomes.filter((outcome) => outcome.allowed).length

    assert.equal(
      allowed,
      10,
      `${allowed} of 40 concurrent requests were allowed against a limit of 10. A read-then-write ` +
        'increment yields a number between 11 and 40 here, differently every run.',
    )

    // And the counter agrees with the answers given.
    const rows = await sql<{ used_units: string }[]>`
      select used_units from quota_windows where quota_id = ${quota.id}
    `
    assert.equal(Number(rows[0]?.used_units), 10)
  })

  await t.test('the race holds when every request is its own window-creating first request', async () => {
    // The `insert … on conflict do nothing` runs concurrently too. Without it, N concurrent
    // first-requests produce N-1 unique-violation errors instead of one row.
    const { quota } = await workspaceWithQuota(5)
    const outcomes = await Promise.all(Array.from({ length: 20 }, () => consumeQuota(store, quota, 1)))
    assert.equal(outcomes.filter((o) => o.allowed).length, 5)
    const rows = await sql<{ n: number }[]>`
      select count(*)::int as n from quota_windows where quota_id = ${quota.id}
    `
    assert.equal(rows[0]?.n, 1, 'concurrent first requests created more than one window row')
  })

  await t.test('a refusal reports how much was available', async () => {
    const { quota } = await workspaceWithQuota(2)
    await consumeQuota(store, quota, 1)
    await consumeQuota(store, quota, 1)
    const refused = await consumeQuota(store, quota, 1)
    assert.equal(refused.allowed, false)
    assert.equal(refused.used, 2)
    assert.equal(refused.limit, 2)
    assert.equal(refused.period, 'minute')
  })

  await t.test('a refused request does not increment the counter', async () => {
    const { quota } = await workspaceWithQuota(1)
    await consumeQuota(store, quota, 1)
    await consumeQuota(store, quota, 1)
    await consumeQuota(store, quota, 1)
    const rows = await sql<{ used_units: string }[]>`
      select used_units from quota_windows where quota_id = ${quota.id}
    `
    assert.equal(Number(rows[0]?.used_units), 1, 'a refusal still incremented')
  })

  await t.test('a multi-unit consume that would exceed the limit is refused whole', async () => {
    // Not partially applied. Allowing 3 of a requested 5 would mean a caller believing it had
    // reserved 5 units of capacity it does not hold.
    const { quota } = await workspaceWithQuota(10)
    await consumeQuota(store, quota, 8)
    const refused = await consumeQuota(store, quota, 5)
    assert.equal(refused.allowed, false)
    assert.equal(refused.used, 8)
  })

  await t.test('a consume of exactly the remaining capacity is allowed', async () => {
    const { quota } = await workspaceWithQuota(10)
    await consumeQuota(store, quota, 8)
    const allowed = await consumeQuota(store, quota, 2)
    assert.equal(allowed.allowed, true)
    assert.equal(allowed.used, 10)
  })

  await t.test('a new window starts empty', async () => {
    const { quota } = await workspaceWithQuota(2)
    const first = new Date('2026-08-01T10:00:30Z')
    const second = new Date('2026-08-01T10:01:30Z')
    await consumeQuota(store, quota, 2, first)
    assert.equal((await consumeQuota(store, quota, 1, first)).allowed, false)
    assert.equal((await consumeQuota(store, quota, 1, second)).allowed, true, 'the next minute was not fresh')
  })

  await t.test('RAISING A QUOTA APPLIES TO THE NEXT WINDOW, NOT THE ONE IN PROGRESS', async () => {
    // `max_units` is copied into the window row. Joining `quotas` on every increment would make the
    // hot path a two-table statement and make "what was the limit when this was refused?"
    // unanswerable after the fact. The copy is the audit trail.
    const { projectId, environmentId, quota } = await workspaceWithQuota(2)
    const now = new Date('2026-08-01T10:00:30Z')
    await consumeQuota(store, quota, 2, now)

    const raised = await setQuota(store, { projectId, environmentId, period: 'minute', maxUnits: 100 })
    assert.equal(raised.id, quota.id, 'raising a quota created a second row')
    assert.equal((await consumeQuota(store, raised, 1, now)).allowed, false, 'the in-progress window was widened')

    const next = new Date('2026-08-01T10:01:30Z')
    assert.equal((await consumeQuota(store, raised, 50, next)).allowed, true)
  })

  /* ---------------------------------------------------------------- several quotas */

  await t.test('every quota on an environment must allow, and the first refusal stops the rest', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} and name = 'live'
    `
    const environmentId = environments[0]!.id
    await setQuota(store, { projectId: project.id, environmentId, period: 'minute', maxUnits: 100 })
    await setQuota(store, { projectId: project.id, environmentId, period: 'month', maxUnits: 3 })

    const quotas = await quotasFor(store, environmentId)
    // Ordered by max_units ascending, so the tightest is consulted first — which is what makes the
    // early return cheap rather than merely correct.
    assert.deepEqual(quotas.map((q) => q.period), ['month', 'minute'])

    for (let i = 0; i < 3; i += 1) {
      assert.equal((await consumeAll(store, quotas)).allowed, true)
    }
    const refused = await consumeAll(store, quotas)
    assert.equal(refused.allowed, false)
    assert.equal(refused.exceeded?.period, 'month')
    assert.equal(refused.outcomes.length, 1, 'the minute quota was consumed after the month refused')
  })

  await t.test('seedDefaultQuotas gives a project both periods on both environments', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id}
    `
    await sql.begin(async (t) => {
      await seedDefaultQuotas(t as unknown as Tx, {
        projectId: project.id,
        environmentIds: environments.map((e) => e.id),
        perMinute: 600,
        perMonth: 1_000_000,
      })
      return { value: null }
    })
    const quotas = await listQuotas(store, project.id)
    assert.equal(quotas.length, 4, 'two environments times two periods')
    assert.deepEqual([...new Set(quotas.map((q) => q.period))].sort(), ['minute', 'month'])
  })

  await t.test('a quota of zero is refused before it reaches the database', async () => {
    const { projectId, environmentId } = await workspaceWithQuota(1)
    for (const maxUnits of [0, -1, 1.5]) {
      await assert.rejects(
        () => setQuota(store, { projectId, environmentId, period: 'minute', maxUnits }),
        ValidationError,
        `maxUnits=${maxUnits} was accepted`,
      )
    }
  })

  await t.test('A QUOTA ABOVE ITS CEILING IS REFUSED BEFORE IT REACHES THE DATABASE', async () => {
    // The database refuses it too — `quotas_max_within_ceiling`, proven in `migrations.test.ts`.
    // Here, so that a caller gets a 400 naming the number rather than a 500 carrying 23514.
    const { projectId, environmentId } = await workspaceWithQuota(1)
    for (const period of ['minute', 'hour', 'day', 'month'] as const) {
      const ceiling = MAX_UNITS_CEILING[period]
      await assert.rejects(
        () => setQuota(store, { projectId, environmentId, period, maxUnits: ceiling + 1 }),
        (err: unknown) => err instanceof ValidationError && String(err).includes(String(ceiling)),
        `a ${period} quota of ${ceiling + 1} was accepted`,
      )
      // The ceiling itself is legal, so this is a bound rather than a blanket refusal.
      const accepted = await setQuota(store, {
        projectId,
        environmentId,
        meter: `ceiling_${period}`,
        period,
        maxUnits: ceiling,
      })
      assert.equal(accepted.maxUnits, ceiling)
    }
  })

  await t.test('A PER-MINUTE CEILING IS LOWER THAN A PER-MONTH ONE', async () => {
    // Not decoration: one ceiling for every period would have to be the month's, and a per-minute
    // allowance of ten billion is not a limit anybody chose — it is a number nobody bounded.
    assert.ok(
      MAX_UNITS_CEILING.minute < MAX_UNITS_CEILING.month,
      'the minute and month ceilings are the same, so the shorter window is effectively unbounded',
    )
  })

  await t.test('findQuota reads exactly one row, by its natural key', async () => {
    // The read `PUT /v1/projects/:id/quotas` makes to decide whether a request is a RAISE. A
    // comparison against the wrong row is a comparison that lets a raise through.
    const { projectId, environmentId } = await workspaceWithQuota(10)
    await setQuota(store, { projectId, environmentId, period: 'month', maxUnits: 500 })

    assert.equal((await findQuota(store, environmentId, 'minute'))?.maxUnits, 10)
    assert.equal((await findQuota(store, environmentId, 'month'))?.maxUnits, 500)
    assert.equal(await findQuota(store, environmentId, 'day'), null, 'a period with no row is null')
    assert.equal(
      await findQuota(store, environmentId, 'minute', 'webhook_deliveries'),
      null,
      'a second meter on the same period is a different quota',
    )
  })

  await t.test('currentUsage reports the live window for every period', async () => {
    const { projectId, environmentId } = await workspaceWithQuota(10)
    await setQuota(store, { projectId, environmentId, period: 'month', maxUnits: 500 })
    const quotas = await quotasFor(store, environmentId)
    await consumeAll(store, quotas, 3)

    const current = await currentUsage(store, environmentId)
    const byPeriod = new Map(current.map((entry) => [entry.period, entry]))
    assert.equal(byPeriod.get('minute')?.used, 3)
    assert.equal(byPeriod.get('minute')?.limit, 10)
    assert.equal(byPeriod.get('month')?.used, 3)
    assert.equal(byPeriod.get('month')?.limit, 500)
  })

  await t.test('an environment with no quota allows everything, and says so as an empty list', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    const quotas = await quotasFor(store, environments[0]!.id)
    assert.deepEqual([...quotas], [])
    // `every` over an empty set is true. A project whose quotas were deleted is unmetered, which is
    // why `createProject` seeds them in the same transaction as the project.
    assert.equal((await consumeAll(store, quotas)).allowed, true)
  })

  /* ---------------------------------------------------------------- usage */

  await t.test('usage is a count of calls, and rolls up hourly', async () => {
    const { projectId, environmentId } = await workspaceWithQuota(1_000)
    for (let i = 0; i < 5; i += 1) {
      await recordUsage(store, {
        projectId,
        environmentId,
        apiKeyId: null,
        route: '/v1/wallets',
        method: 'GET',
        status: i < 4 ? 200 : 500,
      })
    }
    await rollupUsage(store)

    const usage = await listUsage(store, projectId)
    assert.equal(usage.length, 1)
    assert.equal(usage[0]?.calls, 5)
    assert.equal(usage[0]?.errors, 1)
    assert.equal(usage[0]?.route, '/v1/wallets')
  })

  await t.test('the rollup CORRECTS an incomplete hour rather than duplicating it', async () => {
    // The current hour is incomplete every time it is written, so the upsert has to correct it.
    const { projectId, environmentId } = await workspaceWithQuota(1_000)
    const record = () =>
      recordUsage(store, {
        projectId,
        environmentId,
        apiKeyId: null,
        route: '/v1/rates',
        method: 'GET',
        status: 200,
      })

    await record()
    await rollupUsage(store)
    await record()
    await record()
    await rollupUsage(store)

    const usage = await listUsage(store, projectId)
    assert.equal(usage.length, 1, 'the second rollup wrote a second bucket')
    assert.equal(usage[0]?.calls, 3, 'the rollup added to the bucket instead of replacing it')
  })

  await t.test('retention deletes past the horizon and leaves the rest', async () => {
    const { projectId, environmentId } = await workspaceWithQuota(1_000)
    await sql`
      insert into usage_events (project_id, environment_id, route, method, status, occurred_at)
      values (${projectId}, ${environmentId}, '/old', 'GET', 200, now() - interval '100 days'),
             (${projectId}, ${environmentId}, '/new', 'GET', 200, now())
    `
    const swept = await sweepUsage(store, { eventDays: 35, rollupDays: 400 })
    assert.equal(swept.events, 1)
    const remaining = await sql<{ route: string }[]>`select route from usage_events`
    assert.deepEqual(remaining.map((r) => r.route), ['/new'])
  })

  await t.test('retention prunes closed quota windows', async () => {
    const { quota } = await workspaceWithQuota(10)
    await sql`
      insert into quota_windows (quota_id, window_start, used_units, max_units)
      values (${quota.id}, now() - interval '40 days', 5, 10)
    `
    await consumeQuota(store, quota, 1)
    const swept = await sweepUsage(store, { eventDays: 35, rollupDays: 400 })
    assert.equal(swept.windows, 1)
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from quota_windows`
    assert.equal(rows[0]?.n, 1, 'the live window was pruned too')
  })

  await t.test('the meter is a column, so a second meter is a row rather than a migration', async () => {
    const { projectId, environmentId } = await workspaceWithQuota(10)
    await setQuota(store, { projectId, environmentId, meter: 'webhook_deliveries', period: 'day', maxUnits: 50 })
    const apiRequests = await quotasFor(store, environmentId, API_REQUESTS)
    const webhooks = await quotasFor(store, environmentId, 'webhook_deliveries')
    assert.equal(apiRequests.length, 1)
    assert.equal(webhooks.length, 1)
    // And they count independently.
    await consumeAll(store, apiRequests, 10)
    assert.equal((await consumeAll(store, apiRequests)).allowed, false)
    assert.equal((await consumeAll(store, webhooks)).allowed, true)
  })

  void ((): Quota | undefined => undefined)()
})
