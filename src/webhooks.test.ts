/**
 * Webhooks: the signature, the rotation overlap, and delivery.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE SIGNATURE IS VERIFIED OVER THE RAW BYTES, BEFORE ANYTHING IS PARSED.**
 *
 * The ordering is the control. `verifyInbound` takes a `Buffer`, which makes "parse first, verify
 * second" unwriteable rather than merely discouraged — and the test below proves the distinction
 * bites: a body that re-serialises to different bytes (key order, unicode escaping, number
 * formatting) verifies against the ORIGINAL bytes and fails against the round-tripped ones. A
 * handler that verified `JSON.stringify(JSON.parse(body))` would reject its own honest deliveries
 * and, worse, would have already run an unauthenticated document through a parser.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { HttpClient } from '@cloudsforge/http'
import {
  SECRET_PREFIX,
  assertSubscriberUrl,
  backoffFor,
  claimDeliveries,
  constantTimeEquals,
  createEndpoint,
  deleteEndpoint,
  deliverOne,
  enqueueDeliveries,
  findEndpoint,
  listDeliveries,
  listEndpoints,
  liveSecrets,
  markDelivered,
  markFailed,
  mintWebhookSecret,
  pruneRetiredSecrets,
  rotateSecret,
  setEndpointDisabled,
  signingSecret,
  verifyInbound,
} from './webhooks.ts'
import { signEvent, type Db, type EventEnvelope, type Tx } from './outbox.ts'
import { NotFoundError, ValidationError } from './orgs.ts'
import { fakeSubscriber, migrateTestDb, openDb, resetDevplatform, seedWorkspace, skip } from './testsupport.ts'

const SECRET = 'whsec_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd'

/* ------------------------------------------------------------------ the signature */

test('a signature verifies over the exact bytes that were signed', () => {
  const body = Buffer.from('{"a":1,"b":2}', 'utf8')
  const header = signEvent(body.toString('utf8'), SECRET)
  assert.equal(verifyInbound(body, header, [SECRET]).ok, true)
})

test('RE-SERIALISING THE BODY BREAKS THE SIGNATURE — which is why the raw bytes are what is checked', () => {
  // `JSON.stringify` is not the inverse of `JSON.parse`. A handler that parsed first and verified
  // the round-trip would reject its own honest deliveries — and would already have parsed an
  // unauthenticated document to find that out.
  const raw = '{"b":2,"a":1,"s":"caf\\u00e9","n":1.0}'
  const header = signEvent(raw, SECRET)
  assert.equal(verifyInbound(Buffer.from(raw, 'utf8'), header, [SECRET]).ok, true)

  const roundTripped = JSON.stringify(JSON.parse(raw))
  assert.notEqual(roundTripped, raw, 'the fixture must actually differ after a round trip')
  assert.equal(
    verifyInbound(Buffer.from(roundTripped, 'utf8'), header, [SECRET]).ok,
    false,
    'verifying a re-serialised body would accept bytes nobody signed',
  )
})

test('a tampered body does not verify', () => {
  const body = '{"amount":1}'
  const header = signEvent(body, SECRET)
  assert.equal(verifyInbound(Buffer.from('{"amount":9}', 'utf8'), header, [SECRET]).ok, false)
})

test('a body signed with another secret does not verify', () => {
  const body = '{"a":1}'
  const header = signEvent(body, 'whsec_the-other-secret-0000000000000000')
  const outcome = verifyInbound(Buffer.from(body, 'utf8'), header, [SECRET])
  assert.equal(outcome.ok, false)
  assert.equal(outcome.reason, 'mismatch')
})

test('a missing or malformed signature header is refused, and says which', () => {
  const body = Buffer.from('{}', 'utf8')
  assert.deepEqual(verifyInbound(body, undefined, [SECRET]), { ok: false, reason: 'missing_signature' })
  assert.equal(verifyInbound(body, '', [SECRET]).reason, 'missing_signature')
  assert.equal(verifyInbound(body, 'garbage', [SECRET]).reason, 'malformed_header')
  assert.equal(verifyInbound(body, 't=abc,v1=ff', [SECRET]).reason, 'malformed_header')
})

test('a captured delivery cannot be replayed outside the tolerance window', () => {
  // The timestamp is INSIDE the signed material, so it cannot be moved without invalidating the
  // signature — which is what makes the freshness window mean anything.
  const body = '{"a":1}'
  const signedAt = Date.UTC(2026, 0, 1, 12, 0, 0)
  const header = signEvent(body, SECRET, signedAt)
  assert.equal(verifyInbound(Buffer.from(body), header, [SECRET], signedAt).ok, true)
  assert.equal(
    verifyInbound(Buffer.from(body), header, [SECRET], signedAt + 24 * 3_600_000).ok,
    false,
    'a day-old delivery replayed successfully',
  )
})

test('A LIST OF SECRETS IS ACCEPTED, so a rotation has an overlap window', () => {
  const older = 'whsec_the-older-secret-000000000000000000'
  const body = '{"a":1}'
  const header = signEvent(body, older)
  // Signed with the old secret, verified against a list that still contains it.
  assert.equal(verifyInbound(Buffer.from(body), header, [SECRET, older]).ok, true)
  // And once it is dropped from the list, it stops verifying.
  assert.equal(verifyInbound(Buffer.from(body), header, [SECRET]).ok, false)
})

test('constantTimeEquals compares without throwing on a length mismatch', () => {
  assert.equal(constantTimeEquals('abc', 'abc'), true)
  assert.equal(constantTimeEquals('abc', 'abd'), false)
  assert.equal(constantTimeEquals('abc', 'abcd'), false)
  assert.equal(constantTimeEquals('', ''), true)
})

/* ------------------------------------------------------------------ the url guard */

test('a subscriber url must be https and must not point inward', () => {
  assert.equal(assertSubscriberUrl('https://example.com/hook'), 'https://example.com/hook')
  for (const url of [
    'http://example.com/hook',
    'https://localhost/hook',
    'https://127.0.0.1/hook',
    'https://10.0.0.5/hook',
    'https://192.168.1.1/hook',
    // The one that matters: cloud instance metadata. An unchecked subscriber url is a
    // server-side request forgery primitive with a customer-supplied target.
    'https://169.254.169.254/latest/meta-data/',
    'https://172.16.0.1/hook',
    'https://[::1]/hook',
    'https://user:pass@example.com/hook',
    'not a url',
  ]) {
    assert.throws(() => assertSubscriberUrl(url), ValidationError, `${url} was accepted`)
  }
})

test('a minted secret carries its prefix and is long enough for the schema', () => {
  const secret = mintWebhookSecret()
  assert.ok(secret.startsWith(SECRET_PREFIX))
  assert.ok(secret.length >= 32)
  assert.notEqual(mintWebhookSecret(), mintWebhookSecret())
})

test('the backoff grows and is capped at an hour', () => {
  assert.ok(backoffFor(1, () => 1) <= 1_000)
  assert.ok(backoffFor(5, () => 1) > backoffFor(2, () => 1))
  assert.ok(backoffFor(50, () => 1) <= 3_600_000)
  // Full jitter: never zero, never above the cap.
  assert.ok(backoffFor(3, () => 0) > 0)
})

/* ------------------------------------------------------------------ against Postgres */

test('webhooks', { skip }, async (t) => {
  const sql = openDb()
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  const store = sql as unknown as Db
  const tx = <T>(fn: (t: Tx) => Promise<T>): Promise<T> =>
    sql.begin(async (t) => ({ value: await fn(t as unknown as Tx) })).then((o) => o.value)

  async function seedEndpoint(url = 'https://example.com/hook', topics = ['devplatform.key.issued']) {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} and name = 'live'
    `
    const created = await tx((t) =>
      createEndpoint(t, {
        projectId: project.id,
        environmentId: environments[0]!.id,
        url,
        topics,
      }),
    )
    return { project, ...created }
  }

  /* ---------------------------------------------------------------- creation */

  await t.test('THE SECRET IS SHOWN ONCE, AND NO READ RETURNS IT AFTERWARDS', async () => {
    const { endpoint, secret, project } = await seedEndpoint()
    assert.ok(secret.startsWith(SECRET_PREFIX))

    // Every read path this module offers.
    const listed = await listEndpoints(store, project.id)
    const found = await findEndpoint(store, endpoint.id)
    const deliveries = await listDeliveries(store, endpoint.id)
    for (const [name, value] of [
      ['listEndpoints', listed],
      ['findEndpoint', found],
      ['listDeliveries', deliveries],
    ] as const) {
      assert.ok(!JSON.stringify(value).includes(secret), `${name} returned the signing secret`)
    }
    // The endpoint type has no field it could occupy.
    assert.ok(!('secret' in endpoint))
  })

  await t.test('an endpoint with no topics is refused', async () => {
    // An endpoint that receives everything by default is an endpoint nobody meant to subscribe.
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await assert.rejects(
      () =>
        tx((t) =>
          createEndpoint(t, {
            projectId: project.id,
            environmentId: environments[0]!.id,
            url: 'https://example.com/h',
            topics: [],
          }),
        ),
      ValidationError,
    )
  })

  await t.test('a wildcard topic is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await assert.rejects(
      () =>
        tx((t) =>
          createEndpoint(t, {
            projectId: project.id,
            environmentId: environments[0]!.id,
            url: 'https://example.com/h',
            topics: ['devplatform.*'],
          }),
        ),
      ValidationError,
    )
  })

  await t.test('an endpoint cannot be created on another project\'s environment', async () => {
    const mine = await seedWorkspace(sql)
    const theirs = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${theirs.project.id} limit 1
    `
    await assert.rejects(
      () =>
        tx((t) =>
          createEndpoint(t, {
            projectId: mine.project.id,
            environmentId: environments[0]!.id,
            url: 'https://example.com/h',
            topics: ['a.b.c'],
          }),
        ),
      NotFoundError,
    )
  })

  /* ---------------------------------------------------------------- rotation */

  await t.test('ROTATION KEEPS BOTH SECRETS LIVE, so a subscriber does not lose a delivery', async () => {
    const { endpoint, secret: original } = await seedEndpoint()
    const rotated = await tx((t) => rotateSecret(t, endpoint.id, 60))

    assert.notEqual(rotated, original)
    const live = await liveSecrets(store, endpoint.id)
    assert.deepEqual([...live], [rotated, original], 'newest first, and both still accepted')

    // New deliveries sign with the newest.
    assert.equal(await signingSecret(store, endpoint.id), rotated)

    // A delivery signed with the OLD secret during the overlap still verifies at the subscriber.
    const body = '{"a":1}'
    assert.equal(verifyInbound(Buffer.from(body), signEvent(body, original), live).ok, true)
    assert.equal(verifyInbound(Buffer.from(body), signEvent(body, rotated), live).ok, true)
  })

  await t.test('once the overlap has elapsed the old secret stops verifying and is pruned', async () => {
    const { endpoint, secret: original } = await seedEndpoint()
    // Rotate with an overlap that has already passed.
    await tx((t) => rotateSecret(t, endpoint.id, 60))
    await sql`update webhook_secrets set retires_at = now() - interval '1 minute' where secret = ${original}`

    const live = await liveSecrets(store, endpoint.id)
    assert.equal(live.length, 1)
    assert.ok(!live.includes(original))

    const pruned = await pruneRetiredSecrets(store)
    assert.equal(pruned, 1)
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from webhook_secrets`
    assert.equal(rows[0]?.n, 1)
  })

  await t.test('rotating twice inside one window does not extend the first secret\'s life', async () => {
    const { endpoint, secret: original } = await seedEndpoint()
    await tx((t) => rotateSecret(t, endpoint.id, 60))
    const firstRetires = await sql<{ retires_at: Date }[]>`
      select retires_at from webhook_secrets where secret = ${original}
    `
    await tx((t) => rotateSecret(t, endpoint.id, 600))
    const secondRetires = await sql<{ retires_at: Date }[]>`
      select retires_at from webhook_secrets where secret = ${original}
    `
    assert.deepEqual(
      secondRetires[0]?.retires_at,
      firstRetires[0]?.retires_at,
      'the second rotation reset the first secret\'s retirement',
    )
  })

  await t.test('rotating an unknown endpoint is a not-found', async () => {
    await assert.rejects(
      () => tx((t) => rotateSecret(t, '00000000-0000-0000-0000-000000000000', 60)),
      NotFoundError,
    )
  })

  /* ---------------------------------------------------------------- delivery */

  function envelope(topic: string, id: string): EventEnvelope {
    return {
      id,
      topic,
      key: 'k',
      occurredAt: new Date().toISOString(),
      producer: 'devplatform',
      // The wire shape the CONTRACT demands. `version: 1` with null actor and correlation id
      // compiled here for the whole life of this file and is refused by `validateEnvelope` three
      // times over — a fixture reproducing a defect is a fixture that certifies it.
      version: '1.0',
      actor: 'service:devplatform',
      correlationId: 'req-test',
      payload: { hello: 'world' },
    }
  }

  await t.test('an event fans out only to endpoints subscribed to its topic', async () => {
    const wanted = await seedEndpoint('https://a.example.com/h', ['devplatform.key.issued'])
    await seedEndpoint('https://b.example.com/h', ['devplatform.key.revoked'])

    const queued = await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    assert.equal(queued, 1)
    const rows = await sql<{ endpoint_id: string }[]>`select endpoint_id from webhook_deliveries`
    assert.deepEqual(rows.map((r) => r.endpoint_id), [wanted.endpoint.id])
  })

  await t.test('a disabled endpoint receives nothing', async () => {
    const { endpoint } = await seedEndpoint()
    await setEndpointDisabled(store, endpoint.id, true)
    assert.equal(await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID())), 0)
  })

  await t.test('ENQUEUEING THE SAME EVENT TWICE PRODUCES ONE DELIVERY', async () => {
    // The outbox relay is at-least-once, so this WILL happen. The unique constraint is the
    // mechanism; `do nothing` is what stops a redelivery becoming a second customer-visible webhook.
    await seedEndpoint()
    const event = envelope('devplatform.key.issued', crypto.randomUUID())
    assert.equal(await enqueueDeliveries(store, event), 1)
    assert.equal(await enqueueDeliveries(store, event), 0)
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from webhook_deliveries`
    assert.equal(rows[0]?.n, 1)
  })

  await t.test('a claimed delivery is not claimable again until its lease expires', async () => {
    await seedEndpoint()
    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))

    const first = await claimDeliveries(store, 10, 60_000)
    assert.equal(first.length, 1)
    const second = await claimDeliveries(store, 10, 60_000)
    assert.equal(second.length, 0, 'a second worker claimed a delivery already in flight')
  })

  await t.test('TWO CONCURRENT CLAIMS TAKE DISJOINT SETS', async () => {
    // `for update skip locked` at the row level. Without it both workers read the same rows and the
    // customer's endpoint receives every event twice.
    await seedEndpoint()
    for (let i = 0; i < 10; i += 1) {
      await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    }
    const [a, b] = await Promise.all([
      claimDeliveries(store, 10, 60_000),
      claimDeliveries(store, 10, 60_000),
    ])
    const ids = [...a.map((d) => d.id), ...b.map((d) => d.id)]
    assert.equal(new Set(ids).size, ids.length, 'the same delivery was claimed twice')
    assert.equal(ids.length, 10)
  })

  /**
   * Route a delivery at the local fake WITHOUT weakening the https guard.
   *
   * The row keeps a legitimate `https://` url — both `assertSubscriberUrl` and
   * `webhook_endpoints_url_https` refuse anything else, and neither is relaxed for a test. The
   * `clientFor` seam is what production uses to build one client per subscriber origin, and
   * pointing it at the fake exercises the real signing path over the real bytes on a real socket.
   * What is NOT exercised is DNS and TLS, which are the transport's business rather than this
   * module's.
   */
  const routeTo = (subscriber: { baseUrl: string }) => (): Pick<HttpClient, 'request'> =>
    new HttpClient({ baseUrl: subscriber.baseUrl, name: 'sub', defaultRetries: 0 })

  await t.test('a delivery is SIGNED, and the subscriber can verify it over the bytes received', async () => {
    const subscriber = await fakeSubscriber()
    t.after(() => subscriber.close())

    const { secret } = await seedEndpoint('https://subscriber.example.com/hook')

    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    const claimed = await claimDeliveries(store, 1, 60_000)
    const outcome = await deliverOne(
      { sql: store, deadlineMs: 2_000, maxAttempts: 3, clientFor: routeTo(subscriber) },
      claimed[0]!,
    )
    assert.equal(outcome, 'delivered')

    const received = subscriber.deliveries[0]
    assert.ok(received, 'nothing arrived')
    const header = received.headers['cf-signature']
    assert.ok(header, 'the delivery carried no signature')
    assert.equal(
      verifyInbound(Buffer.from(received.body, 'utf8'), header, [secret]).ok,
      true,
      'the signature does not verify over the bytes that arrived',
    )
    assert.ok(received.headers['cf-event-id'], 'the delivery carried no event id to dedupe on')
    // The idempotency key IS the event id, which is what makes the POST safe to retry.
    assert.equal(received.headers['idempotency-key'], received.headers['cf-event-id'])

    const rows = await sql<{ delivered_at: Date | null }[]>`select delivered_at from webhook_deliveries`
    assert.ok(rows[0]?.delivered_at)
  })

  await t.test('a failing subscriber is retried, then abandoned with the row retained', async () => {
    const subscriber = await fakeSubscriber()
    subscriber.setStatus(500)
    t.after(() => subscriber.close())

    await seedEndpoint('https://subscriber.example.com/hook')
    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))

    const deps = { sql: store, deadlineMs: 2_000, maxAttempts: 2, clientFor: routeTo(subscriber) }

    // Attempt 1 → retry. Attempt 2 → the ceiling, so abandoned.
    let claimed = await claimDeliveries(store, 1, 0)
    assert.equal(claimed.length, 1)
    assert.equal(await deliverOne(deps, claimed[0]!), 'retry')

    // The failure scheduled the retry a backoff into the future, which is the point of a backoff.
    // Wind the clock forward by moving the row rather than by sleeping for it: a test that waits
    // out a real exponential backoff is a test that gets a shorter ceiling, and a shorter ceiling
    // is the thing under test.
    await sql`update webhook_deliveries set next_attempt_at = now() - interval '1 second'`

    claimed = await claimDeliveries(store, 1, 0)
    assert.equal(claimed.length, 1, 'the retry never became claimable again')
    assert.equal(await deliverOne(deps, claimed[0]!), 'abandoned')

    const rows = await sql<{ attempts: number; delivered_at: Date | null; last_error: string | null }[]>`
      select attempts, delivered_at, last_error from webhook_deliveries
    `
    assert.equal(rows.length, 1, 'the abandoned delivery was deleted — the row IS the record')
    assert.equal(rows[0]?.delivered_at, null)
    assert.ok(rows[0]?.last_error)
    // And it is pushed far enough out that it stops being claimed.
    const stillDue = await claimDeliveries(store, 1, 0)
    assert.equal(stillDue.length, 0)
  })

  await t.test('a delivery to an endpoint deleted mid-flight is closed out, not retried for ever', async () => {
    const { endpoint } = await seedEndpoint()
    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    const claimed = await claimDeliveries(store, 1, 60_000)
    await setEndpointDisabled(store, endpoint.id, true)

    const outcome = await deliverOne(
      {
        sql: store,
        deadlineMs: 1_000,
        maxAttempts: 3,
        clientFor: () => ({ request: async () => assert.fail('must not dial a disabled endpoint') }),
      },
      claimed[0]!,
    )
    assert.equal(outcome, 'gone')
    const rows = await sql<{ last_status: number | null }[]>`select last_status from webhook_deliveries`
    assert.equal(rows[0]?.last_status, 410)
  })

  await t.test('an endpoint with no live secret is not delivered to', async () => {
    const { endpoint } = await seedEndpoint()
    await sql`delete from webhook_secrets where endpoint_id = ${endpoint.id}`
    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    const claimed = await claimDeliveries(store, 1, 60_000)
    const outcome = await deliverOne(
      {
        sql: store,
        deadlineMs: 1_000,
        maxAttempts: 3,
        clientFor: () => ({ request: async () => assert.fail('must not deliver unsigned') }),
      },
      claimed[0]!,
    )
    assert.equal(outcome, 'no_secret', 'an unsigned delivery is worse than a missed one')
  })

  await t.test('deleting an endpoint takes its secrets and deliveries with it', async () => {
    const { endpoint } = await seedEndpoint()
    await enqueueDeliveries(store, envelope('devplatform.key.issued', crypto.randomUUID()))
    assert.equal(await deleteEndpoint(store, endpoint.id), true)
    const secrets = await sql<{ n: number }[]>`select count(*)::int as n from webhook_secrets`
    const deliveries = await sql<{ n: number }[]>`select count(*)::int as n from webhook_deliveries`
    assert.equal(secrets[0]?.n, 0)
    assert.equal(deliveries[0]?.n, 0)
    assert.equal(await deleteEndpoint(store, endpoint.id), false)
  })

  void markDelivered
  void markFailed
})
