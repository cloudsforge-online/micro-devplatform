/**
 * Idempotency: the fingerprint, and the four properties of the wrapper.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PINNED REGRESSION: A CORRELATION ID IS SUPPOSED TO CHANGE BETWEEN ATTEMPTS.**
 *
 * The ledger fingerprinted the whole request body, `correlationId` included. A caller doing exactly
 * the right thing — a fresh request id per attempt, so a retry is distinguishable in a trace — was
 * told its idempotency key had been reused with a different payload. Every honest retry would have
 * 409'd in production, and the caller could not tell that from a genuine key collision;
 * `micro-wallet` had to carry a correlation id that was stable per operation rather than per
 * attempt, to work around it.
 *
 * Pinned here in BOTH directions, because a one-directional test passes trivially if the
 * fingerprint stops distinguishing anything at all:
 *
 *   - a fresh correlation id REPLAYS
 *   - a genuinely different scope set still 409s
 *
 * `PER_ATTEMPT_FIELDS` is asserted by name, because the defect is an omission and an omission has
 * no behaviour of its own to test.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  PER_ATTEMPT_FIELDS,
  namespacedKey,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import { db, migrateTestDb, openDb, resetDevplatform, skip } from './testsupport.ts'
import type { Db } from './outbox.ts'

/* ------------------------------------------------------------------ the fingerprint */

test('PER_ATTEMPT_FIELDS names correlationId, and the others that change per attempt', () => {
  assert.ok(
    PER_ATTEMPT_FIELDS.has('correlationId'),
    'this set is the fix for the ledger regression; removing correlationId reinstates it',
  )
  assert.ok(PER_ATTEMPT_FIELDS.has('requestId'))
  assert.ok(PER_ATTEMPT_FIELDS.has('idempotencyKey'))
})

test('A FRESH CORRELATION ID FINGERPRINTS THE SAME — the pinned regression', () => {
  const first = requestFingerprint({ scopes: ['market:read'], correlationId: 'req-1' })
  const second = requestFingerprint({ scopes: ['market:read'], correlationId: 'req-2' })
  assert.equal(first, second, 'an honest retry with a new trace id must not look like key reuse')
})

test('A DIFFERENT SCOPE SET STILL FINGERPRINTS DIFFERENTLY — the other direction', () => {
  const first = requestFingerprint({ scopes: ['market:read'], correlationId: 'req-1' })
  const second = requestFingerprint({ scopes: ['market:write'], correlationId: 'req-1' })
  assert.notEqual(
    first,
    second,
    'if this passes vacuously the fingerprint has stopped distinguishing anything',
  )
})

test('key order does not change the fingerprint', () => {
  // JSON.stringify preserves insertion order, so two semantically identical bodies that serialised
  // their fields differently would fingerprint differently and a legitimate retry would 409 — a
  // class of false conflict that is maddening to diagnose from the caller's side.
  const a = requestFingerprint({ environment: 'live', name: 'k', scopes: ['market:read'] })
  const b = requestFingerprint({ scopes: ['market:read'], name: 'k', environment: 'live' })
  assert.equal(a, b)
})

test('key order does not change the fingerprint at depth', () => {
  const a = requestFingerprint({ outer: { x: 1, y: { p: 'a', q: 'b' } } })
  const b = requestFingerprint({ outer: { y: { q: 'b', p: 'a' }, x: 1 } })
  assert.equal(a, b)
})

test('ARRAY ORDER DOES change the fingerprint, deliberately', () => {
  // `['market:read','market:write']` and its reverse are the same scope SET, but an array is
  // ordered in general and a fingerprint that reordered one would be wrong for some other field.
  // `validateScopes` normalises the scope list at the boundary instead, which is where the domain
  // knowledge lives — proven by the next test.
  assert.notEqual(
    requestFingerprint({ scopes: ['a', 'b'] }),
    requestFingerprint({ scopes: ['b', 'a'] }),
  )
})

test('so two scope lists in different orders reach the same fingerprint AFTER validation', async () => {
  const { validateScopes } = await import('./scopes.ts')
  const a = requestFingerprint({ scopes: [...validateScopes(['market:write', 'market:read'])] })
  const b = requestFingerprint({ scopes: [...validateScopes(['market:read', 'market:write'])] })
  assert.equal(a, b, 'normalisation at the boundary is what makes a scope list order-insensitive')
})

test('undefined and a missing field fingerprint the same; null does not', () => {
  assert.equal(requestFingerprint({ a: 1, b: undefined }), requestFingerprint({ a: 1 }))
  // `null` is a value a caller chose. Collapsing it into "absent" would make "clear this field" and
  // "leave this field alone" the same request.
  assert.notEqual(requestFingerprint({ a: 1, b: null }), requestFingerprint({ a: 1 }))
})

test('a scalar and a stringified scalar do not collide', () => {
  assert.notEqual(requestFingerprint({ n: 1 }), requestFingerprint({ n: '1' }))
  assert.notEqual(requestFingerprint({ n: true }), requestFingerprint({ n: 'true' }))
})

test('the fingerprint is stable across calls', () => {
  const body = { environment: 'live', scopes: ['market:read'], nested: { a: [1, 2, { b: 3 }] } }
  assert.equal(requestFingerprint(body), requestFingerprint(body))
})

/* ------------------------------------------------------------------ the namespaced key */

test('the stored key is namespaced by principal AND route', () => {
  // Idempotency keys are chosen by callers. Two developers independently choosing
  // `create-2026-08-01` must not collide — one would replay the other's response, which here means
  // being handed another organisation's key metadata.
  assert.notEqual(
    namespacedKey('user:alice', '/v1/projects', 'create-2026-08-01'),
    namespacedKey('user:bob', '/v1/projects', 'create-2026-08-01'),
  )
  // And the same caller reusing one request id across two different operations is doing something
  // reasonable, so the route is in the key too.
  assert.notEqual(
    namespacedKey('user:alice', '/v1/projects', 'x'),
    namespacedKey('user:alice', '/v1/projects/:id/keys', 'x'),
  )
})

/* ------------------------------------------------------------------ the wrapper */

test('withIdempotency', { skip }, async (t) => {
  const sql = openDb()
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  const store = sql as unknown as Db

  await t.test('the first call runs the work and reports it was not replayed', async () => {
    let ran = 0
    const outcome = await withIdempotency<{ id: string }>(store, {
      principal: 'user:a',
      route: '/v1/projects',
      clientKey: 'k-1',
      requestHash: requestFingerprint({ slug: 'one' }),
      run: async () => {
        ran += 1
        return { response: { id: 'artefact-1' }, artefactId: 'artefact-1' }
      },
    })
    assert.equal(ran, 1)
    assert.equal(outcome.replayed, false)
    assert.deepEqual(outcome.result, { id: 'artefact-1' })
  })

  await t.test('A RETRY REPLAYS THE STORED RESPONSE AND DOES NOT RUN THE WORK AGAIN', async () => {
    let ran = 0
    const call = () =>
      withIdempotency<{ id: string }>(store, {
        principal: 'user:a',
        route: '/v1/projects',
        clientKey: 'k-2',
        requestHash: requestFingerprint({ slug: 'two' }),
        run: async () => {
          ran += 1
          return { response: { id: `artefact-${ran}` }, artefactId: `artefact-${ran}` }
        },
      })

    const first = await call()
    const second = await call()

    assert.equal(ran, 1, 'the work ran twice — a double-clicked Create key would mint two credentials')
    assert.equal(first.replayed, false)
    assert.equal(second.replayed, true)
    assert.deepEqual(second.result, first.result)
  })

  await t.test('a retry carrying a fresh correlation id replays', async () => {
    // The end-to-end form of the pinned regression, through the real table.
    let ran = 0
    const call = (correlationId: string) =>
      withIdempotency<{ id: string }>(store, {
        principal: 'user:a',
        route: '/v1/projects/:id/keys',
        clientKey: 'k-3',
        requestHash: requestFingerprint({ scopes: ['market:read'], correlationId }),
        run: async () => {
          ran += 1
          return { response: { id: 'key-1' }, artefactId: 'key-1' }
        },
      })

    await call('req-first-attempt')
    const retry = await call('req-second-attempt')
    assert.equal(ran, 1)
    assert.equal(retry.replayed, true)
  })

  await t.test('the same key with a genuinely different body is a conflict, not a replay', async () => {
    const call = (scopes: readonly string[]) =>
      withIdempotency<{ id: string }>(store, {
        principal: 'user:a',
        route: '/v1/projects/:id/keys',
        clientKey: 'k-4',
        requestHash: requestFingerprint({ scopes }),
        run: async () => ({ response: { id: 'key-x' }, artefactId: 'key-x' }),
      })

    await call(['market:read'])
    await assert.rejects(() => call(['market:read', 'market:write']), IdempotencyKeyReuseError)
  })

  await t.test('a concurrent duplicate BLOCKS and then replays, rather than racing', async () => {
    // The property that makes a double-clicked button safe. The second INSERT waits on the first
    // transaction's uncommitted row; when that commits, the duplicate reads the stored response.
    let ran = 0
    const call = () =>
      withIdempotency<{ id: string }>(store, {
        principal: 'user:a',
        route: '/v1/projects/:id/keys',
        clientKey: 'k-5',
        requestHash: requestFingerprint({ scopes: ['market:read'] }),
        run: async () => {
          ran += 1
          await new Promise((resolve) => setTimeout(resolve, 60))
          return { response: { id: 'the-only-key' }, artefactId: 'the-only-key' }
        },
      })

    const [a, b] = await Promise.all([call(), call()])
    assert.equal(ran, 1, 'two concurrent attempts both minted a credential')
    assert.deepEqual(a.result, b.result)
    assert.equal([a.replayed, b.replayed].filter(Boolean).length, 1, 'exactly one must be a replay')
  })

  await t.test('a claim whose transaction rolled back leaves nothing behind', async () => {
    // Property 1: the claim INSERT and the work share ONE transaction. If they did not, a failed
    // work step would leave a claim, and a retry would be answered "already created" for a
    // credential that was never minted.
    await assert.rejects(() =>
      withIdempotency(store, {
        principal: 'user:a',
        route: '/v1/projects',
        clientKey: 'k-6',
        requestHash: requestFingerprint({ slug: 'doomed' }),
        run: async () => {
          throw new Error('the work failed')
        },
      }),
    )
    const rows = await sql<{ key: string }[]>`select key from idempotency_keys`
    assert.deepEqual(rows.map((row) => row.key), [], 'a rolled-back claim must leave no row')

    // And the retry therefore runs, rather than replaying a response that never existed.
    let ran = 0
    const retry = await withIdempotency<{ id: string }>(store, {
      principal: 'user:a',
      route: '/v1/projects',
      clientKey: 'k-6',
      requestHash: requestFingerprint({ slug: 'doomed' }),
      run: async () => {
        ran += 1
        return { response: { id: 'ok' }, artefactId: 'ok' }
      },
    })
    assert.equal(ran, 1)
    assert.equal(retry.replayed, false)
  })

  await t.test('a claim with no response yet is in flight, not done', async () => {
    // Property 4: the honest answer to "the row exists but carries no response" is "retry", not a
    // guess. Simulated by writing the claim by hand, which is what a crashed process leaves.
    await sql`
      insert into idempotency_keys (key, route, request_hash)
      values (${namespacedKey('user:a', '/v1/projects', 'k-7')}, '/v1/projects', ${requestFingerprint({ slug: 'x' })})
    `
    await assert.rejects(
      () =>
        withIdempotency(store, {
          principal: 'user:a',
          route: '/v1/projects',
          clientKey: 'k-7',
          requestHash: requestFingerprint({ slug: 'x' }),
          run: async () => ({ response: {}, artefactId: null }),
        }),
      IdempotencyInFlightError,
    )
  })

  await t.test('the artefact id is recorded, so a claim points at what it produced', async () => {
    await withIdempotency(store, {
      principal: 'user:a',
      route: '/v1/projects/:id/keys',
      clientKey: 'k-8',
      requestHash: requestFingerprint({ scopes: [] }),
      run: async () => ({ response: { ok: true }, artefactId: 'key-abc' }),
    })
    const rows = await sql<{ artefact_id: string | null }[]>`
      select artefact_id from idempotency_keys where key = ${namespacedKey('user:a', '/v1/projects/:id/keys', 'k-8')}
    `
    assert.equal(rows[0]?.artefact_id, 'key-abc')
  })

  await t.test('two principals may use the same client key without colliding', async () => {
    const call = (principal: string, id: string) =>
      withIdempotency<{ id: string }>(store, {
        principal,
        route: '/v1/projects',
        clientKey: 'create-2026-08-01',
        requestHash: requestFingerprint({ slug: id }),
        run: async () => ({ response: { id }, artefactId: id }),
      })

    const alice = await call('user:alice', 'alice-project')
    const bob = await call('user:bob', 'bob-project')
    assert.equal(alice.replayed, false)
    assert.equal(bob.replayed, false, "bob replayed alice's response")
    assert.notDeepEqual(alice.result, bob.result)
  })

  await t.test('no stored response ever contains a key secret', async () => {
    // The rule the file header states: the stored response is a jsonb column that outlives the
    // request, and the whole point of this service is that a secret exists for one response and
    // then nowhere. `server.test.ts` proves the route-level version; this is the storage-level one.
    await withIdempotency(store, {
      principal: 'user:a',
      route: '/v1/projects/:id/keys',
      clientKey: 'k-9',
      requestHash: requestFingerprint({ scopes: [] }),
      run: async () => ({ response: { key: { display: 'cfk_live_abc' } }, artefactId: 'k' }),
    })
    const rows = await sql<{ response: unknown }[]>`select response from idempotency_keys`
    for (const row of rows) {
      const text = JSON.stringify(row.response)
      assert.ok(!/cfk_(live|test)_[a-z2-7]{16}_/.test(text), 'a full key string reached the store')
      assert.ok(!text.includes('secretKey'), 'the stored response carries a secretKey field')
    }
  })
})
