/**
 * The credential store, against a real Postgres.
 *
 * `keys.test.ts` proves the cryptography without a database. This proves the ROWS: that issuance
 * writes a one-way hash and nothing else, that revocation is immediate, that a suspended
 * organisation's keys stop working, and that none of the four refusals is distinguishable from
 * another by anything a caller can observe.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  authenticateKey,
  createServiceAccount,
  findApiKey,
  introspect,
  issueApiKey,
  listApiKeys,
  revokeApiKey,
  revokeByDisplay,
  revokeOrgKeys,
  touchLastUsed,
} from './apikeys.ts'
import { CURRENT_ALGO, encodeAlgo, parseKey, resetDecoy, scryptKdf, type Kdf } from './keys.ts'
import { NotFoundError, ValidationError, setOrgStatus } from './orgs.ts'
import { UnknownScopeError } from './scopes.ts'
import type { Db, Tx } from './outbox.ts'
import {
  TEST_PARAMS,
  db,
  migrateTestDb,
  openDb,
  resetDevplatform,
  seedKey,
  seedWorkspace,
  skip,
} from './testsupport.ts'

test('api keys', { skip }, async (t) => {
  const sql = openDb()
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(async () => {
    await resetDevplatform(sql)
    resetDecoy()
  })

  const store = sql as unknown as Db
  const tx = <T>(fn: (t: Tx) => Promise<T>): Promise<T> =>
    sql.begin(async (t) => ({ value: await fn(t as unknown as Tx) })).then((o) => o.value)

  const auth = (presented: string) => authenticateKey(store, presented, { params: TEST_PARAMS })

  /* ---------------------------------------------------------------- issuance */

  await t.test('THE SECRET IS RETURNED ONCE AND IS NOWHERE IN THE ROW', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id, { scopes: ['market:read'] })
    const secret = parseKey(issued.secretKey)!.secret

    // Every column of the row, as text. The secret must appear in none of them.
    const rows = await sql<Record<string, unknown>[]>`select * from api_keys where id = ${issued.key.id}`
    const rowText = JSON.stringify(rows[0])
    assert.ok(!rowText.includes(secret), 'the secret is stored somewhere in the row')
    assert.ok(!rowText.includes(issued.secretKey), 'the full key string is stored in the row')
    // And the lookup id IS stored, in the clear, because it grants nothing.
    assert.ok(rowText.includes(issued.key.lookupId))

    // Every column of every table. A secret that leaked into an outbox payload or an idempotency
    // response would be just as recoverable as one in api_keys.
    for (const table of ['outbox', 'idempotency_keys', 'usage_events']) {
      const all = await sql.unsafe(`select * from ${table}`)
      assert.ok(!JSON.stringify(all).includes(secret), `the secret reached ${table}`)
    }
  })

  await t.test('the summary type has no field a secret could occupy', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    for (const field of ['secret', 'secretKey', 'hash', 'secretHash', 'salt', 'algo']) {
      assert.ok(!(field in issued.key), `ApiKeySummary carries a '${field}' field`)
    }
  })

  await t.test('the row records a scrypt algorithm with its parameters', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    const rows = await sql<{ secret_algo: string }[]>`
      select secret_algo from api_keys where id = ${issued.key.id}
    `
    assert.equal(rows[0]?.secret_algo, encodeAlgo(TEST_PARAMS))
    assert.match(rows[0]!.secret_algo, /^scrypt\$N=\d+,r=\d+,p=\d+,keyLen=\d+$/)
  })

  await t.test('issuance refuses an unknown scope rather than filtering it', async () => {
    const { project } = await seedWorkspace(sql)
    await assert.rejects(
      () =>
        tx((t) =>
          issueApiKey(
            t,
            { projectId: project.id, environment: 'live', name: 'k', scopes: ['market:*'], createdBy: 'u' },
            { params: TEST_PARAMS },
          ),
        ),
      UnknownScopeError,
    )
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from api_keys`
    assert.equal(rows[0]?.n, 0, 'a refused issuance left a row behind')
  })

  await t.test('a key with no scopes is issued, and grants nothing', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id, { scopes: [] })
    assert.deepEqual([...issued.key.scopes], [])
    const outcome = await auth(issued.secretKey)
    assert.equal(outcome.ok, true, 'an inert key must still authenticate — it simply authorises nothing')
  })

  await t.test('issuance refuses an environment the project does not have', async () => {
    const { project } = await seedWorkspace(sql)
    await sql`delete from environments where project_id = ${project.id} and name = 'test'`
    await assert.rejects(
      () =>
        tx((t) =>
          issueApiKey(
            t,
            { projectId: project.id, environment: 'test', name: 'k', scopes: [], createdBy: 'u' },
            { params: TEST_PARAMS },
          ),
        ),
      NotFoundError,
    )
  })

  await t.test('a key cannot be attached to ANOTHER project\'s service account', async () => {
    // `service_accounts.id` alone is a valid foreign key, so without the explicit check a caller
    // could attach a key to a service account belonging to a different customer.
    const mine = await seedWorkspace(sql)
    const theirs = await seedWorkspace(sql)
    const account = await createServiceAccount(store, { projectId: theirs.project.id, name: 'nightly' })
    await assert.rejects(
      () =>
        tx((t) =>
          issueApiKey(
            t,
            {
              projectId: mine.project.id,
              environment: 'live',
              name: 'k',
              scopes: [],
              createdBy: 'u',
              serviceAccountId: account.id,
            },
            { params: TEST_PARAMS },
          ),
        ),
      NotFoundError,
    )
  })

  await t.test('a key name must be present and bounded', async () => {
    const { project } = await seedWorkspace(sql)
    for (const name of ['', '   ', 'x'.repeat(201)]) {
      await assert.rejects(
        () =>
          tx((t) =>
            issueApiKey(
              t,
              { projectId: project.id, environment: 'live', name, scopes: [], createdBy: 'u' },
              { params: TEST_PARAMS },
            ),
          ),
        ValidationError,
      )
    }
  })

  /* ---------------------------------------------------------------- authentication */

  await t.test('a live key authenticates and reports its project and organisation', async () => {
    const { org, project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id, { scopes: ['market:read'] })
    const outcome = await auth(issued.secretKey)
    assert.equal(outcome.ok, true)
    assert.equal(outcome.ok && outcome.key.projectId, project.id)
    assert.equal(outcome.ok && outcome.orgId, org.id)
    assert.deepEqual(outcome.ok ? [...outcome.key.scopes] : null, ['market:read'])
  })

  await t.test('A REVOKED KEY AND AN UNKNOWN KEY ARE THE SAME ANSWER SHAPE', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    await tx((t) => revokeApiKey(t, { id: issued.key.id, revokedBy: 'user:x', reason: 'leaked' }))

    const revoked = await auth(issued.secretKey)
    // A well-formed key whose lookup id is not in the table.
    const unknown = await auth(`cfk_live_${'a'.repeat(16)}_${'b'.repeat(52)}`)

    assert.equal(revoked.ok, false)
    assert.equal(unknown.ok, false)
    assert.deepEqual(Object.keys(revoked).sort(), Object.keys(unknown).sort())
    // The reasons DIFFER — that is what the log and the metric need — and `server.test.ts` proves
    // neither reaches the wire.
    assert.equal(revoked.ok === false && revoked.reason, 'revoked')
    assert.equal(unknown.ok === false && unknown.reason, 'unknown')
  })

  await t.test('BOTH REFUSALS COST EXACTLY ONE KDF RUN', async () => {
    // The database-level form of the timing property. A revoked key answering without hashing would
    // be a fast "no" for a key that exists — which tells an attacker the account is real.
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    await tx((t) => revokeApiKey(t, { id: issued.key.id, revokedBy: 'user:x' }))

    let calls = 0
    const counting: Kdf = (secret, salt, params) => {
      calls += 1
      return scryptKdf(secret, salt, params)
    }
    // Warm the decoy so the first miss does not also pay for building it.
    await authenticateKey(store, `cfk_live_${'c'.repeat(16)}_${'d'.repeat(52)}`, { params: TEST_PARAMS })

    calls = 0
    await authenticateKey(store, issued.secretKey, { params: TEST_PARAMS, kdf: counting })
    assert.equal(calls, 1, 'the revoked path skipped the kdf')

    calls = 0
    await authenticateKey(store, `cfk_live_${'a'.repeat(16)}_${'b'.repeat(52)}`, {
      params: TEST_PARAMS,
      kdf: counting,
    })
    assert.equal(calls, 1, 'the unknown path skipped the kdf')
  })

  await t.test('revocation is immediate — the very next authentication refuses', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    assert.equal((await auth(issued.secretKey)).ok, true)
    await tx((t) => revokeApiKey(t, { id: issued.key.id, revokedBy: 'user:x' }))
    assert.equal((await auth(issued.secretKey)).ok, false)
  })

  await t.test('a malformed string never reaches the database', async () => {
    const outcome = await auth('not-a-key')
    assert.equal(outcome.ok, false)
    assert.equal(outcome.ok === false && outcome.reason, 'malformed')
    assert.equal(outcome.ok === false && outcome.display, null)
  })

  await t.test('an expired key is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id, { expiresAt: new Date(Date.now() - 60_000) })
    const outcome = await auth(issued.secretKey)
    assert.equal(outcome.ok, false)
    assert.equal(outcome.ok === false && outcome.reason, 'expired')
  })

  await t.test('a suspended organisation\'s keys stop working, without a row being destroyed', async () => {
    const { org, project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    assert.equal((await auth(issued.secretKey)).ok, true)

    await setOrgStatus(store, org.id, 'suspended')
    const outcome = await auth(issued.secretKey)
    assert.equal(outcome.ok, false)
    assert.equal(outcome.ok === false && outcome.reason, 'org_suspended')

    // The key survives, so reinstatement is one state change rather than a re-issue of every
    // credential the organisation ever handed to a customer.
    const row = await findApiKey(store, issued.key.id)
    assert.equal(row?.revokedAt, null)
    await setOrgStatus(store, org.id, 'active')
    assert.equal((await auth(issued.secretKey)).ok, true)
  })

  await t.test('the suspension check happens AFTER the kdf run', async () => {
    // If it ran first, a genuine key belonging to a suspended organisation would answer in
    // microseconds — which hands back the fact that the key is genuine.
    const { org, project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    await setOrgStatus(store, org.id, 'suspended')

    let calls = 0
    const counting: Kdf = (secret, salt, params) => {
      calls += 1
      return scryptKdf(secret, salt, params)
    }
    await authenticateKey(store, issued.secretKey, { params: TEST_PARAMS, kdf: counting })
    assert.equal(calls, 1, 'a suspended organisation short-circuited before the kdf')
  })

  await t.test('a key from one project cannot be presented as another\'s', async () => {
    // Not a check in the code: the row IS the project. This asserts the property holds anyway.
    const a = await seedWorkspace(sql)
    const b = await seedWorkspace(sql)
    const issued = await seedKey(sql, a.project.id)
    const outcome = await auth(issued.secretKey)
    assert.equal(outcome.ok && outcome.key.projectId, a.project.id)
    assert.notEqual(outcome.ok && outcome.key.projectId, b.project.id)
  })

  /* ---------------------------------------------------------------- re-hashing */

  await t.test('a key hashed at a lower work factor is re-hashed on its next successful use', async () => {
    // The operation the recorded-parameters design exists to enable. Without it, raising
    // CURRENT_PARAMS would protect only keys issued afterwards.
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)

    const before = await sql<{ secret_algo: string; secret_hash: string }[]>`
      select secret_algo, secret_hash from api_keys where id = ${issued.key.id}
    `
    assert.equal(before[0]?.secret_algo, encodeAlgo(TEST_PARAMS))

    // Authenticate with the CURRENT parameters while the row records the test ones.
    const outcome = await authenticateKey(store, issued.secretKey)
    assert.equal(outcome.ok, true)

    const after = await sql<{ secret_algo: string; secret_hash: string }[]>`
      select secret_algo, secret_hash from api_keys where id = ${issued.key.id}
    `
    assert.equal(after[0]?.secret_algo, CURRENT_ALGO, 'the row was not re-hashed')
    assert.notEqual(after[0]?.secret_hash, before[0]?.secret_hash)

    // And the same key string still authenticates against the new hash.
    assert.equal((await authenticateKey(store, issued.secretKey)).ok, true)
  })

  /* ---------------------------------------------------------------- revocation */

  await t.test('revoking twice preserves the first revocation and reports the second', async () => {
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    const first = await tx((t) =>
      revokeApiKey(t, { id: issued.key.id, revokedBy: 'user:a', reason: 'leaked in a gist' }),
    )
    const second = await tx((t) => revokeApiKey(t, { id: issued.key.id, revokedBy: 'user:b', reason: 'again' }))

    assert.equal(first.alreadyRevoked, false)
    assert.equal(second.alreadyRevoked, true)
    assert.equal(second.key.revokedReason, 'leaked in a gist', 'the second call overwrote the first')
    assert.deepEqual(second.key.revokedAt, first.key.revokedAt)
  })

  await t.test('a key can be revoked by the display string found in a log line', async () => {
    // The property the whole format is arranged around: an operator who finds a key in a paste bin
    // can revoke exactly that key without ever holding the secret.
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)
    const outcome = await tx((t) =>
      revokeByDisplay(t, { display: issued.key.display, revokedBy: 'ops', reason: 'found in a ticket' }),
    )
    assert.equal(outcome.key.id, issued.key.id)
    assert.equal((await auth(issued.secretKey)).ok, false)
  })

  await t.test('revoking an unknown key is a not-found, not a silent success', async () => {
    await assert.rejects(
      () => tx((t) => revokeApiKey(t, { id: '00000000-0000-0000-0000-000000000000', revokedBy: 'x' })),
      NotFoundError,
    )
    await assert.rejects(
      () => tx((t) => revokeByDisplay(t, { display: 'cfk_live_zzzzzzzzzzzzzzzz', revokedBy: 'x' })),
      NotFoundError,
    )
  })

  await t.test('revoking an organisation revokes every live key it has, and no other', async () => {
    const mine = await seedWorkspace(sql)
    const theirs = await seedWorkspace(sql)
    const a = await seedKey(sql, mine.project.id)
    const b = await seedKey(sql, mine.project.id)
    const other = await seedKey(sql, theirs.project.id)
    await tx((t) => revokeApiKey(t, { id: b.key.id, revokedBy: 'user:x', reason: 'earlier' }))

    // `service:identity`, the string `server.ts` really passes. `system:identity` stood here
    // until contracts registered this topic and proved `system` is the one kind with no subject —
    // and `revoked_by` takes the same string the event's `Actor` does, so a fixture that disagrees
    // with production is a fixture that agrees with a defect.
    const revoked = await tx((t) => revokeOrgKeys(t, mine.org.id, 'service:identity', 'organisation deleted'))
    assert.deepEqual(revoked.map((k) => k.id), [a.key.id], 'only the LIVE keys should be revoked')

    assert.equal((await auth(a.secretKey)).ok, false)
    assert.equal((await auth(other.secretKey)).ok, true, "another organisation's key was revoked")
    // And the already-revoked key kept its original reason.
    const kept = await findApiKey(store, b.key.id)
    assert.equal(kept?.revokedReason, 'earlier')
  })

  /* ---------------------------------------------------------------- listing */

  await t.test('listing hides revoked keys by default and never carries a secret', async () => {
    const { project } = await seedWorkspace(sql)
    const live = await seedKey(sql, project.id, { name: 'live one' })
    const dead = await seedKey(sql, project.id, { name: 'dead one' })
    await tx((t) => revokeApiKey(t, { id: dead.key.id, revokedBy: 'x' }))

    const visible = await listApiKeys(store, project.id)
    assert.deepEqual(visible.map((k) => k.id), [live.key.id])

    const all = await listApiKeys(store, project.id, { includeRevoked: true })
    assert.equal(all.length, 2)

    const text = JSON.stringify(all)
    assert.ok(!text.includes(parseKey(live.secretKey)!.secret))
    assert.ok(!text.includes(parseKey(dead.secretKey)!.secret))
  })

  /* ---------------------------------------------------------------- last used */

  await t.test('last_used_at is written once, then coarsened to a minute', async () => {
    // An UPDATE per authenticated request serialises every concurrent caller of one key on one row.
    const { project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id)

    await touchLastUsed(store, issued.key.id)
    const first = await findApiKey(store, issued.key.id)
    assert.ok(first?.lastUsedAt, 'the first use was not recorded')

    await touchLastUsed(store, issued.key.id)
    const second = await findApiKey(store, issued.key.id)
    assert.deepEqual(second?.lastUsedAt, first?.lastUsedAt, 'a second use within the minute rewrote the row')
  })

  /* ---------------------------------------------------------------- introspection */

  await t.test('introspection answers what the credential is, and never what it holds', async () => {
    const { org, project } = await seedWorkspace(sql)
    const issued = await seedKey(sql, project.id, { scopes: ['market:read', 'wallet:read'] })
    const answer = introspect(issued.key, org.id)

    assert.equal(answer.display, issued.key.display)
    assert.equal(answer.projectId, project.id)
    assert.equal(answer.orgId, org.id)
    assert.equal(answer.environment, 'live')
    assert.deepEqual([...answer.scopes], ['market:read', 'wallet:read'])

    const text = JSON.stringify(answer)
    assert.ok(!text.includes(parseKey(issued.secretKey)!.secret), 'introspection returned the secret')
    assert.ok(!text.includes('hash'))
  })

  /* ---------------------------------------------------------------- service accounts */

  await t.test('creating a service account twice returns the first one', async () => {
    const { project } = await seedWorkspace(sql)
    const first = await createServiceAccount(store, { projectId: project.id, name: 'nightly' })
    const second = await createServiceAccount(store, { projectId: project.id, name: 'nightly' })
    assert.equal(second.id, first.id)
    const all = await sql<{ n: number }[]>`select count(*)::int as n from service_accounts`
    assert.equal(all[0]?.n, 1)
  })

  await t.test('a service account on an unknown project is a not-found', async () => {
    await assert.rejects(
      () =>
        createServiceAccount(store, {
          projectId: '00000000-0000-0000-0000-000000000000',
          name: 'x',
        }),
      // The foreign key fires first for a well-formed uuid that does not exist; either way the
      // account is not created.
      (err: unknown) => err instanceof NotFoundError || String(err).includes('service_accounts_project_id_fkey'),
    )
  })

  void db
})
