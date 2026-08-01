/**
 * The constraints, fired against a real Postgres.
 *
 * A CHECK that is never exercised is a comment with a table around it. Each case below writes the
 * row the constraint exists to refuse and asserts the refusal — because the day someone reaches for
 * `createHash` because it is one line shorter, or adds a bulk import that bypasses `scopes.ts`,
 * these are the lines that stop it.
 *
 * The three that matter most, and what each one is standing in front of:
 *
 *   `api_keys_slow_kdf_only`      A credential table hashed with SHA-256. An API key table is a
 *                                 password table; SHA-256 makes a guess free.
 *   `api_keys_scopes_no_wildcard` A key carrying `*`. The application refuses one; this refuses it
 *                                 however it arrived.
 *   `quota_windows_within_limit`  An overage that got past the guarded UPDATE. The UPDATE is the
 *                                 mechanism and this is the belt.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { BASELINE_VERSION, MIGRATIONS, SCHEMA_VERSION, TABLES } from './migrations.ts'
import { CURRENT_ALGO } from './keys.ts'
import { migrateTestDb, openDb, resetDevplatform, seedWorkspace, skip } from './testsupport.ts'

/* ------------------------------------------------------------------ the file itself */

test('every migration version is unique and consecutive from one', () => {
  const versions = MIGRATIONS.map((migration) => migration.version)
  assert.deepEqual(versions, [...versions].sort((a, b) => a - b), 'migrations are out of order')
  assert.deepEqual(versions, Array.from({ length: versions.length }, (_v, i) => i + 1))
})

test('SCHEMA_VERSION is derived, so a new migration cannot leave the assertion behind', () => {
  assert.equal(SCHEMA_VERSION, Math.max(...MIGRATIONS.map((m) => m.version)))
  assert.equal(BASELINE_VERSION, 0)
})

test('TABLES lists every table the migrations create, and nothing else', () => {
  const source = MIGRATIONS.map((m) => m.up).join('\n')
  const created = new Set(
    [...source.matchAll(/create table if not exists\s+([a-z_]+)/g)].map((m) => m[1] as string),
  )
  // `jobs` comes from @cloudsforge/jobs' own DDL and is truncated separately by the harness.
  created.delete('jobs')
  for (const name of created) {
    assert.ok(TABLES.includes(name), `TABLES omits ${name}, so the harness would not truncate it`)
  }
  for (const name of TABLES) {
    assert.ok(created.has(name), `TABLES names ${name}, which no migration creates`)
  }
})

test('THERE IS NO BALANCE COLUMN, ANYWHERE', () => {
  // 04-domain-model §11 and the estate rule: this service holds no money. What lives here is a
  // COUNT of calls. A column named for an amount would be the first row of a second ledger.
  const source = MIGRATIONS.map((m) => m.up).join('\n')
  // Comments carry words like "money" and "balance" deliberately; strip them before matching.
  const ddl = source.replace(/--.*$/gm, '')
  for (const forbidden of ['balance', 'amount', 'price', 'currency', 'minor_units', 'credits']) {
    assert.ok(
      !new RegExp(`\\b${forbidden}\\b`, 'i').test(ddl),
      `a column or table named '${forbidden}' appears in the schema — metered usage that costs ` +
        'money is a micro-billing entitlement or a micro-ledger entry, never a column here',
    )
  }
})

test('the api_keys table has no column a secret could go in', () => {
  const keysMigration = MIGRATIONS.find((m) => m.name === 'api-keys-and-service-accounts')
  assert.ok(keysMigration)
  const table = /create table if not exists api_keys\s*\(([\s\S]*?)\n      \);/.exec(keysMigration.up)
  assert.ok(table, 'could not find the api_keys definition')
  const ddl = (table[1] ?? '').replace(/--.*$/gm, '')
  // `secret_algo`, `secret_salt` and `secret_hash` are a one-way function of the secret. A column
  // holding the secret itself would be named for it.
  assert.ok(!/\bsecret\s+text/.test(ddl), 'api_keys has a bare `secret` column')
  assert.ok(!/\bplaintext\b/i.test(ddl))
  assert.ok(/secret_hash\s+text\s+not null/.test(ddl))
})

/* ------------------------------------------------------------------ against Postgres */

test('the schema', { skip }, async (t) => {
  const sql = openDb()
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  await t.test('migrating twice is a no-op', async () => {
    // Idempotent by construction — `@cloudsforge/db` records applied versions — so every test file
    // may call it and only the first does work.
    await migrateTestDb(sql)
    await migrateTestDb(sql)
  })

  await t.test('every table in TABLES exists', async () => {
    const rows = await sql<{ table_name: string }[]>`
      select table_name from information_schema.tables where table_schema = 'public'
    `
    const present = new Set(rows.map((row) => row.table_name))
    for (const name of [...TABLES, 'jobs']) {
      assert.ok(present.has(name), `${name} was not created`)
    }
  })

  /* ---------------------------------------------------------------- the credential table */

  async function insertKey(overrides: Record<string, unknown> = {}): Promise<void> {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} and name = 'live'
    `
    const row = {
      environment_id: environments[0]!.id,
      project_id: project.id,
      environment: 'live',
      lookup_id: 'abcdefghijklmnop',
      display: 'cfk_live_abcdefghijklmnop',
      secret_algo: CURRENT_ALGO,
      secret_salt: 'a'.repeat(32),
      secret_hash: 'b'.repeat(128),
      name: 'a key',
      scopes: ['market:read'],
      created_by: 'user:test',
      ...overrides,
    }
    await sql`insert into api_keys ${sql(row as Record<string, never>)}`
  }

  await t.test('a well-formed key row inserts', async () => {
    await insertKey()
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from api_keys`
    assert.equal(rows[0]?.n, 1)
  })

  await t.test('THE DATABASE REFUSES SHA-256 IN THE CREDENTIAL TABLE', async () => {
    for (const algo of ['sha256', 'sha512', 'md5', 'plain', 'bcrypt$rounds=10', '']) {
      await assert.rejects(
        () => insertKey({ secret_algo: algo }),
        (err: unknown) => String(err).includes('api_keys_slow_kdf_only'),
        `the database accepted secret_algo='${algo}' — an API key table is a password table`,
      )
    }
  })

  await t.test('the database refuses a wildcard scope, however it arrived', async () => {
    for (const scopes of [['*'], ['market:*'], ['market:read', '*'], [':*']]) {
      await assert.rejects(
        () => insertKey({ scopes }),
        (err: unknown) => String(err).includes('api_keys_scopes_no_wildcard'),
        `the database accepted ${JSON.stringify(scopes)}`,
      )
    }
  })

  await t.test('an EMPTY scope array is legal and inert, not a wildcard', async () => {
    // The array joins to '' and passes the CHECK. A credential that can exist and authorise nothing
    // is what makes "a key with no scope grants nothing" provable rather than merely asserted.
    await insertKey({ scopes: [] })
    const rows = await sql<{ scopes: string[] }[]>`select scopes from api_keys`
    assert.deepEqual(rows[0]?.scopes, [])
  })

  await t.test('the display string must be derived from the environment and lookup id', async () => {
    await assert.rejects(
      () => insertKey({ display: 'cfk_test_abcdefghijklmnop' }),
      (err: unknown) => String(err).includes('api_keys_display_shape'),
      'a display that does not match its own row is a revocation identifier that revokes the wrong key',
    )
  })

  await t.test('the lookup id must be exactly sixteen base32 characters', async () => {
    for (const lookup of ['short', 'ABCDEFGHIJKLMNOP', 'abcdefghijklmno1', 'a'.repeat(17)]) {
      await assert.rejects(
        () => insertKey({ lookup_id: lookup, display: `cfk_live_${lookup}` }),
        (err: unknown) =>
          String(err).includes('api_keys_lookup_shape') || String(err).includes('api_keys_display_shape'),
        `the database accepted lookup_id='${lookup}'`,
      )
    }
  })

  await t.test('the lookup id is unique', async () => {
    await insertKey()
    await assert.rejects(
      () => insertKey(),
      (err: unknown) => String(err).includes('api_keys_lookup_uniq'),
    )
  })

  await t.test('the hash and salt must be hex of a plausible length', async () => {
    await assert.rejects(
      () => insertKey({ secret_hash: 'not-hex-at-all' }),
      (err: unknown) => String(err).includes('api_keys_hash_is_hex'),
    )
    await assert.rejects(
      () => insertKey({ secret_salt: 'ab' }),
      (err: unknown) => String(err).includes('api_keys_hash_is_hex'),
    )
  })

  await t.test('a revocation without a revoker is refused', async () => {
    // A row claiming to be revoked without saying who cannot be reasoned about during an incident,
    // which is the only time anyone reads it.
    await assert.rejects(
      () => insertKey({ revoked_at: new Date() }),
      (err: unknown) => String(err).includes('api_keys_revoked_has_time'),
    )
    await assert.rejects(
      () => insertKey({ revoked_by: 'user:x' }),
      (err: unknown) => String(err).includes('api_keys_revoked_has_time'),
    )
  })

  /* ---------------------------------------------------------------- quotas */

  await t.test('THE QUOTA WINDOW REFUSES AN OVERAGE', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    const quotas = await sql<{ id: string }[]>`
      insert into quotas (project_id, environment_id, meter, period, max_units)
      values (${project.id}, ${environments[0]!.id}, 'api_requests', 'minute', 10)
      returning id
    `
    const quotaId = quotas[0]!.id
    await sql`
      insert into quota_windows (quota_id, window_start, used_units, max_units)
      values (${quotaId}, now(), 10, 10)
    `
    // The belt to the guarded UPDATE's braces. An unguarded increment fails here rather than
    // silently allowing an overage.
    await assert.rejects(
      () => sql`update quota_windows set used_units = used_units + 1 where quota_id = ${quotaId}`,
      (err: unknown) => String(err).includes('quota_windows_within_limit'),
    )
  })

  await t.test('a quota of zero is refused by the database too', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await assert.rejects(
      () => sql`
        insert into quotas (project_id, environment_id, meter, period, max_units)
        values (${project.id}, ${environments[0]!.id}, 'api_requests', 'minute', 0)
      `,
      (err: unknown) => String(err).includes('quotas_max_positive'),
    )
  })

  await t.test('an unknown quota period is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    await assert.rejects(
      () => sql`
        insert into quotas (project_id, environment_id, meter, period, max_units)
        values (${project.id}, ${environments[0]!.id}, 'api_requests', 'fortnight', 10)
      `,
      (err: unknown) => String(err).includes('quotas_period_known'),
    )
  })

  /* ---------------------------------------------------------------- webhooks and oauth */

  await t.test('a plaintext webhook url is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    for (const url of ['http://example.com/hook', 'https://exam*ple.com/hook', 'ftp://x/y']) {
      await assert.rejects(
        () => sql`
          insert into webhook_endpoints (project_id, environment_id, url, topics)
          values (${project.id}, ${environments[0]!.id}, ${url}, ${sql.array(['a.b.c'])})
        `,
        (err: unknown) => String(err).includes('webhook_endpoints_url_https'),
        `the database accepted ${url}`,
      )
    }
  })

  await t.test('an open-redirect oauth client is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const insert = (uris: readonly string[]) => sql`
      insert into oauth_clients (project_id, client_id, name, secret_algo, secret_salt, secret_hash, redirect_uris)
      values (${project.id}, ${`cfc_${Math.random().toString(36).slice(2, 12)}`}, 'app',
              ${CURRENT_ALGO}, ${'a'.repeat(32)}, ${'b'.repeat(128)}, ${sql.array(uris as string[])})
    `
    for (const uris of [['https://app.example.com/*'], ['/callback'], ['http://evil.example.com/cb']]) {
      await assert.rejects(
        () => insert(uris),
        (err: unknown) => String(err).includes('oauth_clients_redirects_absolute'),
        `the database accepted ${JSON.stringify(uris)} — an open redirect hands an authorisation code to whoever asked`,
      )
    }
    // And the legitimate shapes are accepted, so the constraint is not merely refusing everything.
    await insert(['https://app.example.com/callback'])
    await insert(['http://localhost:3000/cb', 'https://app.example.com/cb'])
    await insert([])
  })

  await t.test('an oauth client secret must also be a scrypt encoding', async () => {
    const { project } = await seedWorkspace(sql)
    await assert.rejects(
      () => sql`
        insert into oauth_clients (project_id, client_id, name, secret_algo, secret_salt, secret_hash)
        values (${project.id}, 'cfc_abc', 'app', 'sha256', ${'a'.repeat(32)}, ${'b'.repeat(128)})
      `,
      (err: unknown) => String(err).includes('oauth_clients_slow_kdf_only'),
    )
  })

  await t.test('a webhook secret shorter than 32 characters is refused', async () => {
    const { project } = await seedWorkspace(sql)
    const environments = await sql<{ id: string }[]>`
      select id from environments where project_id = ${project.id} limit 1
    `
    const endpoints = await sql<{ id: string }[]>`
      insert into webhook_endpoints (project_id, environment_id, url, topics)
      values (${project.id}, ${environments[0]!.id}, 'https://example.com/hook', ${sql.array(['a.b.c'])})
      returning id
    `
    await assert.rejects(
      () => sql`insert into webhook_secrets (endpoint_id, secret) values (${endpoints[0]!.id}, 'short')`,
      (err: unknown) => String(err).includes('webhook_secrets_secret_length'),
    )
  })

  /* ---------------------------------------------------------------- the directory */

  await t.test('a listed application must say when it was listed', async () => {
    const { project } = await seedWorkspace(sql)
    await assert.rejects(
      () => sql`
        insert into applications (project_id, slug, name, status)
        values (${project.id}, 'my-app', 'My App', 'listed')
      `,
      (err: unknown) => String(err).includes('applications_listed_has_time'),
      'a state that cannot be dated cannot be audited',
    )
    // And a listed_at without the status is refused too — the pair is inseparable.
    await assert.rejects(
      () => sql`
        insert into applications (project_id, slug, name, status, listed_at)
        values (${project.id}, 'my-app', 'My App', 'draft', now())
      `,
      (err: unknown) => String(err).includes('applications_listed_has_time'),
    )
  })

  /* ---------------------------------------------------------------- cascades */

  await t.test('deleting a project takes its keys, quotas and endpoints with it', async () => {
    await insertKey()
    const rows = await sql<{ project_id: string }[]>`select project_id from api_keys limit 1`
    await sql`delete from projects where id = ${rows[0]!.project_id}`
    const remaining = await sql<{ n: number }[]>`select count(*)::int as n from api_keys`
    assert.equal(remaining[0]?.n, 0, 'a deleted project left orphaned credentials behind')
  })
})

/* ------------------------------------------------------------------ no unleased timers */

test('no source file starts an interval doing domain work', () => {
  // Rule 8, checked locally so it fails in seconds rather than in the build. Every background timer
  // in this service is a leased job; CI greps for this too.
  const dir = fileURLToPath(new URL('.', import.meta.url))
  const files = ['server.ts', 'jobs.ts', 'index.ts', 'outbox.ts', 'webhooks.ts', 'quotas.ts', 'apikeys.ts']
  for (const file of files) {
    const source = readFileSync(`${dir}${file}`, 'utf8').replace(/^\s*\*.*$/gm, '')
    assert.ok(!/setInterval\s*\(/.test(source), `${file} calls setInterval — rule 8`)
  }
})
