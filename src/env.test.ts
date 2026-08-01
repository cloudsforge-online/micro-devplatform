/**
 * Configuration, and the two names that are not negotiable.
 *
 * `DEVPLATFORM_TEST_DATABASE_URL` is asserted by name here because the reusable CI workflow exports
 * the Postgres DSN under exactly that spelling and then FAILS the build if the database-backed
 * suite skipped. A different spelling in `testsupport.ts` reads no DSN, skips silently, and turns
 * that guard into the false-green it exists to prevent — a build that is green because nothing ran.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
const GOOD_SECRET = 'a-real-looking-secret-value-0000'
const SECOND_SECRET = 'another-real-looking-secret-1111'

function base(): Record<string, string> {
  return {
    DEVPLATFORM_DATABASE_URL: 'postgres://user:pw@db:5432/devplatform',
    IDENTITY_JWKS_URL: 'http://identity:4000/.well-known/jwks.json',
    IDENTITY_ISSUER: 'http://identity:4000',
    DEVPLATFORM_INGEST_SECRETS: GOOD_SECRET,
    OUTBOX_SIGNING_SECRET: GOOD_SECRET,
  }
}

// `env.ts` validates `process.env` at IMPORT and exits the process on a bad configuration — right
// for a service, fatal for a test runner. So populate a valid environment first, then import it
// dynamically. `loadEnv` itself is pure over its source, so every case below passes an explicit
// object and never touches `process.env`. The estate's pattern; `lantern/src/env.test.ts:21` is the
// sibling that documents it.
for (const [key, value] of Object.entries(base())) process.env[key] = value
const { EnvError, SERVICE, loadEnv, parseSecretList } = await import('./env.ts')
const { TEST_DSN_VAR } = await import('./testsupport.ts')

/* ------------------------------------------------------------------ the names */

test('the test DSN variable is spelled exactly as CI exports it', () => {
  assert.equal(TEST_DSN_VAR, 'DEVPLATFORM_TEST_DATABASE_URL')
  assert.equal(TEST_DSN_VAR, `${SERVICE.toUpperCase()}_TEST_DATABASE_URL`)
})

test('the service reads exactly one connection string, and it is its own', () => {
  // Rule 1: one database per service. CI greps source for any other `*_DATABASE_URL` token, so this
  // is the local copy of that check — it fails here, in seconds, rather than in the build.
  const source = readFileSync(fileURLToPath(new URL('./env.ts', import.meta.url)), 'utf8')
  const found = [...source.matchAll(/([A-Z][A-Z0-9_]*_DATABASE_URL)/g)].map((m) => m[1])
  assert.deepEqual([...new Set(found)], ['DEVPLATFORM_DATABASE_URL'])
})

test('there is no admin token, no break-glass credential and no reveal switch', () => {
  const source = readFileSync(fileURLToPath(new URL('./env.ts', import.meta.url)), 'utf8')
  for (const forbidden of ['DEVPLATFORM_ADMIN_TOKEN', 'DEVPLATFORM_TOKEN', 'REVEAL', 'BREAK_GLASS']) {
    assert.ok(
      !new RegExp(`\\b${forbidden}\\b`).test(source.replace(/^\s*\*.*$/gm, '')),
      `${forbidden} appears in env.ts — a static string that can read or issue credentials is the ` +
        'shape SD-05 exists to retire',
    )
  }
})

/* ------------------------------------------------------------------ required values */

test('a valid environment loads', () => {
  const env = loadEnv(base(), 'host-1')
  assert.equal(env.databaseUrl, 'postgres://user:pw@db:5432/devplatform')
  assert.equal(env.port, 4000)
  assert.equal(env.instanceId, 'host-1')
  assert.deepEqual([...env.ingestSecrets], [GOOD_SECRET])
})

test('every required variable names itself when it is missing', () => {
  for (const name of [
    'DEVPLATFORM_DATABASE_URL',
    'IDENTITY_JWKS_URL',
    'IDENTITY_ISSUER',
    'DEVPLATFORM_INGEST_SECRETS',
    'OUTBOX_SIGNING_SECRET',
  ]) {
    const source = base()
    delete source[name]
    assert.throws(
      () => loadEnv(source),
      (err: unknown) => err instanceof EnvError && err.message.includes(name),
      `removing ${name} did not produce an error naming it`,
    )
  }
})

test('a blank value is a missing value', () => {
  assert.throws(() => loadEnv({ ...base(), DEVPLATFORM_DATABASE_URL: '   ' }), EnvError)
})

/* ------------------------------------------------------------------ placeholders */

test('a known placeholder does not boot', () => {
  // `.env.example` ships CHANGE_ME, and CHANGE_ME must not start. A default secret in source is not
  // convenient, it is catastrophic, and a placeholder that boots is a placeholder that reaches
  // production.
  for (const placeholder of ['CHANGE_ME', 'change-me', 'changeme', 'secret', 'placeholder']) {
    assert.throws(
      () => loadEnv({ ...base(), OUTBOX_SIGNING_SECRET: placeholder }),
      EnvError,
      `${placeholder} was accepted as a signing secret`,
    )
  }
})

test('a short secret does not boot, whatever it says', () => {
  assert.throws(() => loadEnv({ ...base(), OUTBOX_SIGNING_SECRET: 'hunter2' }), EnvError)
  assert.throws(() => loadEnv({ ...base(), OUTBOX_SIGNING_SECRET: 'x'.repeat(23) }), EnvError)
  assert.doesNotThrow(() => loadEnv({ ...base(), OUTBOX_SIGNING_SECRET: 'x'.repeat(24) }))
})

/* ------------------------------------------------------------------ the secret list */

test('the ingest secret list accepts several, so rotation has an overlap window', () => {
  const env = loadEnv({ ...base(), DEVPLATFORM_INGEST_SECRETS: `${GOOD_SECRET}, ${SECOND_SECRET}` })
  assert.deepEqual([...env.ingestSecrets], [GOOD_SECRET, SECOND_SECRET])
})

test('the ingest secret list refuses a duplicate', () => {
  // A duplicated secret makes "which key verified this" ambiguous, and that answer is what tells an
  // operator whether a rotation has finished.
  assert.throws(
    () => parseSecretList(`${GOOD_SECRET},${GOOD_SECRET}`, 'X'),
    (err: unknown) => err instanceof EnvError && err.message.includes('twice'),
  )
})

test('the ingest secret list refuses an empty list, a placeholder and a short entry', () => {
  assert.throws(() => parseSecretList('', 'X'), EnvError)
  assert.throws(() => parseSecretList(' , , ', 'X'), EnvError)
  assert.throws(() => parseSecretList(`${GOOD_SECRET},changeme`, 'X'), EnvError)
  assert.throws(() => parseSecretList(`${GOOD_SECRET},short`, 'X'), EnvError)
})

test('the ingest secret list is frozen', () => {
  const secrets = parseSecretList(GOOD_SECRET, 'X')
  assert.throws(() => {
    ;(secrets as string[]).push('another')
  })
})

/* ------------------------------------------------------------------ numbers */

test('a non-integer or out-of-range number is refused, naming the variable', () => {
  for (const [name, value] of [
    ['PORT', '0'],
    ['PORT', '70000'],
    ['PORT', 'four thousand'],
    ['DEVPLATFORM_DATABASE_POOL_MAX', '0'],
    ['DEVPLATFORM_DEFAULT_QUOTA_PER_MINUTE', '0'],
    ['DEVPLATFORM_WEBHOOK_DEADLINE_MS', '10'],
    ['DEVPLATFORM_WEBHOOK_MAX_ATTEMPTS', '0'],
  ] as const) {
    assert.throws(
      () => loadEnv({ ...base(), [name]: value }),
      (err: unknown) => err instanceof EnvError && err.message.includes(name),
      `${name}=${value} was accepted`,
    )
  }
})

test('a quota of zero is not expressible', () => {
  // Zero is a project that cannot make a request, which is a suspension — and a suspension is a
  // status on the organisation, not a limit on a meter.
  assert.throws(() => loadEnv({ ...base(), DEVPLATFORM_DEFAULT_QUOTA_PER_MINUTE: '0' }), EnvError)
  assert.throws(() => loadEnv({ ...base(), DEVPLATFORM_DEFAULT_QUOTA_PER_MONTH: '0' }), EnvError)
})

test('a rollup must outlive the events it summarises', () => {
  assert.throws(
    () =>
      loadEnv({
        ...base(),
        DEVPLATFORM_USAGE_EVENT_RETENTION_DAYS: '90',
        DEVPLATFORM_USAGE_ROLLUP_RETENTION_DAYS: '30',
      }),
    (err: unknown) => err instanceof EnvError && err.message.includes('outlives'),
  )
  assert.doesNotThrow(() =>
    loadEnv({
      ...base(),
      DEVPLATFORM_USAGE_EVENT_RETENTION_DAYS: '30',
      DEVPLATFORM_USAGE_ROLLUP_RETENTION_DAYS: '30',
    }),
  )
})

test('LOG_LEVEL is one of four, and says so', () => {
  for (const level of ['debug', 'info', 'warn', 'error']) {
    assert.equal(loadEnv({ ...base(), LOG_LEVEL: level }).logLevel, level)
  }
  assert.throws(
    () => loadEnv({ ...base(), LOG_LEVEL: 'verbose' }),
    (err: unknown) => err instanceof EnvError && err.message.includes('LOG_LEVEL'),
  )
})

test('the defaults are the ones the README and .env.example state', () => {
  const env = loadEnv(base())
  assert.equal(env.defaultQuotaPerMinute, 600)
  assert.equal(env.defaultQuotaPerMonth, 1_000_000)
  assert.equal(env.webhookRotationOverlapMinutes, 1_440)
  assert.equal(env.webhookMaxAttempts, 8)
  assert.equal(env.usageEventRetentionDays, 35)
  assert.equal(env.usageRollupRetentionDays, 400)
})

/* ------------------------------------------------------------------ .env.example */

test('.env.example declares every variable this service reads, with no real secret', () => {
  const example = readFileSync(fileURLToPath(new URL('../.env.example', import.meta.url)), 'utf8')
  const source = readFileSync(fileURLToPath(new URL('./env.ts', import.meta.url)), 'utf8')

  // Every variable read by `loadEnv`, taken from the source rather than a list — a list drifts.
  const read = new Set(
    [...source.matchAll(/source,\s*'([A-Z][A-Z0-9_]*)'/g)].map((m) => m[1] as string),
  )
  assert.ok(read.size >= 10, `expected many variables, found ${read.size}`)

  const declared = new Set(
    example
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0 && !line.startsWith('#'))
      .map((line) => line.split('=')[0]?.trim() ?? ''),
  )
  for (const name of read) {
    assert.ok(declared.has(name), `.env.example does not declare ${name}`)
  }
  for (const name of declared) {
    assert.ok(read.has(name), `.env.example declares ${name}, which env.ts does not read`)
  }

  // And nothing in it is a working secret. Every secret slot is a placeholder that does not boot.
  // Matched on the variable NAME ending in _SECRET/_SECRETS rather than on the line containing the
  // word: `DEVPLATFORM_WEBHOOK_ROTATION_OVERLAP_MINUTES` is a duration, and a check that demanded a
  // placeholder there would be a check somebody deletes.
  let checked = 0
  for (const line of example.split('\n')) {
    if (line.trim().startsWith('#')) continue
    const name = line.split('=')[0]?.trim() ?? ''
    if (!/_SECRETS?$/.test(name)) continue
    checked += 1
    const value = line.split('=').slice(1).join('=').trim()
    assert.ok(value.startsWith('CHANGE_ME'), `${name} does not carry a CHANGE_ME placeholder`)
  }
  assert.ok(checked >= 2, `expected to check at least two secret slots, checked ${checked}`)
})
