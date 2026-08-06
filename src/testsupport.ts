/**
 * The database harness, and the fakes.
 *
 * **A database test runs only against a database whose name says it is a test database.**
 *
 * Not a convenience: `resetDevplatform` truncates every table this service owns, and requiring
 * "test" in the name is the difference between a red build and a destroyed credential store. This
 * service holds `api_keys` — the rows behind every third-party integration on the platform — and
 * they are not recoverable from anything, because the secret half was never stored. Emptying this
 * table is not "lose some data"; it is "every customer's integration stops, permanently, and each
 * one must be re-issued by hand".
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE VARIABLE IS `DEVPLATFORM_TEST_DATABASE_URL`, SPELLED EXACTLY.**
 *
 * The reusable workflow at `cloudsforge-online/micro-org/.github/workflows/service-ci.yml` exports
 * the CI Postgres DSN under `<SERVICE>_TEST_DATABASE_URL` and then GREPS the test output for a skip
 * — if the database-backed suite skipped, the build FAILS rather than going green on nothing. A
 * different spelling here reads no DSN, skips silently, and turns that guard into the exact
 * false-green it exists to prevent. So the name is not negotiable and is asserted by `env.test.ts`.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **THE TEST KDF IS CHEAP, AND THAT IS A CORRECTNESS DECISION RATHER THAN A SPEED ONE.**
 *
 * `TEST_PARAMS` runs scrypt at N=2. A suite that hashes at the production work factor spends ~60 ms
 * per key and several minutes per run, and a suite that takes minutes is a suite whose
 * `--test-concurrency=1` gets "optimised" away — which deadlocks it, because every file here
 * truncates. What must NOT be cheapened is the property under test: the constant-cost verification
 * in `keys.test.ts` is proven by COUNTING kdf invocations through the `Kdf` seam, so it holds at
 * any work factor, and `apikeys.test.ts` separately proves a row written at TEST_PARAMS is
 * re-hashed to the current parameters on its next successful use.
 */

import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import postgres from 'postgres'
import { migrate, type Sql } from '@cloudsforge/db'
import { Logger, Metrics } from '@cloudsforge/telemetry'
import { MIGRATIONS, TABLES } from './migrations.ts'
import { registerServiceMetrics } from './server.ts'
import { enrolOrg, createProject, type DeveloperOrg, type Project } from './orgs.ts'
import { issueApiKey, type IssuedApiKey } from './apikeys.ts'
import type { Db, Tx } from './outbox.ts'
import type { KeyEnvironment, ScryptParams } from './keys.ts'

// Named `TEST_DSN_VAR` rather than spelling `..._DATABASE_URL` in an identifier: the estate's
// Rule 1 CI check greps source for any `*_DATABASE_URL` token that is not this service's own, and a
// constant NAMED after the variable would trip it. The value is the honest spelling.
export const TEST_DSN_VAR = 'DEVPLATFORM_TEST_DATABASE_URL'

const url = process.env[TEST_DSN_VAR]

export const enabled = Boolean(url && /test/i.test(url))

/** node:test's `{ skip }` option: a string reason disables the suite; `false` runs it. */
export const skip = enabled ? false : `set ${TEST_DSN_VAR} (name must contain "test")`

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/** The `@cloudsforge/db` view of a postgres.js client. */
export const db = (sql: postgres.Sql): Sql => sql as unknown as Sql

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture
 * would let the constraints drift out of the tests that prove they fire — and `api_keys_slow_kdf_only`,
 * `api_keys_scopes_no_wildcard` and `quota_windows_within_limit` are the three most important lines
 * in this repository.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as Sql, MIGRATIONS, { service: 'devplatform-test' })
}

/** Empty every table this service owns. `jobs` included, so a lease cannot leak between files. */
export async function resetDevplatform(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${[...TABLES, 'jobs'].join(', ')} restart identity cascade`)
}

/** Logs are discarded rather than silenced, so a serialisation failure still throws. */
export function quietLogger(): Logger {
  return new Logger({ service: 'devplatform-test', sink: () => {} })
}

export function testMetrics(): Metrics {
  return registerServiceMetrics(new Metrics())
}

/* ------------------------------------------------------------------ the cheap KDF */

/**
 * scrypt at the lowest legal cost. See the file header for why this is safe.
 *
 * N=2 still satisfies `api_keys_slow_kdf_only`, which checks the ALGORITHM ENCODING rather than the
 * work factor — deliberately, because a CHECK that pinned N would refuse the day someone raised it,
 * which is the operation the recorded-parameters design exists to enable.
 */
export const TEST_PARAMS: ScryptParams = { N: 2, r: 8, p: 1, keyLen: 64 }

/* ------------------------------------------------------------------ fixtures */

let counter = 0

/** A slug that is unique within a run and still passes `developer_orgs_slug_shape`. */
export function uniqueSlug(prefix = 'acme'): string {
  counter += 1
  return `${prefix}-${counter}-${Math.floor(Math.random() * 1e6)}`
}

export async function seedOrg(sql: postgres.Sql, name = 'Acme'): Promise<DeveloperOrg> {
  const slug = uniqueSlug()
  return enrolOrg(sql as unknown as Db, { identityOrgId: `org_${slug}`, name, slug })
}

export async function seedProject(sql: postgres.Sql, orgId: string, name = 'Checkout'): Promise<Project> {
  const outcome = await sql.begin(async (tx) => ({
    value: await createProject(tx as unknown as Tx, { orgId, name, slug: uniqueSlug('proj') }),
  }))
  return outcome.value
}

/** An org, a project and both environments, in one call. The starting point of most cases. */
export async function seedWorkspace(
  sql: postgres.Sql,
): Promise<{ org: DeveloperOrg; project: Project }> {
  const org = await seedOrg(sql)
  const project = await seedProject(sql, org.id)
  return { org, project }
}

/**
 * The default owner of a seeded key, as an `Actor` and with a UUID subject.
 *
 * This was `'user_test'`, which is neither. `created_by` is written as `actorOf(caller)` in
 * production (`server.ts`), and since `emitKeyRevoked` now derives the revocation's `userId`
 * from that column, a fixture in a shape no code path produces would have let every seeded key
 * emit an event that reaches nobody while the suite stayed green — the fixture answering the
 * question instead of the service, which is the failure `topics.test.ts` was rewritten to stop.
 */
export const TEST_KEY_OWNER = '018f0000-0000-7000-8000-00000000f00d'

export async function seedKey(
  sql: postgres.Sql,
  projectId: string,
  options: {
    readonly environment?: KeyEnvironment
    readonly scopes?: readonly string[]
    readonly name?: string
    readonly expiresAt?: Date | null
    /** `user:<uuid>` or `service:<display>` — the two `actorOf` really produces. */
    readonly createdBy?: string
  } = {},
): Promise<IssuedApiKey> {
  const outcome = await sql.begin(async (tx) => ({
    value: await issueApiKey(
      tx as unknown as Tx,
      {
        projectId,
        environment: options.environment ?? 'live',
        name: options.name ?? 'test key',
        scopes: options.scopes ?? ['devplatform:read'],
        createdBy: options.createdBy ?? `user:${TEST_KEY_OWNER}`,
        expiresAt: options.expiresAt ?? null,
      },
      { params: TEST_PARAMS },
    ),
  }))
  return outcome.value
}

/* ------------------------------------------------------------------ a real HTTP target */

export interface FakeSubscriber {
  readonly baseUrl: string
  /** Every delivery received: the raw body, and the headers, exactly as they arrived. */
  readonly deliveries: ReadonlyArray<{ body: string; headers: Record<string, string> }>
  setStatus(status: number): void
  /**
   * Stop answering entirely.
   *
   * The socket is accepted and nothing is written — what a wedged subscriber actually looks like,
   * and a genuinely different failure from a refused connection. A test that only ever simulates
   * ECONNREFUSED never exercises the delivery deadline, and the deadline is what stops one bad
   * endpoint holding a job lease open until it expires and a second worker takes the same job.
   */
  hang(value: boolean): void
  close(): Promise<void>
}

export async function fakeSubscriber(): Promise<FakeSubscriber> {
  const deliveries: Array<{ body: string; headers: Record<string, string> }> = []
  let status = 200
  let hanging = false
  const open = new Set<import('node:net').Socket>()

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => {
      const headers: Record<string, string> = {}
      for (const [name, value] of Object.entries(req.headers)) {
        headers[name] = Array.isArray(value) ? (value[0] ?? '') : (value ?? '')
      }
      deliveries.push({ body: Buffer.concat(chunks).toString('utf8'), headers })
      if (hanging) return
      const payload = `${JSON.stringify({ ok: status < 400 })}\n`
      res.writeHead(status, {
        'content-type': 'application/json; charset=utf-8',
        'content-length': Buffer.byteLength(payload),
      })
      res.end(payload)
    })
  })
  server.on('connection', (socket) => {
    open.add(socket)
    socket.on('close', () => open.delete(socket))
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const port = (server.address() as AddressInfo).port

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    deliveries,
    setStatus(value) {
      status = value
    },
    hang(value) {
      hanging = value
    },
    close: () =>
      new Promise<void>((resolve) => {
        // A hung request holds its socket open, so `server.close()` alone would never call back and
        // the test file would sit there until the runner killed it.
        for (const socket of open) socket.destroy()
        server.close(() => resolve())
      }),
  }
}
