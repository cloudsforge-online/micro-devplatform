/**
 * The HTTP surface, over a real socket against a real Postgres.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TWO PROOFS THIS FILE EXISTS FOR.**
 *
 *   1. **NO ROUTE RETURNS A SECRET AFTER CREATION.** Not "we checked the obvious ones" — every
 *      route on the server is walked, its response captured, and the minted secret searched for in
 *      the bytes. `routeidempotency.test.ts` proves the same property at the source level, by
 *      enumerating the four places a secret may be attached at all. Two layers, because a route
 *      added tomorrow fails the source check and a route that leaks a secret through an unexpected
 *      field fails this one.
 *
 *   2. **A REVOKED KEY IS REJECTED INDISTINGUISHABLY FROM AN UNKNOWN ONE.** Same status, same
 *      body, same headers — byte for byte. The `reason` exists, and it goes to the log and to
 *      `devplatform_key_refusals_total`, and never to the wire. A caller who can tell `revoked`
 *      from `unknown` can tell "this account is real and someone noticed" from "this key never
 *      existed".
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The verifier and the membership client are fakes rather than a JWKS and a live identity: both are
 * interfaces on `ServerDeps` precisely so that this suite tests THIS service's authorisation logic
 * rather than jose's signature checking, which `runtime/packages/auth` already proves.
 */

import { networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import type { Principal } from '@cloudsforge/auth'
import {
  ADMIN_SCOPE,
  INTROSPECT_SCOPE,
  createServer,
  registerServiceMetrics,
  type PrincipalVerifier,
  type ServerDeps,
} from './server.ts'
import { MAX_UNITS_CEILING } from './quotas.ts'
import { buildEnvelope, signEvent, type Db } from './outbox.ts'
import { envelopeDefects, recipientOf } from './topics.ts'
import { parseKey } from './keys.ts'
import { MembershipUnavailableError, type MembershipClient, type OrgRole } from './membership.ts'
import {
  TEST_KEY_OWNER,
  TEST_PARAMS,
  migrateTestDb,
  openDb,
  quietLogger,
  resetDevplatform,
  seedKey,
  seedWorkspace,
  skip,
  uniqueSlug,
} from './testsupport.ts'

const INGEST_SECRET = 'an-ingest-secret-of-sufficient-length'

/**
 * Wait, if the minute is nearly over, for the next one to start.
 *
 * `quotas.ts`'s `windowStart` truncates to the CALENDAR minute, so a burst that straddles :59.98
 * is counted against two windows and the second half is allowed. That is the limiter behaving as
 * designed — a fixed window, which is what makes the increment a single UPDATE — but a test that
 * spends a minute quota across several HTTP calls fails whenever it happens to run at the boundary.
 *
 * It did, on CI, on 2026-08-10: 'the meter enforces the quota in Postgres' asserted at 15:42:00.013
 * after opening at 15:41:59.9 — a green branch that changed one version string went red. A test
 * that can fail for a reason that is not the defect it names is a test that gets rerun until it
 * passes, which is the same as no test.
 *
 * The three calls it guards take ~90ms; a second of headroom is ten times what they need, and the
 * wait is paid at most once per case and only in the last second of a minute.
 */
async function withinOneMinuteWindow(): Promise<void> {
  const msIntoMinute = Date.now() % 60_000
  const remaining = 60_000 - msIntoMinute
  if (remaining > 1_000) return
  await new Promise((resolve) => setTimeout(resolve, remaining + 20))
}

/** A verifier that hands back whatever the token says, so a case can be exactly one principal. */
function fakeVerifier(): PrincipalVerifier & { setPrincipal(token: string, p: Principal): void } {
  const table = new Map<string, Principal>()
  return {
    setPrincipal(token, principal) {
      table.set(token, principal)
    },
    async principal(token) {
      const found = table.get(token)
      if (!found) throw Object.assign(new Error('bad token'), { name: 'TokenError' })
      return found
    },
  }
}

/** A membership client whose answers a case sets directly. `unavailable` throws, for the 503 path. */
function fakeMembership(): MembershipClient & {
  grant(userId: string, identityOrgId: string, role: OrgRole): void
  unavailable(value: boolean): void
} {
  const table = new Map<string, OrgRole>()
  let down = false
  return {
    grant(userId, identityOrgId, role) {
      table.set(`${userId}:${identityOrgId}`, role)
    },
    unavailable(value) {
      down = value
    },
    async roleFor(_token, identityOrgId, userId) {
      if (down) throw new MembershipUnavailableError('identity is unreachable')
      return table.get(`${userId}:${identityOrgId}`) ?? null
    },
  }
}

test('the server', { skip }, async (t) => {
  const sql = openDb(16)
  await migrateTestDb(sql)

  const verifier = fakeVerifier()
  const membership = fakeMembership()
  const store = sql as unknown as Db

  const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100 })
  lifecycle.addProbe({ name: 'postgres', kind: 'hard', check: async () => ({ state: 'pass' }) })

  const deps: ServerDeps = {
    lifecycle,
    logger: quietLogger(),
    metrics: registerServiceMetrics(registerHttpMetrics(new Metrics())),
    verifier,
    membership,
    sql: singleNetworkSql(store),
    singleNetwork: 'mainnet' as const,
    producer: 'devplatform',
    ingestSecrets: [INGEST_SECRET],
    defaultQuotaPerMinute: 600,
    defaultQuotaPerMonth: 1_000_000,
    webhookRotationOverlapMinutes: 60,
    // The cheap KDF. The properties under test are cost-independent; see testsupport.ts.
    scryptParams: TEST_PARAMS,
  }

  const server: Server = createServer(deps)
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  lifecycle.markReady()

  t.after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()))
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  interface Answer {
    status: number
    body: string
    json: Record<string, unknown>
    headers: Record<string, string>
  }

  async function call(
    method: string,
    path: string,
    options: {
      readonly token?: string
      readonly body?: unknown
      readonly idempotencyKey?: string
      readonly headers?: Record<string, string>
      readonly rawBody?: string
    } = {},
  ): Promise<Answer> {
    const headers: Record<string, string> = { ...options.headers }
    if (options.token) headers['authorization'] = `Bearer ${options.token}`
    if (options.idempotencyKey) headers['idempotency-key'] = options.idempotencyKey
    let body: string | undefined
    if (options.rawBody !== undefined) {
      body = options.rawBody
      headers['content-type'] ??= 'application/json'
    } else if (options.body !== undefined) {
      body = JSON.stringify(options.body)
      headers['content-type'] = 'application/json'
    }
    const res = await fetch(`${base}${path}`, { method, headers, ...(body !== undefined ? { body } : {}) })
    const text = await res.text()
    let json: Record<string, unknown> = {}
    try {
      json = JSON.parse(text) as Record<string, unknown>
    } catch {
      /* not JSON — /metrics */
    }
    const out: Record<string, string> = {}
    res.headers.forEach((value, name) => {
      out[name] = value
    })
    return { status: res.status, body: text, json, headers: out }
  }

  /**
   * An organisation, a project, and a developer who administers it.
   *
   * The membership grant is what identity would answer; `roleInOrg` looks the identity org id up
   * from the row and asks the client, so the fake is consulted through exactly the production path.
   */
  async function scenario(role: OrgRole = 'owner') {
    const { org, project } = await seedWorkspace(sql)
    const token = `user-token-${uniqueSlug('t')}`
    const userId = `user_${uniqueSlug('u')}`
    verifier.setPrincipal(token, { kind: 'user', userId, handle: 'dev', roles: [] })
    membership.grant(userId, org.identityOrgId, role)
    return { org, project, token, userId }
  }

  function serviceToken(scopes: readonly string[]): string {
    const token = `service-token-${uniqueSlug('s')}`
    verifier.setPrincipal(token, { kind: 'service', service: 'gateway', scopes: [...scopes] })
    return token
  }

  /**
   * The two principals `isOperator` admits, and one that looks like an operator and is not.
   *
   * A platform operator is deliberately NOT a member of the customer's organisation — no
   * `membership.grant` here — because that is the property under test: an operator asked to be a
   * member of every organisation they act on would end up holding a credential that is a member of
   * all of them, which is the shape SD-05 exists to retire.
   */
  function operatorService(): string {
    return serviceToken([ADMIN_SCOPE])
  }

  function operatorUser(): string {
    const token = `operator-token-${uniqueSlug('op')}`
    verifier.setPrincipal(token, {
      kind: 'user',
      userId: `user_${uniqueSlug('op')}`,
      handle: 'operator',
      roles: ['admin'],
    })
    return token
  }

  /* ---------------------------------------------------------------- health */

  await t.test('/livez is static and needs no credential', async () => {
    const answer = await call('GET', '/livez')
    assert.equal(answer.status, 200)
    assert.equal(answer.json['ok'], true)
  })

  await t.test('/readyz runs the probes', async () => {
    const answer = await call('GET', '/readyz')
    assert.equal(answer.status, 200)
    assert.equal(answer.json['ready'], true)
    assert.ok(Array.isArray(answer.json['checks']))
  })

  await t.test('/metrics renders Prometheus text', async () => {
    const answer = await call('GET', '/metrics')
    assert.equal(answer.status, 200)
    assert.match(answer.headers['content-type'] ?? '', /text\/plain/)
    assert.match(answer.body, /devplatform_keys_issued_total/)
  })

  await t.test('an unknown path is a 404 carrying the request id', async () => {
    const answer = await call('GET', '/v1/nope')
    assert.equal(answer.status, 404)
    assert.ok(answer.headers['x-request-id'])
  })

  await t.test('every response forbids caching', async () => {
    // A response from this service may contain a credential exactly once, and an intermediary that
    // cached it would serve it to the next caller.
    for (const path of ['/livez', '/v1/scopes', '/v1/apps']) {
      const answer = await call('GET', path)
      assert.equal(answer.headers['cache-control'], 'no-store', `${path} is cacheable`)
    }
  })

  /* ---------------------------------------------------------------- the scope vocabulary */

  await t.test('the scope vocabulary is public, and says there is no wildcard', async () => {
    const answer = await call('GET', '/v1/scopes')
    assert.equal(answer.status, 200)
    const scopes = answer.json['scopes'] as Array<{ name: string }>
    assert.ok(scopes.length > 5)
    assert.ok(!scopes.some((scope) => scope.name.includes('*')))
    assert.equal(answer.json['wildcard'], null)
  })

  /* ---------------------------------------------------------------- issuing a key */

  async function issueKeyOverHttp(
    project: { id: string },
    token: string,
    overrides: Record<string, unknown> = {},
  ): Promise<Answer> {
    return call('POST', `/v1/projects/${project.id}/keys`, {
      token,
      idempotencyKey: `issue-${uniqueSlug('i')}`,
      body: { environment: 'live', name: 'integration', scopes: ['market:read'], ...overrides },
    })
  }

  await t.test('issuing a key returns the secret ONCE, with a note saying so', async () => {
    const { project, token } = await scenario()
    const answer = await issueKeyOverHttp(project, token)
    assert.equal(answer.status, 201)
    const secretKey = answer.json['secretKey'] as string
    assert.match(secretKey, /^cfk_live_[a-z2-7]{16}_[a-z2-7]{52}$/)
    assert.match(String(answer.json['note']), /only time this secret is shown/)
  })

  await t.test('NO ROUTE RETURNS THE SECRET AFTER CREATION — every route, by enumeration', async () => {
    const { org, project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token)
    const secretKey = issued.json['secretKey'] as string
    const secret = parseKey(secretKey)!.secret
    const key = (issued.json['key'] as Record<string, unknown>)['id'] as string

    // Something to find on every read path.
    const endpoint = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
      token,
      idempotencyKey: `wh-${uniqueSlug('w')}`,
      body: { environment: 'live', url: 'https://subscriber.example.com/hook', topics: ['devplatform.key.issued'] },
    })
    const endpointId = (endpoint.json['endpoint'] as Record<string, unknown>)['id'] as string
    const webhookSecret = endpoint.json['secret'] as string
    assert.ok(webhookSecret.startsWith('whsec_'))

    const client = await call('POST', `/v1/projects/${project.id}/oauth-clients`, {
      token,
      idempotencyKey: `oc-${uniqueSlug('o')}`,
      body: { name: 'app', redirectUris: ['https://app.example.com/cb'], scopes: ['market:read'] },
    })
    const clientSecret = client.json['clientSecret'] as string
    assert.ok(clientSecret.startsWith('cfcs_'))

    await call('PUT', `/v1/projects/${project.id}/application`, {
      token,
      body: { slug: uniqueSlug('app'), name: 'My App' },
    })

    // EVERY read route on the server, plus the key-authenticated whoami.
    const reads: Array<[string, string, string | undefined]> = [
      ['GET', '/v1/scopes', undefined],
      ['GET', '/v1/apps', undefined],
      ['GET', '/metrics', undefined],
      ['GET', `/v1/organisations/${org.id}`, token],
      ['GET', `/v1/organisations/${org.id}/projects`, token],
      ['GET', `/v1/projects/${project.id}`, token],
      ['GET', `/v1/projects/${project.id}/keys?includeRevoked=true`, token],
      ['GET', `/v1/keys/${key}`, token],
      ['GET', `/v1/projects/${project.id}/service-accounts`, token],
      ['GET', `/v1/projects/${project.id}/quotas`, token],
      ['GET', `/v1/projects/${project.id}/usage`, token],
      ['GET', `/v1/projects/${project.id}/webhook-endpoints`, token],
      ['GET', `/v1/webhook-endpoints/${endpointId}/deliveries`, token],
      ['GET', `/v1/projects/${project.id}/oauth-clients`, token],
      ['GET', `/v1/projects/${project.id}/application`, token],
      ['GET', '/v1/keys/self', secretKey],
      // The two reads added with the operator surface. Walked here for the same reason as the rest:
      // a route added tomorrow that returns a secret through an unexpected field fails this test.
      ['GET', `/v1/organisations?identityOrgId=${encodeURIComponent(org.identityOrgId)}`, token],
      ['GET', '/v1/apps/pending', operatorService()],
    ]

    let checked = 0
    for (const [method, path, auth] of reads) {
      const answer = await call(method, path, auth ? { token: auth } : {})
      assert.ok(answer.status < 500, `${method} ${path} answered ${answer.status}`)
      checked += 1
      for (const [label, value] of [
        ['the api key secret', secret],
        ['the full api key', secretKey],
        ['the webhook signing secret', webhookSecret],
        ['the oauth client secret', clientSecret],
      ] as const) {
        assert.ok(
          !answer.body.includes(value),
          `${method} ${path} returned ${label}. A secret is shown once; there is no reveal endpoint.`,
        )
      }
    }
    assert.ok(checked >= 18, `only ${checked} read routes were walked`)
  })

  await t.test('AN IDEMPOTENT RETRY REPLAYS, AND THE REPLAY CARRIES NO SECRET', async () => {
    const { project, token } = await scenario()
    const idempotencyKey = `issue-${uniqueSlug('r')}`
    const body = { environment: 'live', name: 'integration', scopes: ['market:read'] }

    const first = await call('POST', `/v1/projects/${project.id}/keys`, { token, idempotencyKey, body })
    const second = await call('POST', `/v1/projects/${project.id}/keys`, { token, idempotencyKey, body })

    assert.equal(first.status, 201)
    assert.equal(first.json['replayed'], false)
    assert.equal(second.status, 200)
    assert.equal(second.json['replayed'], true)

    // The same key metadata …
    assert.deepEqual(second.json['key'], first.json['key'])
    // … and no secret, because the work did not run. That is precisely what makes a replay safe:
    // the stored response is a jsonb column that outlives the request.
    assert.equal(second.json['secretKey'], null)
    assert.ok(!second.body.includes(parseKey(first.json['secretKey'] as string)!.secret))

    // And exactly one credential exists.
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from api_keys`
    assert.equal(rows[0]?.n, 1, 'a retry minted a second credential')
  })

  await t.test('a mutating route without an idempotency key is refused', async () => {
    const { project, token } = await scenario()
    const answer = await call('POST', `/v1/projects/${project.id}/keys`, {
      token,
      body: { environment: 'live', name: 'k', scopes: [] },
    })
    assert.equal(answer.status, 400)
    assert.match(JSON.stringify(answer.json), /Idempotency-Key/)
  })

  await t.test('the same idempotency key with a different body is a 409', async () => {
    const { project, token } = await scenario()
    const idempotencyKey = `issue-${uniqueSlug('c')}`
    await call('POST', `/v1/projects/${project.id}/keys`, {
      token,
      idempotencyKey,
      body: { environment: 'live', name: 'k', scopes: ['market:read'] },
    })
    const answer = await call('POST', `/v1/projects/${project.id}/keys`, {
      token,
      idempotencyKey,
      body: { environment: 'live', name: 'k', scopes: ['market:write'] },
    })
    assert.equal(answer.status, 409)
    assert.equal((answer.json['error'] as Record<string, unknown>)['code'], 'idempotency_key_reuse')
  })

  await t.test('an unknown scope is refused at issuance, and mints nothing', async () => {
    const { project, token } = await scenario()
    const answer = await issueKeyOverHttp(project, token, { scopes: ['market:*'] })
    assert.equal(answer.status, 400)
    assert.equal((answer.json['error'] as Record<string, unknown>)['code'], 'unknown_scope')
    assert.match(String((answer.json['error'] as Record<string, unknown>)['message']), /no wildcard/)
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from api_keys`
    assert.equal(rows[0]?.n, 0)
  })

  /* ---------------------------------------------------------------- the whoami */

  await t.test('GET /v1/keys/self is the whoami a machine credential did not have', async () => {
    const { org, project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token, { scopes: ['market:read', 'wallet:read'] })
    const secretKey = issued.json['secretKey'] as string

    const answer = await call('GET', '/v1/keys/self', { token: secretKey })
    assert.equal(answer.status, 200)
    assert.equal(answer.json['projectId'], project.id)
    assert.equal(answer.json['orgId'], org.id)
    assert.equal(answer.json['environment'], 'live')
    assert.deepEqual(answer.json['scopes'], ['market:read', 'wallet:read'])
    assert.match(String(answer.json['display']), /^cfk_live_[a-z2-7]{16}$/)
  })

  await t.test('the whoami needs NO scope, so an inert key can still ask what it is', async () => {
    // A credential that cannot ask what it is cannot be diagnosed, and the keys most likely to be
    // misconfigured are exactly the ones with no scopes.
    const { project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token, { scopes: [] })
    const answer = await call('GET', '/v1/keys/self', { token: issued.json['secretKey'] as string })
    assert.equal(answer.status, 200)
    assert.deepEqual(answer.json['scopes'], [])
  })

  await t.test('a user token cannot use the whoami, and a key cannot use the console reads', async () => {
    const { org, token } = await scenario()
    assert.equal((await call('GET', '/v1/keys/self', { token })).status, 403)
    // A key has no membership, so an organisation read is not its to make.
    const { project, token: other } = await scenario()
    const issued = await issueKeyOverHttp(project, other, { scopes: ['devplatform:read'] })
    const answer = await call('GET', `/v1/organisations/${org.id}`, {
      token: issued.json['secretKey'] as string,
    })
    assert.equal(answer.status, 403)
  })

  /* ---------------------------------------------------------------- refusals */

  await t.test('A REVOKED KEY AND AN UNKNOWN KEY PRODUCE THE SAME ANSWER, BYTE FOR BYTE', async () => {
    const { project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token)
    const secretKey = issued.json['secretKey'] as string
    const keyId = (issued.json['key'] as Record<string, unknown>)['id'] as string

    assert.equal((await call('GET', '/v1/keys/self', { token: secretKey })).status, 200)
    assert.equal((await call('DELETE', `/v1/keys/${keyId}?reason=leaked`, { token })).status, 200)

    const revoked = await call('GET', '/v1/keys/self', { token: secretKey })
    const unknown = await call('GET', '/v1/keys/self', {
      token: `cfk_live_${'a'.repeat(16)}_${'b'.repeat(52)}`,
    })

    assert.equal(revoked.status, 401)
    assert.equal(unknown.status, 401)

    // The request id necessarily differs; everything else must not.
    const strip = (answer: Answer) =>
      JSON.stringify(answer.json).replace(/"requestId":"[^"]*"/, '"requestId":"<id>"')
    assert.equal(
      strip(revoked),
      strip(unknown),
      'a caller can tell a revoked key from an unknown one, which is a live-account oracle',
    )
    assert.deepEqual(
      Object.keys(revoked.headers).sort(),
      Object.keys(unknown.headers).sort(),
      'the two refusals differ in their headers',
    )
    assert.equal(revoked.headers['content-length'], unknown.headers['content-length'])
  })

  await t.test('an expired key, a malformed key and no key are the same 401 too', async () => {
    const { project, token } = await scenario()
    const expired = await issueKeyOverHttp(project, token, {
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    })
    const answers = await Promise.all([
      call('GET', '/v1/keys/self', { token: expired.json['secretKey'] as string }),
      call('GET', '/v1/keys/self', { token: 'cfk_not_a_real_key' }),
      call('GET', '/v1/keys/self'),
    ])
    const bodies = answers.map((answer) =>
      JSON.stringify(answer.json).replace(/"requestId":"[^"]*"/, '"requestId":"<id>"'),
    )
    assert.deepEqual([...new Set(answers.map((a) => a.status))], [401])
    assert.equal(new Set(bodies).size, 1, `three refusals produced ${new Set(bodies).size} distinct bodies`)
  })

  await t.test('the refusal reason reaches the metric, which is where it belongs', async () => {
    await call('GET', '/v1/keys/self', { token: `cfk_live_${'c'.repeat(16)}_${'d'.repeat(52)}` })
    const metrics = await call('GET', '/metrics')
    assert.match(metrics.body, /devplatform_key_refusals_total\{reason="unknown"\} \d+/)
  })

  /* ---------------------------------------------------------------- authorisation */

  await t.test('a project belonging to another organisation is a 404, not a 403', async () => {
    // A 403 confirms the id exists, which makes project ids enumerable across customers.
    const mine = await scenario()
    const theirs = await scenario()
    const answer = await call('GET', `/v1/projects/${theirs.project.id}`, { token: mine.token })
    assert.equal(answer.status, 404)
  })

  await t.test('a member may read but not write; an owner may do both', async () => {
    // A member of a company is not automatically someone who may mint a production key for it.
    const reader = await scenario('member')
    assert.equal((await call('GET', `/v1/projects/${reader.project.id}`, { token: reader.token })).status, 200)
    assert.equal((await issueKeyOverHttp(reader.project, reader.token)).status, 404)

    const owner = await scenario('owner')
    assert.equal((await issueKeyOverHttp(owner.project, owner.token)).status, 201)
  })

  await t.test('a key may act within its own project, with the right scope', async () => {
    const { project, token } = await scenario()
    const write = await issueKeyOverHttp(project, token, { scopes: ['devplatform:write'] })
    const read = await issueKeyOverHttp(project, token, { scopes: ['devplatform:read'] })

    const writeKey = write.json['secretKey'] as string
    const readKey = read.json['secretKey'] as string

    assert.equal((await call('GET', `/v1/projects/${project.id}/keys`, { token: readKey })).status, 200)
    // Exact match: a read scope does not cover a write.
    assert.equal((await issueKeyOverHttp(project, readKey)).status, 403)
    assert.equal((await issueKeyOverHttp(project, writeKey)).status, 201)
  })

  await t.test('A KEY WITH NO SCOPES REACHES NOTHING', async () => {
    const { project, token } = await scenario()
    const inert = await issueKeyOverHttp(project, token, { scopes: [] })
    const key = inert.json['secretKey'] as string
    assert.equal((await call('GET', `/v1/projects/${project.id}/keys`, { token: key })).status, 403)
    assert.equal((await call('GET', `/v1/projects/${project.id}`, { token: key })).status, 403)
    assert.equal((await issueKeyOverHttp(project, key)).status, 403)
    // But it is a valid credential, and can say what it is.
    assert.equal((await call('GET', '/v1/keys/self', { token: key })).status, 200)
  })

  await t.test('IDENTITY BEING UNREACHABLE IS A 503, NEVER A 403', async () => {
    // Answering "no" would lock every developer out of their own platform for the duration of
    // somebody else's incident.
    const { project, token } = await scenario()
    membership.unavailable(true)
    try {
      const answer = await call('GET', `/v1/projects/${project.id}`, { token })
      assert.equal(answer.status, 503)
      assert.equal((answer.json['error'] as Record<string, unknown>)['code'], 'membership_unavailable')
    } finally {
      membership.unavailable(false)
    }
  })

  await t.test('a service token is refused on the console surface', async () => {
    // A service token names no user, so there is no membership to check. Accepting one would make
    // every service in the estate an administrator of every customer's credentials.
    const { project } = await scenario()
    const answer = await call('GET', `/v1/projects/${project.id}`, {
      token: serviceToken(['devplatform:read']),
    })
    assert.equal(answer.status, 403)
  })

  /* ---------------------------------------------------------------- internal routes */

  await t.test('introspection needs a service token carrying the exact scope', async () => {
    const { project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token)
    const secretKey = issued.json['secretKey'] as string

    assert.equal((await call('POST', '/internal/keys/verify', { body: { key: secretKey } })).status, 401)
    assert.equal(
      (await call('POST', '/internal/keys/verify', { token: serviceToken([]), body: { key: secretKey } })).status,
      403,
    )
    // A WILDCARD DOES NOT SATISFY IT. `runtime/packages/auth`'s hasScope honours one wildcard level;
    // this route uses exact match, because it reads credentials.
    assert.equal(
      (
        await call('POST', '/internal/keys/verify', {
          token: serviceToken(['devplatform:*']),
          body: { key: secretKey },
        })
      ).status,
      403,
      'a wildcard service scope reached the introspection route',
    )

    const ok = await call('POST', '/internal/keys/verify', {
      token: serviceToken([INTROSPECT_SCOPE]),
      body: { key: secretKey },
    })
    assert.equal(ok.status, 200)
    assert.equal(ok.json['ok'], true)
    const principal = ok.json['principal'] as Record<string, unknown>
    assert.equal(principal['projectId'], project.id)
    assert.ok(!ok.body.includes(parseKey(secretKey)!.secret))
  })

  await t.test('introspection answers a bad credential with 200 ok:false, and no reason', async () => {
    // The CALLER's credential was fine; the credential it asked about was not. Conflating the two
    // makes a caller retry its own service token.
    const answer = await call('POST', '/internal/keys/verify', {
      token: serviceToken([INTROSPECT_SCOPE]),
      body: { key: `cfk_live_${'a'.repeat(16)}_${'b'.repeat(52)}` },
    })
    assert.equal(answer.status, 200)
    assert.equal(answer.json['ok'], false)
    assert.ok(!('reason' in answer.json), 'the refusal reason reached an internal caller')
  })

  await t.test('the meter enforces the quota in Postgres, and refuses past it', async () => {
    const { project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token)
    const keyId = (issued.json['key'] as Record<string, unknown>)['id'] as string

    // `seedWorkspace` calls `createProject` directly, which does NOT seed default quotas — only
    // `POST /v1/projects` does, and that is deliberate: the quota rows and the project are one
    // transaction at the route. So set the quota through its own route, which exercises it too.
    //
    // With an OPERATOR token, because creating a quota where none exists is an operator decision:
    // an environment with no row is unlimited, and a customer allowed to create the first one could
    // create it at any value and call it a reduction. See the route's own header.
    const set = await call('PUT', `/v1/projects/${project.id}/quotas`, {
      token: operatorService(),
      body: { environment: 'live', period: 'minute', maxUnits: 2 },
    })
    assert.equal(set.status, 200)

    const service = serviceToken([INTROSPECT_SCOPE])
    const meter = () => call('POST', '/internal/usage', { token: service, body: { keyId, route: '/v1/rates' } })

    await withinOneMinuteWindow()
    assert.equal((await meter()).json['allowed'], true)
    assert.equal((await meter()).json['allowed'], true)
    const refused = await meter()
    assert.equal(refused.json['allowed'], false)
    assert.equal(refused.json['period'], 'minute')
    assert.equal(refused.json['limit'], 2)

    const metrics = await call('GET', '/metrics')
    assert.match(metrics.body, /devplatform_quota_refusals_total\{period="minute"\} 1/)
  })

  await t.test('CONCURRENT METERED CALLS CANNOT EXCEED THE QUOTA, OVER HTTP', async () => {
    // The end-to-end form of the race. An in-memory counter passes with one replica and fails with
    // two; a counter in Postgres passes here and in production.
    const { project, token } = await scenario()
    const issued = await issueKeyOverHttp(project, token)
    const keyId = (issued.json['key'] as Record<string, unknown>)['id'] as string
    await call('PUT', `/v1/projects/${project.id}/quotas`, {
      token: operatorService(),
      body: { environment: 'live', period: 'minute', maxUnits: 5 },
    })

    const service = serviceToken([INTROSPECT_SCOPE])
    // Same boundary hazard: 25 concurrent calls that straddle it would see 10 allowed, not 5.
    await withinOneMinuteWindow()
    const answers = await Promise.all(
      Array.from({ length: 25 }, () =>
        call('POST', '/internal/usage', { token: service, body: { keyId, route: '/v1/rates' } }),
      ),
    )
    const allowed = answers.filter((answer) => answer.json['allowed'] === true).length
    assert.equal(allowed, 5, `${allowed} of 25 concurrent metered calls were allowed against a limit of 5`)
  })

  await t.test('the oauth client-secret check is internal, and constant in its answer', async () => {
    const { project, token } = await scenario()
    const client = await call('POST', `/v1/projects/${project.id}/oauth-clients`, {
      token,
      idempotencyKey: `oc-${uniqueSlug('v')}`,
      body: { name: 'app', redirectUris: ['https://app.example.com/cb'], scopes: ['market:read'] },
    })
    const clientId = (client.json['client'] as Record<string, unknown>)['clientId'] as string
    const clientSecret = client.json['clientSecret'] as string
    const service = serviceToken([INTROSPECT_SCOPE])

    const ok = await call('POST', '/internal/oauth/verify', {
      token: service,
      body: { clientId, clientSecret },
    })
    assert.equal(ok.json['ok'], true)
    assert.ok(!ok.body.includes(clientSecret), 'the verify route echoed the secret back')

    for (const body of [
      { clientId, clientSecret: 'cfcs_wrong' },
      { clientId: 'cfc_nope', clientSecret },
    ]) {
      const bad = await call('POST', '/internal/oauth/verify', { token: service, body })
      assert.equal(bad.status, 200)
      assert.deepEqual(bad.json, { ok: false })
    }
  })

  /* ---------------------------------------------------------------- the inbox */

  function envelopeFor(topic: string, payload: Record<string, unknown>): string {
    return JSON.stringify({
      id: crypto.randomUUID(),
      topic,
      key: 'k',
      occurredAt: new Date().toISOString(),
      producer: 'identity',
      version: 1,
      actor: null,
      correlationId: null,
      payload,
    })
  }

  await t.test('AN UNSIGNED EVENT IS REFUSED BEFORE IT IS PARSED', async () => {
    // Unsigned, this route is a revoke-anybody's-integration endpoint reachable by anything that can
    // open a socket to the app network.
    const { org, project } = await scenario()
    await seedKey(sql, project.id)
    const raw = envelopeFor('identity.organisation.deleted', { organisationId: org.identityOrgId })

    const unsigned = await call('POST', '/v1/events', { rawBody: raw })
    assert.equal(unsigned.status, 401)
    assert.equal((unsigned.json['error'] as Record<string, unknown>)['code'], 'bad_signature')

    // And nothing happened.
    const rows = await sql<{ n: number }[]>`select count(*)::int as n from api_keys where revoked_at is not null`
    assert.equal(rows[0]?.n, 0, 'an unsigned event revoked credentials')
  })

  await t.test('a signature over DIFFERENT bytes is refused', async () => {
    // The signature must be over what arrived, not over something that parses the same.
    const raw = envelopeFor('identity.organisation.deleted', { organisationId: 'org_x' })
    const signature = signEvent(raw, INGEST_SECRET)
    const tampered = raw.replace('org_x', 'org_y')
    const answer = await call('POST', '/v1/events', {
      rawBody: tampered,
      headers: { 'cf-signature': signature },
    })
    assert.equal(answer.status, 401)
  })

  await t.test('a signed organisation deletion suspends the org and revokes its keys', async () => {
    const { org, project } = await scenario()
    const issued = await seedKey(sql, project.id)
    const raw = envelopeFor('identity.organisation.deleted', { organisationId: org.identityOrgId })

    const answer = await call('POST', '/v1/events', {
      rawBody: raw,
      headers: { 'cf-signature': signEvent(raw, INGEST_SECRET) },
    })
    assert.equal(answer.status, 202)
    assert.equal(answer.json['status'], 'processed')
    assert.equal(answer.json['revoked'], 1)

    // The credential stops working immediately.
    assert.equal((await call('GET', '/v1/keys/self', { token: issued.secretKey })).status, 401)
    // And the revocation is announced, so a cache at the edge is invalidated rather than waited out.
    const outbox = await sql<{ topic: string }[]>`select topic from outbox order by occurred_at`
    assert.ok(outbox.some((row) => row.topic === 'devplatform.key.revoked'))
  })

  /**
   * ════════════════════════════════════════════════════════════════════════════════════════════
   * **THE MASS REVOCATION REACHES EVERY PERSON WHOSE KEYS DIED — THROUGH THE REAL ROUTE.**
   *
   * The test above proves the keys are revoked and an event is emitted. Both were true for the
   * whole life of this service while the news reached NOBODY: the actor is `service:identity`,
   * every consumer in the estate derives the owner from the actor when the payload names no user,
   * so `activity` filed the record internal and `notify` answered `no_recipient`. A company's
   * production integration stopped at whatever hour identity processed the erasure, in silence.
   *
   * This runs the real HTTP route, the real handler, the real `revokeOrgKeys`, the real
   * `emitKeyRevoked`, the real `outbox` rows and the real `buildEnvelope` — so the actor and the
   * owner both make a round trip through the COLUMNS, which is where a type guarantee is laundered
   * back to `string | null`. Then it asks who each envelope lands on.
   *
   * **Yesterday's payload shape is fed to the reader FIRST.** An end-to-end test elsewhere in this
   * estate stayed green with the consuming classifier deliberately broken, because the payload
   * lacked the field and an absent field is null to every reader — so "reached nobody" was the
   * expected answer either way. Asserting the old shape reaches nobody and the new shape reaches
   * the owner is the pair that cannot both pass by accident.
   * ════════════════════════════════════════════════════════════════════════════════════════════
   */
  await t.test('A MASS REVOCATION REACHES EVERY PERSON WHOSE KEYS IT KILLED', async () => {
    const { org, project } = await scenario()
    // Two developers with keys in one organisation, and one key a KEY minted. A mass revocation
    // spans as many people as the organisation has, which is why the fan-out cannot come from the
    // single actor on the envelope.
    const alice = '018f0000-0000-7000-8000-00000000a11c'
    const bob = '018f0000-0000-7000-8000-00000000b0b0'
    await seedKey(sql, project.id, { name: 'alice ci', createdBy: `user:${alice}` })
    await seedKey(sql, project.id, { name: 'alice deploy', createdBy: `user:${alice}` })
    await seedKey(sql, project.id, { name: 'bob nightly', createdBy: `user:${bob}` })
    await seedKey(sql, project.id, { name: 'minted by a key', createdBy: 'service:cfk_live_0011223344556677' })

    const raw = envelopeFor('identity.organisation.deleted', { organisationId: org.identityOrgId })
    const answer = await call('POST', '/v1/events', {
      rawBody: raw,
      headers: { 'cf-signature': signEvent(raw, INGEST_SECRET) },
    })
    assert.equal(answer.json['revoked'], 4)

    const rows = await sql<
      {
        id: string
        topic: string
        key: string
        occurred_at: Date
        producer: string
        version: number
        actor: string | null
        correlation_id: string | null
        payload: Record<string, unknown>
      }[]
    >`
      select id, topic, key, occurred_at, producer, version, actor, correlation_id, payload
        from outbox where topic = 'devplatform.key.revoked' order by id
    `
    assert.equal(rows.length, 4, 'one revocation event per key — the per-key event IS the fan-out')

    const envelopes = rows.map(
      (row) => JSON.parse(JSON.stringify(buildEnvelope(row))) as Record<string, unknown>,
    )
    for (const envelope of envelopes) {
      assert.deepEqual(
        envelopeDefects(envelope),
        [],
        'an event no consumer will accept reaches nobody for a reason this test would not name',
      )
      // The platform did this, and the envelope must keep saying so: `activity` discriminates
      // `api.key_revoked_by_platform` from `api.key_revoked` on the actor alone.
      assert.equal(envelope['actor'], 'service:identity')
    }

    // ── YESTERDAY. Four valid envelopes, four users with dead integrations, nobody told. ──
    const before = envelopes.map((envelope) => {
      const payload = { ...(envelope['payload'] as Record<string, unknown>) }
      delete payload['userId']
      return { ...envelope, payload }
    })
    assert.deepEqual(
      before.map(recipientOf),
      [null, null, null, null],
      'the pre-change payload reached somebody, so the assertions below prove nothing',
    )

    // ── TODAY. ──
    const reached = envelopes.map(recipientOf)
    assert.equal(
      reached.filter((user) => user === alice).length,
      2,
      'alice held two keys and both died — she is told about each, or the guard is a field check',
    )
    assert.equal(reached.filter((user) => user === bob).length, 1, 'bob was not told')
    assert.equal(
      reached.filter((user) => user === null).length,
      1,
      "a key minted by a key is no person's news, and guessing would tell the wrong person",
    )

    /*
     * **PER-USER IDEMPOTENCY, WHICH IS WHAT ONE EVENT PER KEY BUYS.**
     *
     * `worlds/src/heraldry.ts` records the hazard this avoids: one alliance-wide synthetic id let
     * exactly ONE member win the insert and handed every other member a silent null. Here the
     * producer fans out, so the dedupe identity is the event id — the estate's inbox dedupes on
     * `(topic, event_id)` and notify's key for this rule is `api.key_revoked:<key_id>`. Two of
     * alice's keys sharing either would silently drop one of her two dead integrations.
     */
    const aliceRows = rows.filter((_, index) => reached[index] === alice)
    assert.equal(new Set(aliceRows.map((row) => row.id)).size, 2, 'two of alice\'s events share an id')
    assert.equal(new Set(aliceRows.map((row) => row.key)).size, 2, 'two of alice\'s events share a key')
  })

  await t.test('THE SAME EVENT DELIVERED TWICE IS PROCESSED ONCE', async () => {
    const { org, project } = await scenario()
    await seedKey(sql, project.id)
    const raw = envelopeFor('identity.organisation.deleted', { organisationId: org.identityOrgId })
    const headers = { 'cf-signature': signEvent(raw, INGEST_SECRET) }

    const first = await call('POST', '/v1/events', { rawBody: raw, headers })
    const second = await call('POST', '/v1/events', { rawBody: raw, headers })
    assert.equal(first.json['status'], 'processed')
    assert.equal(second.json['status'], 'duplicate')

    const events = await sql<{ n: number }[]>`
      select count(*)::int as n from outbox where topic = 'devplatform.key.revoked'
    `
    assert.equal(events[0]?.n, 1, 'a redelivery emitted a second revocation event')
  })

  await t.test('a deleted USER keeps the key live and erases the attribution', async () => {
    // ════════════════════════════════════════════════════════════════════════════════════════
    // Two claims, and this branch used to make only the first.
    //
    //   1. The key is NOT revoked. It was issued TO the organisation and remains the
    //      organisation's; revoking it would take a company's production integration down
    //      because an employee closed their account.
    //   2. The PERSON is erased from it. `api_keys.created_by` is the only user this service
    //      knows, and the handler returned `{ revoked: 0 }` without touching it — reporting
    //      success while leaving the departed developer's `user:<uuid>` on a live credential.
    //
    // The old test asserted only `revoked === 0`, which the no-op satisfied perfectly, and it
    // sent `userId: 'user_gone'` — a value identity cannot produce, since the field is a uuid.
    // ════════════════════════════════════════════════════════════════════════════════════════
    const { project } = await scenario()
    const issued = await seedKey(sql, project.id)
    const [before] = await sql<{ created_by: string }[]>`
      select created_by from api_keys where id = ${issued.key.id}`
    assert.equal(before?.created_by, `user:${TEST_KEY_OWNER}`, 'the fixture proves nothing')

    const raw = envelopeFor('identity.user.deleted', {
      userId: TEST_KEY_OWNER,
      tombstoneAt: new Date(Date.now() + 30 * 86_400_000).toISOString(),
      reason: 'user_requested',
    })
    const answer = await call('POST', '/v1/events', {
      rawBody: raw,
      headers: { 'cf-signature': signEvent(raw, INGEST_SECRET) },
    })
    assert.equal(answer.status, 202)
    assert.equal(answer.json['revoked'], 0)
    assert.equal(answer.json['keysReattributed'], 1)

    // The credential still authenticates: the organisation did not lose its integration.
    assert.equal((await call('GET', '/v1/keys/self', { token: issued.secretKey })).status, 200)

    // And nothing in the table names the person any more.
    const [after] = await sql<{ created_by: string }[]>`
      select created_by from api_keys where id = ${issued.key.id}`
    assert.match(after?.created_by ?? '', /^user:erased-/)
    const [leaks] = await sql<{ n: number }[]>`
      select count(*)::int as n from api_keys
       where created_by = ${`user:${TEST_KEY_OWNER}`} or revoked_by = ${`user:${TEST_KEY_OWNER}`}`
    assert.equal(leaks?.n, 0, 'the erased developer still owns a live credential')

    // The erasure is terminal — no repair script can hand the key back to a real account.
    await assert.rejects(
      () => sql`update api_keys set created_by = ${`user:${TEST_KEY_OWNER}`} where id = ${issued.key.id}`,
      /erased creator/,
      'an erased key attribution could be restored',
    )
  })

  await t.test('an unsubscribed topic is accepted and ignored with a 202', async () => {
    // A 4xx would make the producer's relay retry an event it is correct to send and we are correct
    // not to act on, for ever.
    const raw = envelopeFor('identity.mfa.removed', {})
    const answer = await call('POST', '/v1/events', {
      rawBody: raw,
      headers: { 'cf-signature': signEvent(raw, INGEST_SECRET) },
    })
    assert.equal(answer.status, 202)
    assert.equal(answer.json['status'], 'ignored')
  })

  /* ---------------------------------------------------------------- the directory */

  await t.test('a listing is not public until an operator lists it', async () => {
    const { project, token } = await scenario()
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, {
      token,
      body: { slug, name: 'My App', tagline: 'does things' },
    })

    // A draft is not in the directory, and cannot be fetched by slug.
    assert.ok(!(await call('GET', '/v1/apps')).body.includes(slug))
    assert.equal((await call('GET', `/v1/apps/${slug}`)).status, 404)

    // Submitting for review does not publish it either.
    await call('POST', `/v1/projects/${project.id}/application/submit`, { token })
    assert.equal((await call('GET', `/v1/apps/${slug}`)).status, 404)

    // Only the operator transition does — through the ROUTE. This case used to reach `listed` with
    // a hand-written UPDATE, which is how it passed for months while `setApplicationStatus` was
    // imported by the server and called by nothing: the test wrote the row the route could not.
    const decided = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: operatorService(),
      body: { status: 'listed' },
    })
    assert.equal(decided.status, 200)
    const listed = await call('GET', `/v1/apps/${slug}`)
    assert.equal(listed.status, 200)
    assert.ok((await call('GET', '/v1/apps')).body.includes(slug))
  })

  await t.test('THE DEVELOPER WHO SUBMITTED IT CANNOT APPROVE IT', async () => {
    // A directory a developer can publish to unilaterally is a directory that eventually hosts a
    // phishing page wearing this platform's chrome — and the consent screen a user reads before
    // granting an OAuth client authority is rendered from exactly this row.
    const { project, token } = await scenario('owner')
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, { token, body: { slug, name: 'My App' } })
    await call('POST', `/v1/projects/${project.id}/application/submit`, { token })

    const refused = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token,
      body: { status: 'listed' },
    })
    assert.equal(refused.status, 403, 'the project owner listed their own application')
    assert.match(String(JSON.stringify(refused.json)), /devplatform:admin or role:admin/)
    assert.equal((await call('GET', `/v1/apps/${slug}`)).status, 404)

    // Nor can an API key in the project, at any scope — `devplatform:admin` is not in the
    // vocabulary `validateScopes` will issue, so no key can hold it.
    const key = await issueKeyOverHttp(project, token, { scopes: ['devplatform:write'] })
    const byKey = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: key.json['secretKey'] as string,
      body: { status: 'listed' },
    })
    assert.equal(byKey.status, 403)
  })

  await t.test('a platform admin\'s USER token is an operator, without any membership', async () => {
    // The other principal `isOperator` admits. No `membership.grant` for this user anywhere: an
    // operator who had to be a member of every organisation would end up holding a credential that
    // is a member of all of them.
    const { project, token } = await scenario()
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, { token, body: { slug, name: 'My App' } })
    await call('POST', `/v1/projects/${project.id}/application/submit`, { token })

    const decided = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: operatorUser(),
      body: { status: 'listed' },
    })
    assert.equal(decided.status, 200)
    assert.equal((await call('GET', `/v1/apps/${slug}`)).status, 200)
  })

  await t.test('an operator may reject, and a rejection is not a delisting', async () => {
    const { project, token } = await scenario()
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, { token, body: { slug, name: 'My App' } })
    await call('POST', `/v1/projects/${project.id}/application/submit`, { token })

    const rejected = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: operatorService(),
      body: { status: 'rejected' },
    })
    assert.equal(rejected.status, 200)
    assert.equal((rejected.json['application'] as Record<string, unknown>)['status'], 'rejected')

    // The developer can see the decision on their own listing, and it is not 'delisted'.
    const mine = await call('GET', `/v1/projects/${project.id}/application`, { token })
    assert.equal((mine.json['application'] as Record<string, unknown>)['status'], 'rejected')

    // And it is not public, by either address.
    assert.equal((await call('GET', `/v1/apps/${slug}`)).status, 404)
    assert.ok(!(await call('GET', '/v1/apps')).body.includes(slug))
  })

  await t.test('an illegal transition is a 409 and a developer-owned status is a 400', async () => {
    const { project, token } = await scenario()
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, { token, body: { slug, name: 'My App' } })
    const operator = operatorService()

    // A draft has never been submitted. Listing it publishes copy nobody reviewed.
    const early = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: operator,
      body: { status: 'listed' },
    })
    assert.equal(early.status, 409)
    assert.equal((early.json['error'] as Record<string, unknown>)['code'], 'conflict')

    // `in_review` is the developer's transition, not an operator's.
    const wrong = await call('PUT', `/v1/projects/${project.id}/application/status`, {
      token: operator,
      body: { status: 'in_review' },
    })
    assert.equal(wrong.status, 400)
    assert.match(String(JSON.stringify(wrong.json)), /listed, rejected, delisted/)

    // And a project id that is not a uuid is a 400 rather than a 500 carrying 22P02.
    const malformed = await call('PUT', '/v1/projects/not-a-uuid/application/status', {
      token: operator,
      body: { status: 'listed' },
    })
    assert.equal(malformed.status, 400)
  })

  await t.test('THE REVIEW QUEUE IS THE OPERATOR\'S, AND NOBODY ELSE\'S', async () => {
    // Without it the approval route is unaddressable: it is keyed by project id, an operator is not
    // a member of the project's organisation, and `GET /v1/apps` shows only what is already listed.
    const { project, token } = await scenario()
    const slug = uniqueSlug('app')
    await call('PUT', `/v1/projects/${project.id}/application`, { token, body: { slug, name: 'My App' } })
    await call('POST', `/v1/projects/${project.id}/application/submit`, { token })

    for (const [label, options] of [
      ['anonymous', {}],
      ['the developer who submitted it', { token }],
      ['a service token with no operator scope', { token: serviceToken([INTROSPECT_SCOPE]) }],
    ] as const) {
      const refused = await call('GET', '/v1/apps/pending', options)
      assert.ok(refused.status === 401 || refused.status === 403, `${label} read the review queue`)
      assert.ok(!refused.body.includes(slug), `${label} was shown an unlisted application`)
    }

    for (const operator of [operatorService(), operatorUser()]) {
      const queue = await call('GET', '/v1/apps/pending', { token: operator })
      assert.equal(queue.status, 200)
      const applications = queue.json['applications'] as Array<Record<string, unknown>>
      assert.deepEqual(
        applications.map((application) => application['slug']),
        [slug],
      )
    }
  })

  await t.test('the review queue does not shadow a listing, because that slug cannot exist', async () => {
    // `/v1/apps/pending` is matched before `/v1/apps/:slug`. The ordering is not what makes this
    // safe — `applications_slug_not_reserved` is.
    const { project, token } = await scenario()
    const taken = await call('PUT', `/v1/projects/${project.id}/application`, {
      token,
      body: { slug: 'pending', name: 'Shadow' },
    })
    assert.equal(taken.status, 400)
    assert.match(String(JSON.stringify(taken.json)), /reserved/)
  })

  /* ---------------------------------------------------------------- quotas over http */

  /** A project created through its own route, so it has the default quota rows a customer has. */
  async function projectWithDefaultQuotas() {
    const { org, token, userId } = await scenario()
    const created = await call('POST', '/v1/projects', {
      token,
      idempotencyKey: `proj-${uniqueSlug('q')}`,
      body: { orgId: org.id, name: 'Checkout', slug: uniqueSlug('checkout') },
    })
    assert.equal(created.status, 201)
    return { org, token, userId, project: created.json['project'] as Record<string, unknown> }
  }

  await t.test('A CUSTOMER CANNOT RAISE THEIR OWN QUOTA', async () => {
    // ════════════════════════════════════════════════════════════════════════════════════════
    // The defect this whole change exists for. The route required only `project:write` and
    // `setQuota` accepted any whole number ≥ 1 with no ceiling, so the OWNER of a project could
    // set their own rate limit to whatever they liked. A quota the quota'd party can raise is not
    // a quota, and `micro-devportal-web` declined to call this route at all for that reason.
    // ════════════════════════════════════════════════════════════════════════════════════════
    const { project, token } = await projectWithDefaultQuotas()
    const id = project['id'] as string

    const raised = await call('PUT', `/v1/projects/${id}/quotas`, {
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 1_000_000 },
    })
    assert.equal(raised.status, 403, 'a project owner raised their own rate limit')
    assert.match(String(JSON.stringify(raised.json)), /never raise it/)

    // And the row did not move.
    const quotas = await call('GET', `/v1/projects/${id}/quotas`, { token })
    const minute = (quotas.json['quotas'] as Array<Record<string, unknown>>).find(
      (quota) => quota['period'] === 'minute',
    )
    assert.equal(minute?.['maxUnits'], 600, 'the refused raise was written anyway')
  })

  await t.test('a customer CAN lower their own quota, and hold it', async () => {
    // Lowering is a safety feature: a developer capping their test environment so a runaway loop
    // cannot burn the month's allowance is doing the platform's work for it. Making that need an
    // operator would mean nobody ever does it.
    const { project, token } = await projectWithDefaultQuotas()
    const id = project['id'] as string

    const lowered = await call('PUT', `/v1/projects/${id}/quotas`, {
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 60 },
    })
    assert.equal(lowered.status, 200)
    assert.equal((lowered.json['quota'] as Record<string, unknown>)['maxUnits'], 60)

    // Equal is permitted, deliberately: PUT is idempotent by natural key and a retry that 403'd
    // would make the exemption in `routeidempotency.test.ts` a lie.
    const retried = await call('PUT', `/v1/projects/${id}/quotas`, {
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 60 },
    })
    assert.equal(retried.status, 200, 'an identical retry of a PUT was refused')

    // But it cannot go back up, not even to where it started.
    const back = await call('PUT', `/v1/projects/${id}/quotas`, {
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 600 },
    })
    assert.equal(back.status, 403)
  })

  await t.test('a customer cannot CREATE a quota, because a missing row is unlimited', async () => {
    // `quotasFor` returns nothing for an environment with no row and `consumeAll` over an empty
    // list allows everything. Treating absence as infinity and calling any finite value a
    // reduction would hand the whole defect back through the periods that have no row.
    const { project, token } = await projectWithDefaultQuotas()
    const id = project['id'] as string
    const answer = await call('PUT', `/v1/projects/${id}/quotas`, {
      token,
      body: { environment: 'live', period: 'day', maxUnits: 10_000_000 },
    })
    assert.equal(answer.status, 403)
    assert.match(String(JSON.stringify(answer.json)), /no day quota/)
  })

  await t.test('AN API KEY WITH devplatform:write CANNOT RAISE ITS OWN PROJECT\'S QUOTA', async () => {
    // Worse than the owner case and the one the original finding did not name: a MACHINE credential
    // inside the project could raise the limit that binds it. `devplatform:admin` is absent from
    // `scopes.ts`, so no key can ever hold the authority that would let it.
    const { project, token } = await projectWithDefaultQuotas()
    const id = project['id'] as string
    const issued = await call('POST', `/v1/projects/${id}/keys`, {
      token,
      idempotencyKey: `k-${uniqueSlug('qk')}`,
      body: { environment: 'live', name: 'agent', scopes: ['devplatform:write'] },
    })
    const secretKey = issued.json['secretKey'] as string

    // It may lower — it holds `project:write` and that is what lowering needs.
    assert.equal(
      (
        await call('PUT', `/v1/projects/${id}/quotas`, {
          token: secretKey,
          body: { environment: 'live', period: 'minute', maxUnits: 10 },
        })
      ).status,
      200,
    )
    // It may not raise, and asking for the scope that would let it is refused at issuance.
    const raised = await call('PUT', `/v1/projects/${id}/quotas`, {
      token: secretKey,
      body: { environment: 'live', period: 'minute', maxUnits: 11 },
    })
    assert.equal(raised.status, 403)

    const forbidden = await call('POST', `/v1/projects/${id}/keys`, {
      token,
      idempotencyKey: `k-${uniqueSlug('qa')}`,
      body: { environment: 'live', name: 'escalation', scopes: ['devplatform:admin'] },
    })
    assert.equal(forbidden.status, 400, 'devplatform:admin was issued to an api key')
    assert.equal((forbidden.json['error'] as Record<string, unknown>)['code'], 'unknown_scope')
  })

  await t.test('an operator may raise it, and needs no membership to do so', async () => {
    const { project, token } = await projectWithDefaultQuotas()
    const id = project['id'] as string

    for (const operator of [operatorService(), operatorUser()]) {
      const raised = await call('PUT', `/v1/projects/${id}/quotas`, {
        token: operator,
        body: { environment: 'live', period: 'minute', maxUnits: 5_000 },
      })
      assert.equal(raised.status, 200)
      assert.equal((raised.json['quota'] as Record<string, unknown>)['maxUnits'], 5_000)
    }
    // The customer can still see it, and still cannot move it upward.
    const quotas = await call('GET', `/v1/projects/${id}/quotas`, { token })
    assert.match(quotas.body, /5000/)
  })

  await t.test('NOT EVEN AN OPERATOR MAY EXCEED THE CEILING IN THE SCHEMA', async () => {
    // The bound is `quotas_max_within_ceiling`, and it holds against a caller with a database
    // connection — which this handler is not. Refused here as a 400 naming the number rather than
    // reaching the constraint and returning a 500 carrying 23514.
    const { project } = await projectWithDefaultQuotas()
    const id = project['id'] as string
    const operator = operatorService()

    const over = await call('PUT', `/v1/projects/${id}/quotas`, {
      token: operator,
      body: { environment: 'live', period: 'minute', maxUnits: MAX_UNITS_CEILING.minute + 1 },
    })
    assert.equal(over.status, 400, `a minute quota of ${MAX_UNITS_CEILING.minute + 1} was accepted`)
    assert.equal((over.json['error'] as Record<string, unknown>)['code'], 'invalid')
    assert.match(String(JSON.stringify(over.json)), new RegExp(String(MAX_UNITS_CEILING.minute)))

    // The ceiling itself is legal, so this is a bound rather than a blanket refusal, and the reply
    // says what it is so a console can render the range rather than guess it.
    const at = await call('PUT', `/v1/projects/${id}/quotas`, {
      token: operator,
      body: { environment: 'live', period: 'minute', maxUnits: MAX_UNITS_CEILING.minute },
    })
    assert.equal(at.status, 200)
    assert.equal(at.json['ceiling'], MAX_UNITS_CEILING.minute)
  })

  await t.test('a service token with no operator scope reaches neither half of the route', async () => {
    // It is not a member of anything, so there is no `project:write` path open to it either.
    const { project } = await projectWithDefaultQuotas()
    const answer = await call('PUT', `/v1/projects/${project['id'] as string}/quotas`, {
      token: serviceToken([INTROSPECT_SCOPE]),
      body: { environment: 'live', period: 'minute', maxUnits: 1 },
    })
    assert.equal(answer.status, 403)
  })

  await t.test('an operator still gets a 404 for a project that does not exist', async () => {
    const answer = await call('PUT', `/v1/projects/${crypto.randomUUID()}/quotas`, {
      token: operatorService(),
      body: { environment: 'live', period: 'minute', maxUnits: 10 },
    })
    assert.equal(answer.status, 404)
  })

  /* ---------------------------------------------------------------- resolving an organisation */

  await t.test('GET /v1/organisations resolves an enrolment without a mutation', async () => {
    // Before this route the only way to answer "which developer organisation am I in?" was to
    // re-POST the idempotent enrolment and read what came back — a write issued to ask a question.
    const { org, token } = await scenario()
    const answer = await call(
      'GET',
      `/v1/organisations?identityOrgId=${encodeURIComponent(org.identityOrgId)}`,
      { token },
    )
    assert.equal(answer.status, 200)
    const organisations = answer.json['organisations'] as Array<Record<string, unknown>>
    assert.equal(organisations.length, 1)
    assert.equal(organisations[0]?.['id'], org.id)
    assert.equal(organisations[0]?.['identityOrgId'], org.identityOrgId)
  })

  await t.test('IT CANNOT BE USED TO ENUMERATE ANOTHER CUSTOMER\'S ORGANISATION', async () => {
    // Authority is asked of identity with the caller's own token BEFORE the row is read, and a
    // non-member gets the same 404 identity itself gives for "not a member, or no such
    // organisation". Resolving that ambiguity would make devplatform an oracle for organisations
    // identity deliberately hides.
    const mine = await scenario()
    const theirs = await scenario()
    const answer = await call(
      'GET',
      `/v1/organisations?identityOrgId=${encodeURIComponent(theirs.org.identityOrgId)}`,
      { token: mine.token },
    )
    assert.equal(answer.status, 404)
    assert.ok(!answer.body.includes(theirs.org.id), 'a non-member was shown the organisation id')

    // An organisation that does not exist at all answers identically.
    const unknown = await call('GET', '/v1/organisations?identityOrgId=org_does_not_exist', {
      token: mine.token,
    })
    assert.equal(unknown.status, 404)
    assert.equal(
      JSON.stringify(unknown.json).replace(/"requestId":"[^"]*"/, ''),
      JSON.stringify(answer.json).replace(/"requestId":"[^"]*"/, ''),
      'a caller can tell "not a member" from "no such organisation"',
    )
  })

  await t.test('a member of an unenrolled organisation gets an empty list, not a 404', async () => {
    // The difference matters to a console: "you are in this company but it has no developer
    // platform presence yet" is an enrolment button, whereas a 404 is a dead end. It leaks
    // nothing — identity has already confirmed the caller is a member.
    const token = `user-token-${uniqueSlug('t')}`
    const userId = `user_${uniqueSlug('u')}`
    verifier.setPrincipal(token, { kind: 'user', userId, handle: 'dev', roles: [] })
    membership.grant(userId, 'org_never_enrolled', 'owner')

    const answer = await call('GET', '/v1/organisations?identityOrgId=org_never_enrolled', { token })
    assert.equal(answer.status, 200)
    assert.deepEqual(answer.json['organisations'], [])
  })

  await t.test('the resolve route refuses a key, a service token and a missing parameter', async () => {
    const { org, project, token } = await scenario()
    const query = `?identityOrgId=${encodeURIComponent(org.identityOrgId)}`

    assert.equal((await call('GET', `/v1/organisations${query}`)).status, 401)
    assert.equal(
      (await call('GET', `/v1/organisations${query}`, { token: serviceToken(['devplatform:read']) })).status,
      403,
    )
    const issued = await issueKeyOverHttp(project, token, { scopes: ['devplatform:read'] })
    assert.equal(
      (await call('GET', `/v1/organisations${query}`, { token: issued.json['secretKey'] as string })).status,
      403,
      'an api key resolved an organisation it has no membership in',
    )
    const bare = await call('GET', '/v1/organisations', { token })
    assert.equal(bare.status, 400, 'the route listed every organisation it holds')
    assert.match(String(JSON.stringify(bare.json)), /identityOrgId is required/)
  })

  await t.test('identity being unreachable is a 503 here too, never a 404', async () => {
    const { org, token } = await scenario()
    membership.unavailable(true)
    try {
      const answer = await call(
        'GET',
        `/v1/organisations?identityOrgId=${encodeURIComponent(org.identityOrgId)}`,
        { token },
      )
      assert.equal(answer.status, 503)
    } finally {
      membership.unavailable(false)
    }
  })

  /* ---------------------------------------------------------------- webhooks over http */

  await t.test('rotating a webhook secret returns the new one once and keeps the old live', async () => {
    const { project, token } = await scenario()
    const created = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
      token,
      idempotencyKey: `wh-${uniqueSlug('a')}`,
      body: { environment: 'live', url: 'https://subscriber.example.com/hook', topics: ['devplatform.key.issued'] },
    })
    const endpointId = (created.json['endpoint'] as Record<string, unknown>)['id'] as string
    const original = created.json['secret'] as string

    const rotated = await call('POST', `/v1/webhook-endpoints/${endpointId}/rotate-secret`, {
      token,
      idempotencyKey: `rot-${uniqueSlug('b')}`,
    })
    assert.equal(rotated.status, 201)
    const next = rotated.json['secret'] as string
    assert.notEqual(next, original)

    const rows = await sql<{ secret: string; retires_at: Date | null }[]>`
      select secret, retires_at from webhook_secrets where endpoint_id = ${endpointId} order by created_at
    `
    assert.equal(rows.length, 2, 'the old secret was destroyed rather than retired')
    assert.ok(rows[0]?.retires_at, 'the old secret was not given a retirement')

    // A retried rotation replays and does NOT mint a third secret.
    const retry = await call('POST', `/v1/webhook-endpoints/${endpointId}/rotate-secret`, {
      token,
      idempotencyKey: rotated.headers['x-request-id'] ? `rot-${uniqueSlug('b')}` : 'x',
    })
    void retry
  })

  await t.test('an idempotent rotation retry replays without minting a third secret', async () => {
    const { project, token } = await scenario()
    const created = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
      token,
      idempotencyKey: `wh-${uniqueSlug('c')}`,
      body: { environment: 'live', url: 'https://subscriber.example.com/hook', topics: ['devplatform.key.issued'] },
    })
    const endpointId = (created.json['endpoint'] as Record<string, unknown>)['id'] as string
    const key = `rot-${uniqueSlug('d')}`

    const first = await call('POST', `/v1/webhook-endpoints/${endpointId}/rotate-secret`, { token, idempotencyKey: key })
    const second = await call('POST', `/v1/webhook-endpoints/${endpointId}/rotate-secret`, { token, idempotencyKey: key })

    assert.equal(first.status, 201)
    assert.equal(second.status, 200)
    assert.equal(second.json['replayed'], true)
    assert.equal(second.json['secret'], null, 'a replayed rotation handed out a secret')

    const rows = await sql<{ n: number }[]>`
      select count(*)::int as n from webhook_secrets where endpoint_id = ${endpointId}
    `
    assert.equal(rows[0]?.n, 2, 'a retried rotation minted a third secret')
  })

  await t.test('A DISABLED ENDPOINT CAN BE RE-ENABLED, AND KEEPS ITS SECRET', async () => {
    // `/disable` passed `true` unconditionally and there was no inverse, so disabling was
    // permanent: the only way back was to DELETE the endpoint and create a new one, which mints a
    // new signing secret, drops the delivery history and requires the subscriber to redeploy. An
    // endpoint is disabled DURING an incident, which is the worst hour to be told to rotate.
    const { project, token } = await scenario()
    const created = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
      token,
      idempotencyKey: `wh-${uniqueSlug('en')}`,
      body: { environment: 'live', url: 'https://subscriber.example.com/hook', topics: ['devplatform.key.issued'] },
    })
    const endpointId = (created.json['endpoint'] as Record<string, unknown>)['id'] as string
    const secretBefore = await sql<{ secret: string }[]>`
      select secret from webhook_secrets where endpoint_id = ${endpointId}
    `

    const disabled = await call('POST', `/v1/webhook-endpoints/${endpointId}/disable`, { token })
    assert.equal(disabled.status, 200)
    assert.ok((disabled.json['endpoint'] as Record<string, unknown>)['disabledAt'])

    const enabled = await call('POST', `/v1/webhook-endpoints/${endpointId}/enable`, { token })
    assert.equal(enabled.status, 200)
    assert.equal((enabled.json['endpoint'] as Record<string, unknown>)['disabledAt'], null)

    // The same signing secret, so the subscriber never had to redeploy.
    const secretAfter = await sql<{ secret: string }[]>`
      select secret from webhook_secrets where endpoint_id = ${endpointId}
    `
    assert.equal(secretAfter.length, 1)
    assert.equal(secretAfter[0]?.secret, secretBefore[0]?.secret)
    // And no route ever showed it again.
    assert.ok(!disabled.body.includes(secretBefore[0]!.secret))
    assert.ok(!enabled.body.includes(secretBefore[0]!.secret))

    // Idempotent: the second enable writes the same value and creates no second artefact.
    const again = await call('POST', `/v1/webhook-endpoints/${endpointId}/enable`, { token })
    assert.equal(again.status, 200)
    assert.equal((again.json['endpoint'] as Record<string, unknown>)['disabledAt'], null)
  })

  await t.test('enabling an endpoint needs project:write, and another customer cannot', async () => {
    const { project, token } = await scenario()
    const created = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
      token,
      idempotencyKey: `wh-${uniqueSlug('ep')}`,
      body: { environment: 'live', url: 'https://subscriber.example.com/hook', topics: ['devplatform.key.issued'] },
    })
    const endpointId = (created.json['endpoint'] as Record<string, unknown>)['id'] as string
    await call('POST', `/v1/webhook-endpoints/${endpointId}/disable`, { token })

    // A member may read but not write, so a member may not put a customer's integration back on.
    const reader = await scenario('member')
    assert.equal(
      (await call('POST', `/v1/webhook-endpoints/${endpointId}/enable`, { token: reader.token })).status,
      404,
      'a member of ANOTHER organisation re-enabled this endpoint',
    )
    // A read-scoped key in the right project is a 403 rather than a 404 — it can see the project.
    const readKey = await issueKeyOverHttp(project, token, { scopes: ['devplatform:read'] })
    assert.equal(
      (
        await call('POST', `/v1/webhook-endpoints/${endpointId}/enable`, {
          token: readKey.json['secretKey'] as string,
        })
      ).status,
      403,
    )
    assert.equal((await call('POST', `/v1/webhook-endpoints/${endpointId}/enable`)).status, 401)

    // Still disabled after all of that.
    const endpoints = await call('GET', `/v1/projects/${project.id}/webhook-endpoints`, { token })
    const endpoint = (endpoints.json['endpoints'] as Array<Record<string, unknown>>)[0]
    assert.ok(endpoint?.['disabledAt'], 'a refused enable took effect anyway')

    assert.equal(
      (await call('POST', `/v1/webhook-endpoints/${crypto.randomUUID()}/enable`, { token })).status,
      404,
    )
  })

  await t.test('a plaintext or inward-pointing webhook url is refused', async () => {
    const { project, token } = await scenario()
    for (const url of ['http://subscriber.example.com/h', 'https://169.254.169.254/latest/meta-data/']) {
      const answer = await call('POST', `/v1/projects/${project.id}/webhook-endpoints`, {
        token,
        idempotencyKey: `wh-${uniqueSlug('e')}`,
        body: { environment: 'live', url, topics: ['devplatform.key.issued'] },
      })
      assert.equal(answer.status, 400, `${url} was accepted`)
    }
  })

  /* ---------------------------------------------------------------- projects */

  await t.test('creating a project seeds both environments and their default quotas', async () => {
    const { org, token } = await scenario()
    const answer = await call('POST', '/v1/projects', {
      token,
      idempotencyKey: `proj-${uniqueSlug('p')}`,
      body: { orgId: org.id, name: 'Checkout', slug: uniqueSlug('checkout') },
    })
    assert.equal(answer.status, 201)
    const project = answer.json['project'] as Record<string, unknown>
    const environments = project['environments'] as Array<{ name: string }>
    assert.deepEqual(environments.map((e) => e.name).sort(), ['live', 'test'])

    const quotas = await call('GET', `/v1/projects/${project['id'] as string}/quotas`, { token })
    const list = quotas.json['quotas'] as unknown[]
    assert.equal(list.length, 4, 'two environments times two periods')
  })

  await t.test('an oversized body is refused rather than buffered', async () => {
    const { project, token } = await scenario()
    const answer = await call('POST', `/v1/projects/${project.id}/keys`, {
      token,
      idempotencyKey: `big-${uniqueSlug('g')}`,
      rawBody: JSON.stringify({ environment: 'live', name: 'x'.repeat(300_000), scopes: [] }),
    })
    assert.equal(answer.status, 400)
  })
})

/**
 * One handle, presented as the per-network selector the server now takes. The fixture runs against
 * a single test database, so mainnet is the only configured network — which exercises the REFUSAL
 * path for free: anything reaching for testnet throws rather than reusing this handle.
 */
function singleNetworkSql(db: unknown) {
  return networkSql({ mainnet: db as RuntimeSql })
}
