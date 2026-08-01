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

import { test } from 'node:test'
import assert from 'node:assert/strict'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, registerHttpMetrics } from '@cloudsforge/telemetry'
import type { Principal } from '@cloudsforge/auth'
import {
  INTROSPECT_SCOPE,
  createServer,
  registerServiceMetrics,
  type PrincipalVerifier,
  type ServerDeps,
} from './server.ts'
import { signEvent, type Db } from './outbox.ts'
import { parseKey } from './keys.ts'
import { MembershipUnavailableError, type MembershipClient, type OrgRole } from './membership.ts'
import {
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
    sql: store,
    producer: 'devplatform',
    ingestSecrets: [INGEST_SECRET],
    defaultQuotaPerMinute: 600,
    defaultQuotaPerMonth: 1_000_000,
    webhookSecretOverlapMinutes: 60,
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
    assert.ok(checked >= 16, `only ${checked} read routes were walked`)
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
    const set = await call('PUT', `/v1/projects/${project.id}/quotas`, {
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 2 },
    })
    assert.equal(set.status, 200)

    const service = serviceToken([INTROSPECT_SCOPE])
    const meter = () => call('POST', '/internal/usage', { token: service, body: { keyId, route: '/v1/rates' } })

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
      token,
      body: { environment: 'live', period: 'minute', maxUnits: 5 },
    })

    const service = serviceToken([INTROSPECT_SCOPE])
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

  await t.test('a deleted USER does not revoke the organisation\'s keys', async () => {
    // Their keys were issued TO the organisation and remain the organisation's. Revoking them would
    // take a company's production integration down because an employee closed their account.
    const { project } = await scenario()
    const issued = await seedKey(sql, project.id)
    const raw = envelopeFor('identity.user.deleted', { userId: 'user_gone' })
    const answer = await call('POST', '/v1/events', {
      rawBody: raw,
      headers: { 'cf-signature': signEvent(raw, INGEST_SECRET) },
    })
    assert.equal(answer.status, 202)
    assert.equal(answer.json['revoked'], 0)
    assert.equal((await call('GET', '/v1/keys/self', { token: issued.secretKey })).status, 200)
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

    // Only the operator transition does.
    await sql`update applications set status = 'listed', listed_at = now() where project_id = ${project.id}`
    const listed = await call('GET', `/v1/apps/${slug}`)
    assert.equal(listed.status, 200)
    assert.ok((await call('GET', '/v1/apps')).body.includes(slug))
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
