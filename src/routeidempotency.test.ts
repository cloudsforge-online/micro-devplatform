/**
 * Every mutating route either replays a retry or has a documented reason not to.
 *
 * **WHY THIS IS A SOURCE-LEVEL TEST.** `micro-market` shipped `POST /v1/orders/:id/disputes` and
 * `POST /v1/moderation/cases` as plain INSERTs with no natural key and no route wrapper, so a
 * double-clicked button opened two disputes on one order and froze the listing twice. Both sat
 * beside four sibling routes that wrapped correctly, and nothing noticed — because the domain tests
 * call the domain functions directly and never traverse the route.
 *
 * The defect is an OMISSION, and an omission has no behaviour to test. So this asserts the shape of
 * the file: a route added tomorrow without a wrapper fails here, and the author must either wrap it
 * or write down why it does not need one.
 *
 * The stakes here are higher than a duplicate dispute. `POST /v1/projects/:id/keys` unwrapped mints
 * TWO credentials on a retry, and the second is one the developer never saw and therefore never
 * revokes: a live key with no owner.
 *
 * This file is `market/src/routeidempotency.test.ts`, adopted deliberately rather than reinvented.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const SERVER = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8')

/**
 * Mutating routes that are safe WITHOUT the wrapper, each with the reason it is safe.
 *
 * A route is only exempt if retrying it a second time cannot produce a second artefact. "It
 * probably will not be retried" is not a reason; every one of these names the mechanism.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  'POST /v1/organisations':
    'developer_orgs_identity_uniq makes the identity organisation the natural key, and enrolOrg is ' +
    '`on conflict do nothing` then read — a second enrolment IS the first',
  'POST /v1/projects/:id/service-accounts':
    'service_accounts_name_uniq makes (project, name) the natural key; createServiceAccount is ' +
    '`on conflict do nothing` then read, so a retry returns the first account',
  'PUT /v1/projects/:id/quotas':
    'an upsert on (environment_id, meter, period) — the natural key. A retry writes the same row',
  'PUT /v1/projects/:id/application':
    'an upsert on project_id; applications_project_uniq allows one listing per project, so a retry updates',
  'POST /v1/projects/:id/application/submit':
    'a state transition claimed with `where status in (...)`; the second attempt matches no row',
  'POST /v1/webhook-endpoints/:id/disable':
    'a state transition writing a fixed value; the second attempt writes the same value',
  'POST /v1/webhook-endpoints/:id/enable':
    'the inverse of /disable, and the same mechanism: a state transition writing a fixed value ' +
    '(disabled_at = null), so the second attempt writes the same value',
  'PUT /v1/projects/:id/application/status':
    'a state transition claimed with `where status = any(...)` from OPERATOR_TRANSITIONS; the ' +
    'second attempt matches no row and answers 409 rather than deciding the application twice',
  'DELETE /v1/keys/:id':
    'DELETE is idempotent by definition, and revokeApiKey claims with `where revoked_at is null` so ' +
    'the first revocation\'s time and reason survive',
  'DELETE /v1/webhook-endpoints/:id': 'DELETE is idempotent by definition',
  'DELETE /v1/oauth-clients/:id':
    'DELETE is idempotent by definition; revokeClient uses coalesce(revoked_at, now())',
  'POST /v1/events':
    'the inbox, deduplicated on source_event_id — its idempotency is the whole point of the table',
  'POST /internal/keys/verify': 'a read. It verifies a credential and creates nothing',
  'POST /internal/oauth/verify': 'a read. It verifies a client secret and creates nothing',
  'POST /internal/usage':
    'a meter. Two identical calls a millisecond apart ARE two calls, and deduplicating usage would ' +
    'under-report exactly the customer using the platform hardest',
}

function mutatingRoutes(): Array<{ key: string; wrapped: boolean }> {
  const out: Array<{ key: string; wrapped: boolean }> = []
  const re = /define\('(POST|PUT|PATCH|DELETE)', '([^']+)'/g
  const starts: Array<{ key: string; at: number }> = []
  for (let m = re.exec(SERVER); m !== null; m = re.exec(SERVER)) {
    starts.push({ key: `${m[1]} ${m[2]}`, at: m.index })
  }
  const all = [...SERVER.matchAll(/define\('[A-Z]+', '[^']+'/g)].map((m) => m.index ?? 0)
  for (const s of starts) {
    const next = all.find((i) => i > s.at) ?? SERVER.length
    out.push({ key: s.key, wrapped: SERVER.slice(s.at, next).includes('withIdempotentRoute') })
  }
  return out
}

test('every mutating route replays a retry, or says why it need not', () => {
  const unexplained = mutatingRoutes()
    .filter((r) => !r.wrapped && !(r.key in EXEMPT))
    .map((r) => r.key)
  assert.deepEqual(
    unexplained,
    [],
    `these mutating routes neither wrap withIdempotentRoute nor appear in EXEMPT:\n  ${unexplained.join('\n  ')}\n` +
      'A retried request must not create a second artefact. Wrap it, or add it to EXEMPT with the reason it is safe.',
  )
})

test('THE ROUTES THAT MINT A CREDENTIAL ARE WRAPPED', () => {
  // The four routes whose retry would hand a second secret to somebody. Named individually, so
  // that unwrapping one fails with a message about credentials rather than about a list.
  const byKey = new Map(mutatingRoutes().map((r) => [r.key, r.wrapped]))
  assert.equal(
    byKey.get('POST /v1/projects/:id/keys'),
    true,
    'a retry must not mint a second API key — the second is one the developer never sees and never revokes',
  )
  assert.equal(
    byKey.get('POST /v1/projects/:id/oauth-clients'),
    true,
    'a retry must not register a second oauth client',
  )
  assert.equal(
    byKey.get('POST /v1/projects/:id/webhook-endpoints'),
    true,
    'a retry must not mint a second webhook signing secret',
  )
  assert.equal(
    byKey.get('POST /v1/webhook-endpoints/:id/rotate-secret'),
    true,
    'a retry must not rotate twice — the second rotation retires the secret the customer was just shown',
  )
})

test('the checker sees the routes at all', () => {
  // An empty list passes the first test vacuously. This is the line that stops that.
  const routes = mutatingRoutes()
  assert.ok(routes.length >= 12, `expected the server to have many mutating routes, found ${routes.length}`)
  assert.ok(routes.some((r) => r.wrapped), 'no route was detected as wrapped — the detector is broken')
  assert.ok(routes.some((r) => !r.wrapped), 'every route looks wrapped — the detector is broken the other way')
})

test('no exemption is stale', () => {
  // An exemption for a route that no longer exists is a claim nobody is checking, and it hides the
  // day that route comes back without a wrapper.
  const keys = new Set(mutatingRoutes().map((r) => r.key))
  for (const k of Object.keys(EXEMPT)) {
    assert.ok(keys.has(k), `EXEMPT names ${k}, which is not a route on this server any more`)
  }
})

test('every exemption states a mechanism, not an intention', () => {
  for (const [route, reason] of Object.entries(EXEMPT)) {
    assert.ok(reason.length > 30, `${route}'s exemption is too short to be a reason`)
    assert.ok(
      /natural key|on conflict|idempotent by definition|state transition|upsert|dedup|inbox|a read|a meter|coalesce|matches no row/i.test(
        reason,
      ),
      `${route}'s exemption does not name a mechanism: "${reason}"`,
    )
  }
})

/* ------------------------------------------------------------------ the other enumeration */

test('EVERY SECRET A RESPONSE CARRIES IS MINTED IN THAT REQUEST, NOT READ FROM A ROW', () => {
  // The source-level companion to `server.test.ts`'s over-the-wire proof.
  //
  // A secret reaches a response through exactly one shape: a `let … : string | null = null` holder
  // declared inside a route, assigned from the call that MINTS the value, and spread into the reply
  // afterwards. `null` is what a replay carries, which is what makes a replay safe. Any holder that
  // is not on this list, or that is assigned from anything but a mint, is a reveal endpoint by
  // another name — which is what micro-custody deleted rather than guard (SD-08).
  const holders = [...SERVER.matchAll(/let (\w+): string \| null = null/g)].map((m) => m[1] as string)
  assert.deepEqual(
    [...holders].sort(),
    // Four routes mint something: a key, a webhook secret at creation, a webhook secret on
    // rotation, and an oauth client secret. Two of them name their holder `secret`.
    ['clientSecret', 'minted', 'secret', 'secret'],
    'a route declares a new secret holder',
  )

  // And EVERY assignment to one of them comes from a call that mints a fresh value. A holder
  // assigned from a query result would be a reveal endpoint wearing a legitimate variable name.
  const MINTS = [
    'minted = issued.secretKey',
    'secret = created.secret',
    'secret = await rotateSecret(tx, id, deps.webhookRotationOverlapMinutes)',
    'clientSecret = registered.clientSecret',
  ]
  const assignments = [...SERVER.matchAll(/(?<!let )\b(minted|secret|clientSecret) = ([^\n]+)/g)]
    .map((m) => `${m[1]} = ${m[2]}`.replace(/\s+$/, ''))
  assert.equal(assignments.length, MINTS.length, `expected ${MINTS.length} assignments, found ${assignments.length}`)
  for (const assignment of assignments) {
    assert.ok(
      MINTS.includes(assignment),
      `\`${assignment}\` is not one of the four mints — a secret must never be read back into a response`,
    )
  }
})

test('the server never selects a stored secret column', () => {
  // The other half: even if a holder were legitimate, a route that read `secret_hash` or
  // `webhook_secrets.secret` out of the database would be reconstructing a reveal endpoint.
  for (const forbidden of ['secret_hash', 'secret_salt', 'secret_algo', 'from webhook_secrets']) {
    assert.ok(!SERVER.includes(forbidden), `server.ts reads ${forbidden}`)
  }
})

test('no route reads a stored webhook secret back to a caller', () => {
  // `liveSecrets` and `signingSecret` exist for the delivery job. If either appears inside a route
  // handler, a customer can read a secret they were shown once — which is the whole property.
  //
  // ── THIS CHECK WAS VACUOUS, AND IS THE THIRD OF ITS KIND FOUND IN THIS ESTATE. ────────────────
  //
  // It ended the slice at `SERVER.indexOf('/* ----')`, which finds the FIRST such banner in the
  // file — the `plumbing` one, ~15 kB BEFORE `function buildRoutes`. A backwards slice in
  // JavaScript is the empty string, so this searched nothing and could never fail, for either
  // name, however a route was written. Exactly the failure `micro-trade-web`'s hardcoded line
  // numbers produced: a guard that cannot fail is worse than none, because it is counted.
  //
  // Fixed by naming the banner that CLOSES the route list rather than the first one that matches a
  // prefix, and by asserting the extractor found the block at all — a length assertion is what
  // stops the next version going quiet the same way.
  const start = SERVER.indexOf('function buildRoutes')
  const end = SERVER.indexOf('------ helpers */', start)
  assert.ok(start >= 0 && end > start, 'the route block could not be located in server.ts')
  const routeBlock = SERVER.slice(start, end)
  assert.ok(
    routeBlock.length > 10_000 && routeBlock.includes("define('GET', '/v1/scopes'"),
    `the route block extractor found ${routeBlock.length} characters and no route list`,
  )
  for (const forbidden of ['liveSecrets', 'signingSecret']) {
    assert.ok(!routeBlock.includes(forbidden), `a route calls ${forbidden}`)
  }
})
