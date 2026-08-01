/**
 * The scope rules, both directions.
 *
 * "A wildcard grants nothing" is two separate claims and each protects against a different failure:
 *
 *   1. **A wildcard cannot be ISSUED.** `validateScopes` refuses it, so no row can be written with
 *      one through the application. `migrations.test.ts` proves the database refuses it too, for
 *      the write paths the application does not own.
 *   2. **A wildcard would GRANT NOTHING if one somehow reached a row.** `grantsScope` is exact
 *      match, so a row carrying `market:*` — restored from an old dump, written by a migration,
 *      inserted by hand during an incident — authorises nothing rather than everything.
 *
 * Testing only (1) leaves a service where the guard is a validation, and validations get bypassed.
 * Testing only (2) leaves a service that silently issues keys a developer believes are powerful.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  SCOPES,
  SCOPE_NAMES,
  UnknownScopeError,
  grantsAllScopes,
  grantsScope,
  isScope,
  knownScopes,
  scopeSpec,
  validateScopes,
  type Scope,
} from './scopes.ts'

/* ------------------------------------------------------------------ the registry */

test('every scope names a service and a kind, and reads as service:action', () => {
  for (const name of SCOPE_NAMES) {
    const spec = scopeSpec(name)
    assert.ok(spec.service.length > 0, `${name} names no service`)
    assert.ok(spec.kind === 'read' || spec.kind === 'write', `${name} has no kind`)
    assert.ok(spec.description.length > 20, `${name} has no usable description`)
    // Named by SERVICE and ACTION, never by URL path — a scope named for a route is invalidated
    // the day the gateway moves it, and the gateway has moved once already.
    assert.match(name, /^[a-z]+:[a-z]+$/, `${name} is not service:action`)
    assert.equal(name.split(':')[0], spec.service, `${name} disagrees with its own service`)
  }
})

test('no scope in the registry contains a wildcard', () => {
  for (const name of SCOPE_NAMES) {
    assert.ok(!name.includes('*'), `${name} is a wildcard, and there are none`)
  }
})

test('the registry is frozen, so a scope cannot be added at runtime', () => {
  assert.throws(() => {
    // @ts-expect-error — deliberately writing to a frozen registry.
    SCOPES['everything:*'] = { service: 'x', kind: 'write', description: 'no' }
  })
  assert.equal(isScope('everything:*'), false)
})

test('isScope accepts exactly the registry', () => {
  for (const name of SCOPE_NAMES) assert.equal(isScope(name), true)
  for (const name of ['', '*', 'market', 'market:', ':read', 'MARKET:READ', 'market:admin']) {
    assert.equal(isScope(name), false, `${name} must not be a scope`)
  }
})

/* ------------------------------------------------------------------ granting */

test('A KEY WITH NO SCOPES GRANTS NOTHING', () => {
  for (const name of SCOPE_NAMES) {
    assert.equal(grantsScope([], name), false, `an empty scope set granted ${name}`)
  }
  // And an empty set is a legal, inert credential rather than an error — which is what makes the
  // property provable at all: a key can exist and authorise nothing.
  assert.deepEqual(validateScopes([]), [])
})

test('A WILDCARD GRANTS NOTHING, in every form it could take', () => {
  const wildcards = ['*', '*:*', 'market:*', ':*', 'market:**', '**', 'market:*x', '.*']
  for (const wildcard of wildcards) {
    for (const required of SCOPE_NAMES) {
      assert.equal(
        grantsScope([wildcard], required),
        false,
        `${wildcard} granted ${required} — there is no hierarchy and no wildcard`,
      )
    }
  }
})

test('a wildcard beside a real scope grants only the real scope', () => {
  // The realistic shape of the mistake: someone edits a row and adds `market:*` next to what was
  // already there, believing they have widened it.
  const granted = ['market:read', 'market:*']
  assert.equal(grantsScope(granted, 'market:read'), true)
  assert.equal(grantsScope(granted, 'market:write'), false)
})

test('there is no implication ordering: write does not cover read', () => {
  assert.equal(grantsScope(['market:write'], 'market:read'), false)
  assert.equal(grantsScope(['market:read'], 'market:write'), false)
  assert.equal(grantsScope(['worlds:write'], 'worlds:read'), false)
})

test('there is no prefix implication across services', () => {
  assert.equal(grantsScope(['market:read'], 'mint:read'), false)
  assert.equal(grantsScope(['mint:read'], 'market:read'), false)
})

test('grantsScope is exact and case-sensitive', () => {
  assert.equal(grantsScope(['market:read'], 'market:read'), true)
  assert.equal(grantsScope(['MARKET:READ'], 'market:read'), false)
  assert.equal(grantsScope([' market:read'], 'market:read'), false)
  assert.equal(grantsScope(['market:read '], 'market:read'), false)
})

test('grantsAllScopes needs every scope, and an empty requirement is satisfied', () => {
  const granted = ['market:read', 'market:write']
  assert.equal(grantsAllScopes(granted, ['market:read', 'market:write']), true)
  assert.equal(grantsAllScopes(granted, ['market:read', 'mint:read']), false)
  // A route that requires no scope requires no scope. Routes that must never be reachable by a key
  // demand one explicitly — `authoriseProject` in server.ts always names one.
  assert.equal(grantsAllScopes([], []), true)
})

/* ------------------------------------------------------------------ issuance */

test('validateScopes REFUSES an unknown scope rather than filtering it', () => {
  // Filtering is the tempting version and it is worse than an error: a caller that asked for
  // `market:write` and `wallet:*` and got back a key with only the first would believe it holds an
  // authority it does not, and would find out at the worst possible moment.
  assert.throws(
    () => validateScopes(['market:write', 'wallet:*']),
    (err: unknown) => err instanceof UnknownScopeError && err.unknown.includes('wallet:*'),
  )
  assert.throws(() => validateScopes(['*']), UnknownScopeError)
  assert.throws(() => validateScopes(['market:admin']), UnknownScopeError)
})

test('the refusal names every unknown scope, once each', () => {
  try {
    validateScopes(['nope:read', 'nope:read', 'also:bad', 'market:read'])
    assert.fail('should have thrown')
  } catch (err) {
    assert.ok(err instanceof UnknownScopeError)
    assert.deepEqual([...err.unknown].sort(), ['also:bad', 'nope:read'])
    assert.ok(err.message.includes('There is no wildcard'), 'the message must say why')
  }
})

test('validateScopes normalises: trimmed, deduplicated, sorted', () => {
  // Stability is what makes an idempotency fingerprint over a scope list meaningful — two
  // identical requests that listed their scopes in a different order must produce one key.
  const a = validateScopes([' market:write ', 'market:read', 'market:write'])
  const b = validateScopes(['market:read', 'market:write'])
  assert.deepEqual(a, ['market:read', 'market:write'])
  assert.deepEqual(a, b)
})

test('validateScopes drops empty entries rather than refusing them', () => {
  // A trailing comma in a console form is a user-interface artefact, not an attempt at a scope.
  assert.deepEqual(validateScopes(['market:read', '', '   ']), ['market:read'])
})

test('the validated result is frozen', () => {
  const scopes = validateScopes(['market:read'])
  assert.throws(() => {
    ;(scopes as Scope[]).push('market:write')
  })
})

test('knownScopes drops what the registry does not know, and keeps what it does', () => {
  assert.deepEqual(knownScopes(['market:read', 'market:*', 'nope', '*']), ['market:read'])
  assert.deepEqual(knownScopes([]), [])
})

test('this service can express a read-only and a write key over its own resources', () => {
  // The two scopes `server.ts` demands. Named here so that removing either from the registry fails
  // a test rather than turning every devplatform route into a 403 at run time.
  assert.equal(isScope('devplatform:read'), true)
  assert.equal(isScope('devplatform:write'), true)
  assert.equal(grantsScope(['devplatform:read'], 'devplatform:write'), false)
})
