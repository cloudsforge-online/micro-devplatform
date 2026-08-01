/**
 * The credential's format and cryptography, proven without a database.
 *
 * These are the tests that must not be weakened. Every one of them corresponds to a property in
 * `keys.ts`'s header, and each is written so that the obvious "simplification" of the code under
 * test makes it fail:
 *
 *   - Return early on a lookup miss  → 'the kdf runs on every path' fails.
 *   - Check `revoked_at` before the secret → 'a revoked key costs the same as a live one' fails.
 *   - Accept `*` in a scope         → `scopes.test.ts` fails in both directions.
 *   - Hash with `createHash`        → 'the recorded algorithm is a scrypt encoding' fails, and so
 *                                     does `migrations.test.ts`'s CHECK.
 *
 * **THE CONSTANT-COST PROPERTY IS PROVEN BY COUNTING, NOT BY TIMING.** A stopwatch assertion on a
 * shared CI runner fails for reasons unrelated to the code, and a flaky security test is a security
 * test that gets deleted. `Kdf` is a seam, so the count of invocations is observable exactly.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'
import {
  CURRENT_ALGO,
  CURRENT_PARAMS,
  KEY_PREFIX,
  LOOKUP_LENGTH,
  SECRET_LENGTH,
  base32Encode,
  encodeAlgo,
  hashSecret,
  issueKey,
  keyDisplay,
  parseAlgo,
  parseKey,
  redactKeys,
  resetDecoy,
  scryptKdf,
  verifyAgainst,
  verifyPresentedKey,
  type Kdf,
  type ScryptParams,
  type VerifiableKey,
} from './keys.ts'

/** scrypt at the lowest legal cost. The properties under test are cost-independent by design. */
const FAST: ScryptParams = { N: 2, r: 8, p: 1, keyLen: 64 }

/** The real KDF behind a counter. The count is the whole instrument. */
function countingKdf(): { kdf: Kdf; calls: () => number } {
  let calls = 0
  const kdf: Kdf = (secret, salt, params) => {
    calls += 1
    return scryptKdf(secret, salt, params)
  }
  return { kdf, calls: () => calls }
}

/* ------------------------------------------------------------------ the alphabet */

test('base32 encodes into the declared alphabet and nothing else', () => {
  for (let i = 0; i < 200; i += 1) {
    const encoded = base32Encode(randomBytes(1 + (i % 40)))
    assert.match(encoded, /^[a-z2-7]*$/, `${encoded} left the alphabet`)
  }
})

test('base32 never emits the field separator', () => {
  // The whole reason base32 was chosen over base64url: `_` splits the key format, and a separator
  // that can occur inside a field is a parse that can be steered.
  for (let i = 0; i < 200; i += 1) {
    assert.ok(!base32Encode(randomBytes(32)).includes('_'))
  }
})

test('base32 is deterministic and injective on short inputs', () => {
  const seen = new Map<string, string>()
  for (let i = 0; i < 256; i += 1) {
    const bytes = Uint8Array.from([i])
    const encoded = base32Encode(bytes)
    assert.equal(encoded, base32Encode(bytes), 'not deterministic')
    const previous = seen.get(encoded)
    assert.equal(previous, undefined, `collision: ${i} and ${previous} both encode to ${encoded}`)
    seen.set(encoded, String(i))
  }
})

/* ------------------------------------------------------------------ the format */

test('an issued key has four parts, and the third is the lookup id', async () => {
  const issued = await issueKey('live', FAST)
  const parts = issued.secretKey.split('_')
  assert.equal(parts.length, 4)
  assert.equal(parts[0], KEY_PREFIX)
  assert.equal(parts[1], 'live')
  assert.equal(parts[2], issued.lookupId)
  assert.equal(parts[2]?.length, LOOKUP_LENGTH)
  assert.equal(parts[3]?.length, SECRET_LENGTH)
})

test('the display string is the key with the secret removed', async () => {
  const issued = await issueKey('test', FAST)
  assert.equal(issued.display, keyDisplay('test', issued.lookupId))
  assert.ok(issued.secretKey.startsWith(`${issued.display}_`))
  // The property the whole format is arranged around: identifiable without being usable.
  assert.ok(!issued.display.includes(issued.secretKey.split('_')[3] ?? 'x'))
})

test('parseKey round-trips an issued key and refuses everything else', async () => {
  const issued = await issueKey('live', FAST)
  const parsed = parseKey(issued.secretKey)
  assert.ok(parsed)
  assert.equal(parsed.environment, 'live')
  assert.equal(parsed.lookupId, issued.lookupId)

  const rejects = [
    '',
    'cfk_live',
    'cfk_live_short_short',
    `cfk_prod_${'a'.repeat(16)}_${'a'.repeat(52)}`,
    `cfk_live_${'a'.repeat(15)}_${'a'.repeat(52)}`,
    `cfk_live_${'a'.repeat(16)}_${'a'.repeat(51)}`,
    `cfk_live_${'A'.repeat(16)}_${'a'.repeat(52)}`,
    `cfk_live_${'1'.repeat(16)}_${'a'.repeat(52)}`,
    `xcfk_live_${'a'.repeat(16)}_${'a'.repeat(52)}`,
    `${issued.secretKey}extra`,
    `${issued.secretKey}\n${issued.secretKey}`,
  ]
  for (const value of rejects) {
    assert.equal(parseKey(value), null, `${JSON.stringify(value)} should not parse`)
  }
})

test('parseKey is anchored, so a key embedded in other text does not parse', async () => {
  const issued = await issueKey('live', FAST)
  assert.equal(parseKey(`prefix ${issued.secretKey}`), null)
  assert.equal(parseKey(`${issued.secretKey} suffix`), null)
})

test('redactKeys keeps the identifiable half and destroys the usable half', async () => {
  const issued = await issueKey('live', FAST)
  const line = `auth failed for ${issued.secretKey} on /v1/wallets`
  const redacted = redactKeys(line)
  assert.ok(redacted.includes(issued.display), 'the operator must still be able to revoke it')
  assert.ok(!redacted.includes(issued.secretKey), 'the secret survived redaction')
  assert.ok(redacted.includes('[redacted]'))
})

/* ------------------------------------------------------------------ the hash */

test('the recorded algorithm is a scrypt encoding, and round-trips', () => {
  assert.equal(CURRENT_ALGO, 'scrypt$N=16384,r=8,p=1,keyLen=64')
  assert.deepEqual(parseAlgo(CURRENT_ALGO), CURRENT_PARAMS)
  assert.deepEqual(parseAlgo(encodeAlgo(FAST)), FAST)
})

test('parseAlgo refuses anything that is not scrypt, or is malformed', () => {
  for (const value of [
    'sha256',
    'sha256$N=1',
    'bcrypt$N=16384,r=8,p=1,keyLen=64',
    'scrypt$N=16385,r=8,p=1,keyLen=64', // not a power of two
    'scrypt$N=1,r=8,p=1,keyLen=64', // below the floor
    'scrypt$N=16384,r=0,p=1,keyLen=64',
    'scrypt$N=16384,r=8,p=1,keyLen=8',
    'scrypt$N=16384,r=8,p=1',
    '',
  ]) {
    assert.equal(parseAlgo(value), null, `${value} should not parse as scrypt parameters`)
  }
})

test('the same secret hashes to two different rows', async () => {
  const a = await hashSecret('the-same-secret', FAST)
  const b = await hashSecret('the-same-secret', FAST)
  assert.notEqual(a.salt, b.salt, 'the salt must be random per key')
  assert.notEqual(a.hash, b.hash, 'two identical secrets must not produce identical rows')
  // Both still verify — the salt is recorded, so the derivation is reproducible.
  assert.equal(await verifyAgainst('the-same-secret', a), true)
  assert.equal(await verifyAgainst('the-same-secret', b), true)
})

test('a hash verifies under its OWN recorded parameters, not the current ones', async () => {
  // This is the property that makes raising the work factor a one-line change. A row written at
  // N=2 must keep verifying after CURRENT_PARAMS moves, or the upgrade is a forced reset.
  const stored = await hashSecret('legacy', FAST)
  assert.equal(stored.algo, encodeAlgo(FAST))
  assert.notEqual(stored.algo, CURRENT_ALGO)
  assert.equal(await verifyAgainst('legacy', stored), true)
})

test('verifyAgainst refuses a row whose algorithm this build cannot parse', async () => {
  const stored = await hashSecret('x', FAST)
  // A row written by a NEWER build during a rolling deploy. The correct answer is "cannot verify",
  // which the caller renders as 401 — never a guess at current parameters.
  assert.equal(await verifyAgainst('x', { ...stored, algo: 'argon2id$m=65536,t=3,p=4' }), false)
})

test('verifyAgainst refuses a wrong secret and a corrupt hash without throwing', async () => {
  const stored = await hashSecret('right', FAST)
  assert.equal(await verifyAgainst('wrong', stored), false)
  assert.equal(await verifyAgainst('right', { ...stored, hash: 'not-hex' }), false)
  assert.equal(await verifyAgainst('right', { ...stored, hash: '' }), false)
  assert.equal(await verifyAgainst('right', { ...stored, salt: 'zz' }), false)
})

/* ------------------------------------------------------------------ verification */

function liveRow(stored: { algo: string; salt: string; hash: string }): VerifiableKey {
  return { ...stored, environment: 'live', revokedAt: null, expiresAt: null }
}

test('a live key with the right secret verifies', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const outcome = await verifyPresentedKey(issued.secretKey, async () => liveRow(issued.stored), {
    params: FAST,
  })
  assert.equal(outcome.ok, true)
  assert.equal(outcome.ok && outcome.lookupId, issued.lookupId)
})

test('THE KDF RUNS ON EVERY PATH: unknown, revoked and live each cost exactly one run', async () => {
  // The test this file exists for. If any of these counts is 0, response latency is an oracle: a
  // caller learns from a fast answer that a lookup id does not exist, or that a key was revoked —
  // which is "the account is real and someone is watching" rather than "this never existed".
  const issued = await issueKey('live', FAST)

  // Warm the decoy first, with an uncounted call. Building it is itself a scrypt run, so the very
  // first miss in a process costs two and every miss after it costs one — which is the steady state
  // and the only one an attacker can measure. The cold-start cost is asserted separately below.
  resetDecoy()
  await verifyPresentedKey(`cfk_live_${'a'.repeat(LOOKUP_LENGTH)}_${'b'.repeat(SECRET_LENGTH)}`, async () => null, {
    params: FAST,
  })

  for (const scenario of ['unknown', 'revoked', 'expired', 'bad_secret'] as const) {
    const { kdf, calls } = countingKdf()

    const presented =
      scenario === 'bad_secret'
        ? `${issued.display}_${'a'.repeat(SECRET_LENGTH)}`
        : issued.secretKey

    const load = async (): Promise<VerifiableKey | null> => {
      if (scenario === 'unknown') return null
      const base = liveRow(issued.stored)
      if (scenario === 'revoked') return { ...base, revokedAt: new Date('2020-01-01') }
      if (scenario === 'expired') return { ...base, expiresAt: new Date('2020-01-01') }
      return base
    }

    const outcome = await verifyPresentedKey(presented, load, { kdf, params: FAST })
    assert.equal(outcome.ok, false, `${scenario} must not authenticate`)
    assert.equal(
      calls(),
      1,
      `${scenario} ran the kdf ${calls()} times, expected exactly 1 — a refusal that skips the ` +
        'kdf is distinguishable by timing from one that does not',
    )
  }

  // And the live path costs the same one run, so there is nothing to compare against.
  const live = countingKdf()
  const ok = await verifyPresentedKey(issued.secretKey, async () => liveRow(issued.stored), {
    kdf: live.kdf,
    params: FAST,
  })
  assert.equal(ok.ok, true)
  assert.equal(live.calls(), 1, 'the live path must cost the same single kdf run')
})

test('the decoy is built once and reused, so a failed auth costs one run and not two', async () => {
  resetDecoy()
  const { kdf, calls } = countingKdf()
  const presented = `cfk_live_${'a'.repeat(LOOKUP_LENGTH)}_${'b'.repeat(SECRET_LENGTH)}`

  await verifyPresentedKey(presented, async () => null, { kdf, params: FAST })
  const afterFirst = calls()
  // The first miss pays for building the decoy AND for verifying against it.
  assert.ok(afterFirst >= 1)

  await verifyPresentedKey(presented, async () => null, { kdf, params: FAST })
  assert.equal(
    calls() - afterFirst,
    1,
    'a subsequent miss must cost exactly one kdf run — rebuilding the decoy per request doubles ' +
      'the cost of the one request an attacker controls the rate of',
  )
})

test('a malformed key is the ONE path that skips the kdf, deliberately', async () => {
  resetDecoy()
  const { kdf, calls } = countingKdf()
  let loaded = false
  const outcome = await verifyPresentedKey(
    'not-a-key-at-all',
    async () => {
      loaded = true
      return null
    },
    { kdf, params: FAST },
  )
  assert.equal(outcome.ok, false)
  assert.equal(outcome.ok === false && outcome.reason, 'malformed')
  assert.equal(outcome.ok === false && outcome.lookupId, null, 'a malformed string carries no lookup id')
  assert.equal(loaded, false, 'a malformed string must never reach the database')
  assert.equal(
    calls(),
    0,
    'spending 60ms of cpu on a string that was never a key hands an unauthenticated caller a way ' +
      'to exhaust the process, and reveals nothing about which keys exist',
  )
})

test('the secret is checked BEFORE the state, so a revoked key still costs a hash', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const { kdf, calls } = countingKdf()
  const outcome = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), revokedAt: new Date('2020-01-01') }),
    { kdf, params: FAST },
  )
  assert.equal(outcome.ok, false)
  assert.equal(outcome.ok === false && outcome.reason, 'revoked')
  assert.equal(calls(), 1)
})

test('a revoked key and an unknown key are the same shape of answer', async () => {
  // Both are `{ ok: false }` carrying only a reason the SERVER logs. `server.test.ts` proves the
  // reason never reaches the wire; this proves the two are structurally identical here.
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const revoked = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), revokedAt: new Date('2020-01-01') }),
    { params: FAST },
  )
  resetDecoy()
  const unknown = await verifyPresentedKey(issued.secretKey, async () => null, { params: FAST })

  assert.equal(revoked.ok, false)
  assert.equal(unknown.ok, false)
  assert.deepEqual(Object.keys(revoked).sort(), Object.keys(unknown).sort())
})

test('an expiry in the future is fine; one in the past is not', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const now = new Date('2026-01-01T00:00:00Z')

  const future = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), expiresAt: new Date('2027-01-01T00:00:00Z') }),
    { now, params: FAST },
  )
  assert.equal(future.ok, true)

  const past = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), expiresAt: new Date('2025-01-01T00:00:00Z') }),
    { now, params: FAST },
  )
  assert.equal(past.ok, false)
  assert.equal(past.ok === false && past.reason, 'expired')
})

test('an expiry exactly at now is expired, not live', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const now = new Date('2026-01-01T00:00:00Z')
  const outcome = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), expiresAt: now }),
    { now, params: FAST },
  )
  assert.equal(outcome.ok, false, 'the boundary must fall closed')
})

test('a key string whose environment disagrees with its row is refused', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const outcome = await verifyPresentedKey(
    issued.secretKey,
    async () => ({ ...liveRow(issued.stored), environment: 'test' as const }),
    { params: FAST },
  )
  assert.equal(outcome.ok, false)
  assert.equal(outcome.ok === false && outcome.reason, 'wrong_environment')
})

test('a key hashed under old parameters authenticates and asks to be re-hashed', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const outcome = await verifyPresentedKey(issued.secretKey, async () => liveRow(issued.stored), {
    // Verifying against the CURRENT parameters while the row records FAST.
    params: CURRENT_PARAMS,
    kdf: scryptKdf,
  })
  assert.equal(outcome.ok, true)
  assert.equal(
    outcome.ok && outcome.needsRehash,
    true,
    'without this, raising CURRENT_PARAMS would protect only keys issued afterwards',
  )
})

test('a key already at the current parameters is not re-hashed', async () => {
  resetDecoy()
  const issued = await issueKey('live', FAST)
  const outcome = await verifyPresentedKey(issued.secretKey, async () => liveRow(issued.stored), {
    params: FAST,
  })
  assert.equal(outcome.ok && outcome.needsRehash, false)
})

test('two issued keys never share a lookup id or a secret', async () => {
  const lookups = new Set<string>()
  const secrets = new Set<string>()
  for (let i = 0; i < 50; i += 1) {
    const issued = await issueKey(i % 2 === 0 ? 'live' : 'test', FAST)
    assert.ok(!lookups.has(issued.lookupId), 'lookup id collision')
    assert.ok(!secrets.has(issued.secretKey), 'secret collision')
    lookups.add(issued.lookupId)
    secrets.add(issued.secretKey)
  }
})

test('nothing in an IssuedKey exposes the secret except `secretKey`', async () => {
  const issued = await issueKey('live', FAST)
  const secret = issued.secretKey.split('_')[3]!
  const withoutTheField = { ...issued, secretKey: undefined }
  assert.ok(
    !JSON.stringify(withoutTheField).includes(secret),
    'the secret leaked into another field of the issuance result',
  )
})
