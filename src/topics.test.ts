/**
 * The producer half of the bus contract, checked against the source rather than against a list.
 *
 * Two families of check, for the two shapes one defect class has already taken in this estate:
 *
 *   1. **The name.** `wallet` emitted `wallet.deposit.credited` for the life of the service while
 *      the registry, `notify` and `activity` all spelled it `wallet.deposit.confirmed`. Nothing
 *      could ever match it. Reconciling the emitted set with the registry in BOTH directions is
 *      what catches that, and reading the literals back out of `src/` is what stops the check
 *      agreeing with itself while the emit sites drift.
 *   2. **The envelope.** Six producers stamped `version` as the integer `1` where the contract
 *      types it `"major.minor"`, so `validateEnvelope` refused every event they ever relayed with
 *      "version: missing". Every suite in the estate was green throughout, because both sides
 *      tested against imagined counterparts. The only check that could have caught it is the one
 *      below: build an envelope with the relay's own `buildEnvelope` and hand it to the contract's
 *      own `classifyEnvelope`.
 *
 *   3. **The actor.** Added after `micro-contracts` `8889373` registered the two key topics and
 *      withdrew the shelter the other two defects had lived under. `actorOf` spelled an API-key
 *      caller `` `key:${display}` `` and the erasure path passed `'system:identity'`; neither is an
 *      `ActorKind` the contract admits, so both were refused whole. The check below drives the real
 *      emitters with every actor a real code path passes, rather than with one fixture.
 *
 * NOTE that the registry now names two `devplatform.*` topics — `devplatform.key.issued` and
 * `devplatform.key.revoked` — and the other three are still quarantined. So the envelope check
 * would pass vacuously for three of five if the quarantine excused everything. It does not:
 * `envelopeDefects excuses a lagging registry and nothing else` proves a real defect is still
 * reported on a quarantined topic.
 *
 * That distinction matters more here than anywhere, because being quarantined is exactly how the
 * integer version stayed invisible: `activity` shelves every unregistered topic WITHOUT validating
 * it, so nothing in the estate ever validated one of these envelopes. Whatever is still in the
 * quarantine is still unvalidated in production, and this suite is the only thing looking at it.
 *
 * No database. Pure text, set arithmetic and one function call, so it runs in CI even when the
 * database-backed suite skips.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  SIGNATURE_HEADER,
  TOPICS,
  TOPIC_NAMES,
  classifyEnvelope,
  isRegisteredTopic,
  parseActor,
  parseVersion,
  topicsProducedBy,
  verifyDelivery,
  type Actor,
} from '@cloudsforge/contracts-events'
import { buildEnvelope, signEvent, type Emit } from './outbox.ts'
import { emitKeyIssued, emitKeyRevoked } from './apikeys.ts'
import {
  AWAITING_REGISTRATION,
  EMITTED_TOPICS,
  SERVICE,
  adoptedProposals,
  envelopeDefects,
  malformedProposals,
  recipientOf,
  undeclaredTopics,
  unemittedOwnedTopics,
} from './topics.ts'

const SRC = dirname(fileURLToPath(import.meta.url))

function sourceFiles(): readonly string[] {
  return readdirSync(SRC)
    .filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts') && file !== 'testsupport.ts')
    .map((file) => join(SRC, file))
}

/**
 * The files a topic literal may legitimately appear in.
 *
 * `topics.ts` is excluded, and that exclusion is the whole check rather than a convenience: it is
 * the file holding `EMITTED_TOPICS` and the quarantine, and it is the thing being checked. Scanning
 * it would let a quarantine entry justify its own existence — a topic could be declared,
 * quarantined and never emitted, and every assertion below would still agree.
 */
function emitSourceFiles(): readonly string[] {
  return sourceFiles().filter((file) => !file.endsWith('/topics.ts'))
}

/**
 * Every topic literal in this service's namespace that appears anywhere in `src/`.
 *
 * Deliberately broader than `topic: '<name>'`, which is what identity's equivalent matches: a scan
 * tied to the emit-site shape misses a CONSTANT that no emit site uses, and that is a real defect
 * — `market.order.refunded` was declared, exported, emitted by nothing, and a name a consumer
 * could have subscribed to for ever.
 *
 * Comment lines are skipped, and that is load-bearing rather than tidy: `outbox.ts` carries a
 * worked `emit({ topic: 'market.listing.sold' … })` example in its header, and counting it would
 * report a topic no code path produces.
 *
 * `action:` and `scope:` lines are skipped for a sharper reason: the scope vocabulary shares this
 * namespace. A scope such as `devplatform.key.write` (`scopes.ts`) is three lowercase segments and
 * looks exactly like a topic, and nothing emits it.
 */
function topicsInSource(): readonly string[] {
  const found = new Set<string>()
  const literal = new RegExp(`'(${SERVICE}\\.[a-z0-9_]+\\.[a-z0-9_]+)'`, 'g')
  for (const file of emitSourceFiles()) {
    for (const line of readFileSync(file, 'utf8').split('\n')) {
      const trimmed = line.trimStart()
      if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue
      if (/\b(?:action|scope|resource|permission)\s*:/.test(line)) continue
      for (const match of line.matchAll(literal)) if (match[1]) found.add(match[1])
    }
  }
  return [...found].sort()
}

/* ------------------------------------------------------------------ the names */

test('the source emits exactly the topics this service declares', () => {
  // Both halves of the drift: a literal `src/` spells that EMITTED_TOPICS does not list, and an
  // entry in EMITTED_TOPICS that no literal backs. The second half is what stops the list being
  // repaired by editing the list.
  assert.deepEqual(
    topicsInSource(),
    [...EMITTED_TOPICS].sort(),
    'src/ and EMITTED_TOPICS disagree about what this service puts on the bus',
  )
})

test('every topic this service emits is one the estate has a name for', () => {
  assert.deepEqual(
    undeclaredTopics(topicsInSource()),
    [],
    'emitted, but in neither the registry nor AWAITING_REGISTRATION — decide which, then say so',
  )
})

test('every registry topic this service owns is actually emitted', () => {
  // The feature-that-can-never-fire direction, and the one that fails silently in production:
  // consumers classify the topic, the code path renders it, and nothing ever arrives.
  assert.deepEqual(
    unemittedOwnedTopics(topicsInSource()),
    [],
    'the registry says devplatform produces these and no emit site does — every consumer of each is dead code',
  )
  // And the registry is being read rather than the check passing vacuously.
  assert.ok(TOPIC_NAMES.length >= 40, 'the registry is being read rather than the check passing vacuously')
})

test('a pending proposal disappears once contracts adopts it', () => {
  // Without this the quarantine becomes a permanent allow-list: the topic gets registered, the
  // entry stays, and the next reader believes the topic is still unregistered.
  assert.deepEqual(
    adoptedProposals(),
    [],
    'the registry now names these — delete them from AWAITING_REGISTRATION',
  )
  // Every emitted topic is accounted for EXACTLY once — registered or quarantined, never both and
  // never neither. This replaces two counts (`topicsProducedBy(SERVICE).length === 0` and
  // `AWAITING_REGISTRATION.length === EMITTED_TOPICS.length`) that held only while the registry
  // owned no devplatform topic, and that a reader could have returned to green by adjusting a
  // number. A partition cannot be satisfied by editing one side of it.
  assert.deepEqual(
    [...topicsProducedBy(SERVICE), ...Object.keys(AWAITING_REGISTRATION)].sort(),
    [...EMITTED_TOPICS].sort(),
    'an emitted topic is registered or quarantined — this says it is neither, or counted twice',
  )
  // And the split, pinned, so moving a topic across the line is a deliberate edit here.
  // `devplatform.key.revoked` being on the registered side is the one that changes behaviour
  // rather than tidiness: `11-data-and-contract-strategy.md` names it as the mechanism by
  // which a revoked key stops working at every 30-second gateway cache in the estate, and until
  // 8889373 no consumer could classify it, so that propagation path did not exist.
  assert.deepEqual(topicsProducedBy(SERVICE), ['devplatform.key.issued', 'devplatform.key.revoked'])
  assert.deepEqual(Object.keys(AWAITING_REGISTRATION).sort(), [
    'devplatform.project.created',
    'devplatform.quota.exceeded',
    'devplatform.webhook_endpoint.created',
  ])
})

/**
 * The `custody` defect, asked from this side of the wire, for the two topics now registered.
 *
 * `keyedBy` is PROSE in the registry — a column name in a frozen object, not a type — so nothing
 * in the contract can force an emit site to pass what it names. Both of custody's ceremony topics
 * were registered `keyedBy: 'user_id'` while the emit sites passed the ADDRESS, and `activity`
 * reads the envelope key AS the subject id, so every export was filed against a user that does not
 * exist while every name check in the estate stayed green.
 *
 * `micro-contracts` checked this once, by reading these two emit sites while adopting the specs.
 * That is a check with no expiry date: it cannot notice the emit site changing afterwards. This is
 * the standing version.
 */
test('the key each registered topic is emitted with is the key the registry says it is', () => {
  assert.equal(TOPICS['devplatform.key.issued'].keyedBy, 'key_id')
  assert.equal(TOPICS['devplatform.key.revoked'].keyedBy, 'key_id')

  const apikeys = readFileSync(join(SRC, 'apikeys.ts'), 'utf8').split('\n')
  const emitters = apikeys
    .map((line, index) => ({ line, at: index }))
    .filter(({ line }) => /^export function emitKey(Issued|Revoked)\b/.test(line))
  assert.equal(emitters.length, 2, 'apikeys.ts should export exactly emitKeyIssued and emitKeyRevoked')

  for (const { line, at } of emitters) {
    // The `key:` line of the emit call, which is the ordering partition and the id every consumer
    // files the event against. `key.id` and nothing else — `key.lookupId` and `key.projectId` are
    // both in scope in these bodies and both are the substitution custody made.
    const body = apikeys.slice(at, at + 12)
    const keyLine = body.find((text) => /^\s*key: /.test(text))
    assert.ok(keyLine, `${line.trim()} has no key: line within its first 12 lines`)
    assert.match(
      keyLine,
      /^\s*key: key\.id,?\s*$/,
      `${line.trim()} passes something other than key.id, while the registry says key_id`,
    )
  }
})

/**
 * Every actor these emitters really pass, through the real emitter and the real relay.
 *
 * ## The two defects this exists because of
 *
 * `Actor` admits `user:`, `service:`, `operator:` and the BARE word `system`
 * (`contracts/packages/events/src/index.ts`). This service wrote two strings that are none of
 * those, for the whole life of the service:
 *
 *   - `server.ts`'s `actorOf` returned `` `key:${display}` `` for an API-key caller — one of the
 *     two principals the customer surface admits — so every event raised by a third-party
 *     integration carried `actor: unknown kind "key"` and was refused whole.
 *   - the organisation-erasure path passed `'system:identity'`, and `system` is the one kind that
 *     takes no subject, so every revocation it announced was refused with
 *     `actor: unknown kind "system"`.
 *
 * ## Why nothing caught them
 *
 * Two shelters, both now gone. `activity` quarantines an unregistered topic WITHOUT validating the
 * envelope, and no `devplatform.*` topic was registered until `8889373`. And this suite built its
 * envelope from ONE fixture row whose actor was a well-formed `user:…`, so the assertion that the
 * relay's envelope is acceptable was answered by the fixture rather than by the service.
 *
 * ## Why this is a test and not only a type
 *
 * `DomainEvent.actor` is now the contract's `Actor`, which makes both defects a `tsc` error, and
 * that is the stronger half. It is not the whole answer: `actor` reaches the wire from the
 * `outbox.actor` COLUMN, and a column read is `string | null` however carefully it was written.
 * This drives the real `emitKeyIssued`/`emitKeyRevoked`, takes the actor they really pass, sends it
 * through the column's type and out through `buildEnvelope`, and asks the contract's own
 * `classifyEnvelope`. Both `emitKeyRevoked` call sites appear here BY THEIR ACTOR, because a second
 * caller sharing one payload builder is exactly where a shape drifts unnoticed — and it is the
 * second caller that was broken.
 */
const KEY_FIXTURE = {
  id: '018f0000-0000-7000-8000-0000000000d1',
  projectId: '018f0000-0000-7000-8000-0000000000d2',
  environmentId: '018f0000-0000-7000-8000-0000000000d3',
  environment: 'live' as const,
  serviceAccountId: null,
  display: 'cfk_live_a1b2c3d4e5f6g7h8',
  lookupId: 'a1b2c3d4e5f6g7h8',
  name: 'ci',
  scopes: ['devplatform.key.read'],
  createdBy: 'user:018f0000-0000-7000-8000-0000000000c1',
  createdAt: new Date('2026-08-03T09:00:00.000Z'),
  lastUsedAt: null,
  expiresAt: null,
  revokedAt: new Date('2026-08-03T10:00:00.000Z'),
  revokedReason: 'leaked in a gist',
}

/** Every actor a real code path in this service passes, and the site that passes it. */
const REAL_ACTORS: readonly { readonly actor: Actor; readonly where: string }[] = [
  // `actorOf` for a UserPrincipal — server.ts.
  { actor: `user:${'018f0000-0000-7000-8000-0000000000c1'}`, where: 'actorOf, user caller' },
  // `actorOf` for a KeyPrincipal — server.ts. Was `key:${display}`, refused by every consumer.
  { actor: `service:${KEY_FIXTURE.display}`, where: 'actorOf, API-key caller' },
  // The erasure path — server.ts. Was `system:identity`, refused by every consumer.
  { actor: 'service:identity', where: 'identity.organisation.deleted handler' },
  // The relay's own fallback when a row has no actor at all — outbox.ts `buildEnvelope`.
  { actor: 'service:devplatform', where: 'buildEnvelope fallback' },
]

test('every actor this service really emits is one the contract accepts', () => {
  for (const { actor, where } of REAL_ACTORS) {
    const parsed = parseActor(actor)
    assert.equal(parsed.ok, true, `${where} passes an actor the contract refuses: ${actor}`)
  }
})

test('both emitKeyRevoked callers, and emitKeyIssued, build an envelope the contract accepts', () => {
  for (const { actor, where } of REAL_ACTORS) {
    const emitted: Parameters<Emit>[0][] = []
    const collect: Emit = (event) => void emitted.push(event)

    emitKeyIssued(collect, KEY_FIXTURE, actor)
    emitKeyRevoked(collect, KEY_FIXTURE, actor)
    assert.equal(emitted.length, 2, 'both emitters must produce exactly one event each')

    for (const event of emitted) {
      // The key is the aggregate the registry names, checked on the real emitted event rather than
      // on the source text — the other half of the custody check above.
      assert.equal(event.key, KEY_FIXTURE.id, `${event.topic} was keyed by something other than key.id`)
      assert.equal(isRegisteredTopic(event.topic), true, `${event.topic} is no longer registered`)

      // Through the COLUMN — `string | null`, which is what the database gives back — and out
      // through the one function that builds an envelope. `emitInTx` (server.ts) writes
      // `event.actor ?? null` into exactly this column.
      const envelope = buildEnvelope({
        ...ROW,
        topic: event.topic,
        key: event.key,
        actor: (event.actor ?? null) as string | null,
        payload: event.payload,
      })
      const verdict = classifyEnvelope(JSON.parse(JSON.stringify(envelope)))
      assert.deepEqual(
        verdict.defects,
        [],
        `${where}: an event on ${event.topic} would be refused by every consumer — ${verdict.defects.join('; ')}`,
      )
      assert.equal(verdict.unregisteredTopic, null)
      assert.equal(verdict.ok, true)
    }
  }
})

test('every pending proposal carries a spec that could be pasted into the registry', () => {
  assert.deepEqual(
    malformedProposals(),
    [],
    'a proposal needs a well-formed devplatform topic, a real ordering key, and a reason worth reading',
  )
})

/* ------------------------------------------------------------------ the envelope */

const ROW = {
  id: '018f0000-0000-7000-8000-0000000000a1',
  topic: 'devplatform.key.revoked',
  key: '018f0000-0000-7000-8000-0000000000b1',
  occurred_at: new Date('2026-08-03T10:00:00.000Z'),
  producer: SERVICE,
  version: 1,
  actor: 'user:018f0000-0000-7000-8000-0000000000c1',
  correlation_id: 'req-1',
  payload: { keyId: 'k-1' },
}

test('THE RULE: the envelope this relay builds is one the contract accepts', () => {
  // The check whose absence let six producers relay nothing but refusals. `validateEnvelope` is
  // the contract's own function and is literally what activity/src/ingest.ts and notify run on a
  // delivered body — not a restatement of it here.
  for (const topic of topicsInSource()) {
    const envelope = buildEnvelope({ ...ROW, topic })
    assert.deepEqual(
      envelopeDefects(JSON.parse(JSON.stringify(envelope))),
      [],
      `an event on ${topic} would be refused by every consumer in the estate`,
    )
  }
})

test('the version on the wire is "major.minor", never the stored integer', () => {
  const envelope = buildEnvelope(ROW)
  // The specific defect, named, so a reader of a failure knows what broke.
  assert.equal(typeof envelope.version, 'string')
  assert.equal(envelope.version, '1.0')
  assert.equal(parseVersion(envelope.version).ok, true)
  assert.equal(parseVersion(String(ROW.version)).ok, false, 'the stored integer is NOT a wire version')
})

test('a row with no actor and no correlation id still makes a readable envelope', () => {
  // Both columns are nullable and both are refused by the contract if they arrive null. The
  // fallbacks are the contract's own semantics: a service actor, and an event that is its own
  // correlation root.
  const envelope = buildEnvelope({ ...ROW, actor: null, correlation_id: null })
  assert.equal(envelope.actor, 'service:devplatform')
  assert.equal(envelope.correlationId, ROW.id)
  assert.deepEqual(envelopeDefects(JSON.parse(JSON.stringify(envelope))), [])
})

test('envelopeDefects excuses a lagging registry and nothing else', () => {
  // The tolerance is narrow on purpose. An unregistered topic this repository has explained is a
  // consumer being behind its producers; anything else is this service emitting the unreadable.
  const quarantined = buildEnvelope({ ...ROW, topic: 'devplatform.quota.exceeded' })
  assert.deepEqual(envelopeDefects(JSON.parse(JSON.stringify(quarantined))), [])

  // An unregistered topic the quarantine does NOT explain is not excused.
  const unexplained = { ...buildEnvelope(ROW), topic: 'devplatform.nothing.happened' }
  assert.ok(envelopeDefects(unexplained).length > 0)

  // And a real envelope defect is never excused, even on a quarantined topic.
  const broken = { ...quarantined, version: 1 as unknown as string }
  assert.ok(
    envelopeDefects(broken).some((error) => error.startsWith('version:')),
    'an integer version must be reported however the topic is registered',
  )
})

/**
 * The case that separates this repository's `envelopeDefects` from the contract's own
 * `envelopeDefects(value, awaitingRegistration)`, which ships beside `classifyEnvelope` and looks
 * like a drop-in for it.
 *
 * "Malformed" and "not in this registry" are two facts with two remedies — a producer bug, and a
 * missing registration — and an envelope can carry both. `classifyEnvelope` keeps both, deliberately
 * (`unregisteredTopic` survives on a `malformed` verdict). The contract's flattening wrapper drops
 * the topic whenever any other defect is present, so the author is sent to fix one thing twice.
 *
 * Every other assertion in this suite stays green under that wrapper. This is the only one that
 * would go red, which is the point of writing it.
 */
test('an unproposed topic AND a broken version are reported together, not one per round', () => {
  const both = {
    ...buildEnvelope(ROW),
    topic: 'devplatform.nothing.happened',
    version: 1 as unknown as string,
  }
  const defects = envelopeDefects(both)
  assert.ok(
    defects.some((error) => error.startsWith('version:')),
    `the producer bug must be named: ${defects.join('; ')}`,
  )
  assert.ok(
    defects.some((error) => error.includes('devplatform.nothing.happened')),
    `the missing registration must be named too: ${defects.join('; ')}`,
  )
})

test('the delivery this relay signs is one a contract-following consumer verifies', () => {
  // The half this service already had right, asserted so it cannot regress: four siblings carried
  // drifted local copies (`x-cloudsforge-signature`, `sha256=<hmac>`) and every delivery from them
  // was refused as "signature: missing". Having this right is what made the version defect harder
  // to see rather than easier.
  const body = JSON.stringify(buildEnvelope(ROW))
  const secret = 'K2sN4vQ8xR1wB6tY9zL3mF7hC5jD0pA4'
  assert.equal(SIGNATURE_HEADER, 'cf-signature')
  const verification = verifyDelivery(body, signEvent(body, secret), [secret])
  assert.equal(verification.ok, true)
})

/* ------------------------------------------------------------------ the person */

/**
 * **A REVOCATION MUST REACH A PERSON, AND EVERY CHECK ABOVE IS GREEN WHEN IT REACHES NOBODY.**
 *
 * `THE RULE` above asks whether the estate would ACCEPT this envelope. For the whole life of this
 * service the answer was yes and the answer was worthless: the organisation-erasure path revoked
 * every live key a company held, as `service:identity`, and the payload named no user — so
 * `activity` filed it internal as `api.key_revoked_by_platform` and `notify` answered
 * `no_recipient`, both correctly, and a developer's integrations died in silence.
 *
 * ## Why this is not a test that a field is present
 *
 * Because that test is weaker than it looks, and this estate has been caught by the difference
 * twice tonight. An end-to-end feed test stayed green with the consuming classifier DELIBERATELY
 * BROKEN, because the payload lacked the field and an absent field is null to every reader — so
 * "nobody was reached" was the expected answer either way. The cure is the order below: **feed the
 * reader YESTERDAY'S PAYLOAD SHAPE FIRST** and require it to reach nobody, then today's and require
 * it to reach the owner. The first assertion fails if `recipientOf` would answer for any reason
 * other than this field; the second fails if the field stops arriving. Neither can be satisfied by
 * an empty result.
 *
 * `withoutOwner` is not a hypothetical: it is exactly what `emitKeyRevoked` built until this
 * commit.
 */
function withoutOwner(payload: Record<string, unknown>): Record<string, unknown> {
  const copy = { ...payload }
  delete copy['userId']
  return copy
}

/** The one revocation event `emitKeyRevoked` produces for a key, through the real relay. */
function revocationEnvelope(key: typeof KEY_FIXTURE, actor: Actor): Record<string, unknown> {
  const emitted: Parameters<Emit>[0][] = []
  emitKeyRevoked((event) => void emitted.push(event), key, actor)
  const event = emitted[0]
  assert.equal(emitted.length, 1, 'emitKeyRevoked must produce exactly one event')
  assert.ok(event)
  const envelope = buildEnvelope({
    ...ROW,
    topic: event.topic,
    key: event.key,
    actor: (event.actor ?? null) as string | null,
    payload: event.payload,
  })
  return JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>
}

const OWNER = '018f0000-0000-7000-8000-0000000000c1'

test('A KEY THE PLATFORM REVOKES REACHES ITS OWNER, WHO IS NOT THE ACTOR', () => {
  // The erasure path — server.ts. `service:identity` is the honest actor and is not a person.
  const envelope = revocationEnvelope(KEY_FIXTURE, 'service:identity')

  // Yesterday, FIRST. A perfectly valid envelope that lands on nobody: the gap, reproduced.
  const yesterday = { ...envelope, payload: withoutOwner(envelope['payload'] as Record<string, unknown>) }
  assert.deepEqual(
    envelopeDefects(yesterday),
    [],
    'the envelope that reached nobody was VALID — which is why no check in this repository saw it',
  )
  assert.equal(
    recipientOf(yesterday),
    null,
    'yesterday\'s payload reached somebody, so the assertion below proves nothing about the new field',
  )

  // Today.
  assert.equal(
    recipientOf(envelope),
    OWNER,
    'a mass revocation still reaches nobody — the developer whose keys just died is not told',
  )

  // And the platform is STILL the platform. `activity` discriminates `api.key_revoked_by_platform`
  // from `api.key_revoked` on the actor alone (`activity/src/classify.ts`), so naming the
  // owner must not make an erasure read as something the owner did.
  assert.equal(envelope['actor'], 'service:identity')
  assert.deepEqual(envelopeDefects(envelope), [])
})

test('the owner is read from the key, not from whoever pressed delete', () => {
  // server.ts, where an ADMIN revokes a key a COLLEAGUE created. The actor is the admin; the
  // integration that stops belongs to the colleague, and it is the colleague who has to fix it.
  const admin = '018f0000-0000-7000-8000-0000000000c9'
  const envelope = revocationEnvelope(KEY_FIXTURE, `user:${admin}`)
  assert.equal(recipientOf(envelope), OWNER)
  assert.notEqual(recipientOf(envelope), admin)

  // Without the field this envelope resolved the ADMIN — a receipt for the one person who already
  // knew, and nothing for the one who did not.
  const yesterday = { ...envelope, payload: withoutOwner(envelope['payload'] as Record<string, unknown>) }
  assert.equal(recipientOf(yesterday), admin)
})

test('a key minted by a key names nobody, rather than guessing', () => {
  // `actorOf` for a KeyPrincipal is `service:<display>`, so `created_by` names no person. notify's
  // own rule is that this must stay silent: "a key minting a key is no person's news, and guessing
  // would tell the wrong person that their credentials changed" (notify/src/catalogue.ts).
  // Absent rather than null or empty — an absent field is the only one that does not claim to have
  // answered.
  const serviceOwned = { ...KEY_FIXTURE, createdBy: `service:${KEY_FIXTURE.display}` }
  const envelope = revocationEnvelope(serviceOwned, 'service:identity')
  assert.equal(recipientOf(envelope), null)
  assert.equal('userId' in (envelope['payload'] as Record<string, unknown>), false)
  assert.deepEqual(envelopeDefects(envelope), [])

  // A `created_by` that is not a well-formed subject at all — an older row, a hand-written fixture
  // — is refused for the same reason: `activity` files against `activity_records.user_id`, and a
  // non-uuid there is a record no feed query can ever return.
  for (const createdBy of ['user_test', 'user:', 'user:not-a-uuid', 'operator:ops']) {
    const odd = revocationEnvelope({ ...KEY_FIXTURE, createdBy }, 'service:identity')
    assert.equal((odd['payload'] as Record<string, unknown>)['userId'], undefined, createdBy)
    assert.equal(recipientOf(odd), null, createdBy)
  }
})

test('the recipient reader is the consumers\' order, and can answer null', () => {
  // The model is only worth anything if it can fail. Each branch, in the order notify's `userIdOf`
  // applies them (`notify/src/catalogue.ts`).
  const base = revocationEnvelope(KEY_FIXTURE, 'service:identity')
  assert.equal(recipientOf({ ...base, payload: {}, actor: 'service:identity' }), null)
  assert.equal(recipientOf({ ...base, payload: {}, actor: `user:${OWNER}` }), OWNER)
  // The payload wins over the actor when both name somebody, which is what makes the erasure path
  // and the colleague case above resolve the owner rather than the revoker.
  assert.equal(recipientOf({ ...base, actor: 'user:018f0000-0000-7000-8000-0000000000c9' }), OWNER)
  // Not an envelope at all, and an actor the contract refuses outright.
  assert.equal(recipientOf(null), null)
  assert.equal(recipientOf({ ...base, payload: {}, actor: 'system:identity' }), null)
  assert.equal(recipientOf({ ...base, payload: {}, actor: `key:${KEY_FIXTURE.display}` }), null)
})

/* ------------------------------------------------------------------ reachability */

/**
 * A guard that proves a topic name is correct proves nothing about whether the emit is reached.
 *
 * `identity/src/sessions.ts` exports `emitSessionRevoked` and NOTHING CALLS IT — `revokeSession`
 * and `revokeAllSessions` update rows without emitting — so `identity.session.revoked` is produced
 * by dead code while identity's own guard passes, because it scans literals rather than
 * reachability. This is the cheapest check that catches that exact shape.
 *
 * ## An import is not a call, and this used to think it was
 *
 * The scan below asks whether any line in `src/` mentions the symbol. An `import { emitFoo } from
 * './foo.ts'` line mentions it, so a symbol that was imported and then never called read as
 * reached. That is not hypothetical: deleting BOTH `emitKeyRevoked` call sites from `server.ts` and
 * leaving its import left this suite fully green, with `devplatform.key.revoked` — the topic
 * `11-data-and-contract-strategy.md` names as the estate's key-cache flush — produced by
 * nothing at all. The check could not fail in exactly the case it was written for, because the
 * import that survives a deleted call is the FIRST thing a reader would delete last.
 *
 * This is the same family as the defect it was written to catch: a scan that counts a MENTION as a
 * USE. So imports and re-exports are stripped before the reference scan. Blank lines are left in
 * their place, so line numbers in the declaration scan still name the real line.
 *
 * The detector is exercised on fixtures FIRST, including that exact case. A repository with no
 * exported emitter would otherwise get a green from a scan that finds nothing because it is broken,
 * which is precisely the "check that cannot fail" this estate keeps rediscovering — and it is not
 * hypothetical here either: `micro-trade` carries this identical detector and declares no
 * exported emitter at all, so there the fixtures are the ONLY thing exercising it.
 */
function withoutImports(text: string): string {
  const kept: string[] = []
  let inDeclaration = false
  for (const line of text.split('\n')) {
    const trimmed = line.trimStart()
    // `export { x } from './y.ts'` re-exports a symbol without using it, exactly as an import does.
    const opens = !inDeclaration && /^(?:import\b|export\s*\{[^}]*$|export\s*\{[^}]*\}\s*from\b)/.test(trimmed)
    if (opens) {
      // A bare `import './x.ts'` and a one-line `import { a } from './x.ts'` both close at once; a
      // braced list spread over several lines closes at the `from '…'`.
      inDeclaration = !/\bfrom\s+['"]/.test(line) && !/^import\s+['"]/.test(trimmed)
      kept.push('')
      continue
    }
    if (inDeclaration) {
      if (/\bfrom\s+['"]/.test(line)) inDeclaration = false
      kept.push('')
      continue
    }
    kept.push(line)
  }
  return kept.join('\n')
}

function unreachedEmitters(files: readonly { name: string; text: string }[]): readonly string[] {
  const declared: { symbol: string; where: string }[] = []
  for (const file of files) {
    file.text.split('\n').forEach((line, index) => {
      const match = /^export (?:async )?function (emit[A-Za-z0-9_]*)/.exec(line)
      if (match?.[1]) declared.push({ symbol: match[1], where: `${file.name}:${index + 1}` })
    })
  }
  const bodies = files.map((file) => ({ name: file.name, text: withoutImports(file.text) }))
  return declared
    .filter(({ symbol }) => {
      const reference = new RegExp(`\\b${symbol}\\b`)
      for (const file of bodies) {
        for (const line of file.text.split('\n')) {
          const trimmed = line.trimStart()
          if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('/*')) continue
          if (/^export (?:async )?function /.test(trimmed)) continue
          if (reference.test(line)) return false
        }
      }
      return true
    })
    .map(({ symbol, where }) => `${symbol} (${where})`)
    .sort()
}

test('the unreachable-emitter detector can actually fail', () => {
  // identity's defect, reproduced in miniature. Without this the assertion below is worth nothing
  // in a repository whose emit sites are all inline.
  const dead = [{ name: 'sessions.ts', text: 'export function emitSessionRevoked(): void {}\n' }]
  assert.deepEqual(unreachedEmitters(dead), ['emitSessionRevoked (sessions.ts:1)'])

  const alive = [
    { name: 'sessions.ts', text: 'export function emitSessionRevoked(): void {}\n' },
    { name: 'server.ts', text: 'emitSessionRevoked()\n' },
  ]
  assert.deepEqual(unreachedEmitters(alive), [])
})

/**
 * The case the detector used to get wrong, and the reason it is worth having at all.
 *
 * A dead emitter is almost never dead by having its import removed too — a call is deleted or
 * refactored away and the import is what lingers. Counting that import as a reference made this
 * check green in precisely the situation it exists for.
 */
test('an emitter that is imported but never called is NOT reached', () => {
  const importedOnly = [
    { name: 'apikeys.ts', text: 'export function emitKeyRevoked(): void {}\n' },
    {
      name: 'server.ts',
      text: "import { emitKeyRevoked, revokeApiKey } from './apikeys.ts'\nrevokeApiKey()\n",
    },
  ]
  assert.deepEqual(unreachedEmitters(importedOnly), ['emitKeyRevoked (apikeys.ts:1)'])

  // The multi-line form, which is how every import in this service is actually written.
  const multiline = [
    { name: 'apikeys.ts', text: 'export function emitKeyRevoked(): void {}\n' },
    {
      name: 'server.ts',
      text: "import {\n  emitKeyRevoked,\n  revokeApiKey,\n} from './apikeys.ts'\nrevokeApiKey()\n",
    },
  ]
  assert.deepEqual(unreachedEmitters(multiline), ['emitKeyRevoked (apikeys.ts:1)'])

  // A re-export is not a use either.
  const reExported = [
    { name: 'apikeys.ts', text: 'export function emitKeyRevoked(): void {}\n' },
    { name: 'index.ts', text: "export { emitKeyRevoked } from './apikeys.ts'\n" },
  ]
  assert.deepEqual(unreachedEmitters(reExported), ['emitKeyRevoked (apikeys.ts:1)'])

  // And stripping imports must not blind it to the call that FOLLOWS one.
  const importedAndCalled = [
    { name: 'apikeys.ts', text: 'export function emitKeyRevoked(): void {}\n' },
    {
      name: 'server.ts',
      text: "import {\n  emitKeyRevoked,\n} from './apikeys.ts'\nemitKeyRevoked()\n",
    },
  ]
  assert.deepEqual(unreachedEmitters(importedAndCalled), [])
})

test('every exported emitter is reached from somewhere', () => {
  assert.deepEqual(
    unreachedEmitters(sourceFiles().map((name) => ({ name, text: readFileSync(name, 'utf8') }))),
    [],
    'exported, emits an event, and no code path reaches it — the topic is produced by dead code',
  )
})
