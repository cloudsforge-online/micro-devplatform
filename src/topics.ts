/**
 * The producer half of the bus contract: what this service puts on the wire, and whether the
 * estate can read it.
 *
 * ## The defect this file exists to close
 *
 * Every consumer in the estate is pinned to `@cloudsforge/contracts-events`. `activity` declares
 * its classifier table `satisfies Readonly<Record<TopicName, _>>`; `notify` asserts it has a rule
 * for every registry topic. **The producer was pinned to nothing at all** — not to the topic names
 * and, worse, not to the shape of the envelope it wrote them into.
 *
 * Two instances of that one class have already cost the estate every event it ever relayed:
 *
 *   - **A version stamped wrong.** `EventEnvelope.version` is `` `${number}.${number}` `` in the
 *     contract — a "major.minor" STRING. Six producers typed it `number` end to end and sent `1`,
 *     and `validateEnvelope` refuses that with "version: missing". The signature verified, the
 *     delivery arrived, and the consumer threw it away at the envelope before anything looked at
 *     a payload. Each service's own suite stayed green throughout, because each tested against
 *     its own fake of the other side.
 *   - **A topic renamed on the wire.** `wallet` emitted `wallet.deposit.credited` while the
 *     registry, `notify` and `activity` all spell it `wallet.deposit.confirmed`. Nothing could
 *     ever match it.
 *
 * These are the same defect wearing two hats: **the producer is free and the consumer is pinned.**
 * So this file pins the producer, in both directions and two ways:
 *
 *   1. **At compile time.** `EventEnvelope.version` in `outbox.ts` is the contract's
 *      `EventVersion`, imported rather than restated. Assigning the stored integer to it is a type
 *      error, which is `pnpm typecheck`, which is the build.
 *   2. **At test time, against the source rather than against this list.** `topics.test.ts` reads
 *      every topic literal out of `src/` and reconciles that set with the registry, and it builds
 *      a real envelope through the relay's own `buildEnvelope` and hands it to the contract's own
 *      `classifyEnvelope`.
 *
 * ## Two of the five are now registered, and they are the two that were load-bearing
 *
 * `devplatform` IS a valid `ProducerService` in the contract's union and, as of `micro-contracts`
 * `8889373`, owns two topics in `TOPICS`: **`devplatform.key.issued`** and
 * **`devplatform.key.revoked`**, adopted verbatim from the entries that used to sit below. The
 * other three are still quarantined, each carrying the exact `TopicSpec` `micro-contracts` should
 * paste.
 *
 * `devplatform.key.revoked` is the one that was never merely tidiness.
 * `11-data-and-contract-strategy.md` says key validation is cached 30 s by the gateway and
 * that "revocation propagates via `devplatform.key.revoked`" — so that topic IS the mechanism by
 * which a revoked API key stops working everywhere rather than only here. While no registry named
 * it, no consumer could classify it, so the documented propagation path did not exist: revocation
 * was immediate in THIS service and immediate nowhere else. Registration is what builds it.
 *
 * ## What registration took away, and what it then found
 *
 * `activity`'s ingest takes its unregistered-topic branch for a topic it cannot classify and
 * quarantines **without validating the envelope**. Every `devplatform.*` topic was unregistered, so
 * for the whole life of this service an envelope defect here cost nothing — the events were shelved
 * for being unnameable long before anything looked at their contents. That is what hid the integer
 * `version`, and it is what hid the two `actor` defects found the day it was withdrawn:
 *
 *   - `server.ts`'s `actorOf` spelled an API-key caller `` `key:${display}` ``. `key` is not an
 *     `ActorKind` — the contract admits `user`, `service`, `operator` and the bare word `system`
 *     (`parseActor`, `contracts/packages/events/src/index.ts`) — so every event raised by a
 *     third-party integration was refused whole with `actor: unknown kind "key"`. A `KeyPrincipal`
 *     is not a corner case: it is one of the two principals the customer surface admits.
 *   - the `identity.organisation.deleted` handler passed `'system:identity'`. `system` is the one
 *     kind that takes NO subject, so every revocation that path announced — the mass revocation
 *     that follows an organisation being erased, which is precisely when a cache flush matters most
 *     — was refused with `actor: unknown kind "system"`.
 *
 * Both are repaired, and repaired the way `version` was rather than by correcting two strings:
 * `DomainEvent.actor` is now the contract's `Actor`, imported rather than restated, so each is a
 * `tsc --noEmit` error and neither can be written again. `topics.test.ts` carries the runtime half,
 * because `actor` reaches the wire from a COLUMN and a column read is `string | null` however
 * carefully it was written.
 */

import {
  TOPICS as REGISTRY,
  classifyEnvelope,
  isRegisteredTopic,
  isValidTopicName,
  parseActor,
  topicsProducedBy,
  type TopicName,
  type TopicSpec,
} from '@cloudsforge/contracts-events'
import { TOPICS } from './outbox.ts'

/** This service's own name, and the namespace it is the only permitted producer under. */
export const SERVICE = 'devplatform'

/**
 * Every topic this service emits.
 *
 * Taken from `outbox.ts` rather than retyped, so this list cannot name a topic whose spelling has
 * since changed under it. `topics.test.ts` additionally reads the literals back out of `src/`, so
 * `outbox.ts` cannot name one that no emit site produces either.
 */
export const EMITTED_TOPICS: readonly string[] = Object.freeze(Object.values(TOPICS))

export interface ProposedTopic {
  /** Why the fact belongs on the bus at all. Read by a human reviewing the contracts change. */
  readonly reason: string
  /** The entry to add to `TOPICS` in `@cloudsforge/contracts-events`, verbatim. */
  readonly spec: TopicSpec
}

/**
 * Topics this service emits that the shared registry does not yet name.
 *
 * A quarantine, not an exemption, with the three properties that keep identity's honest:
 *
 *   - An entry carries the exact `TopicSpec` it is asking for, so adopting it into
 *     `contracts/packages/events/src/index.ts` is a copy rather than a fresh design.
 *   - `topics.test.ts` asserts every entry is **genuinely absent** from the registry. The moment
 *     contracts registers one, this file fails until the entry is deleted — so the quarantine
 *     empties itself rather than rotting into a permanent allow-list.
 *   - An emit site whose topic is in neither the registry nor here fails the test.
 *
 * `keyedBy` on each is read off the emit site, never chosen here: the key is the ordering
 * partition, so it is contract rather than a producer's private preference.
 */
export const AWAITING_REGISTRATION: Readonly<Record<string, ProposedTopic>> = Object.freeze({
  // `devplatform.key.revoked` and `devplatform.key.issued` were here until contracts-events
  // registered them (micro-contracts 8889373, adopted verbatim: `keyedBy: 'key_id'` on both).
  // Deleted rather than annotated, because `adoptedProposals()` fails while an adopted entry is
  // present and that failure IS the self-emptying quarantine.
  //
  // Registering `key.revoked` is what finally builds the propagation path
  // `11-data-and-contract-strategy.md` describes — a revoked key ceasing to work at every
  // 30-second gateway cache rather than only inside this service. It also removed this service's
  // last hiding place: `activity` quarantined every unregistered `devplatform.*` topic WITHOUT
  // validating the envelope, so an envelope defect on these two cost nothing. It costs everything
  // now. That is how the two `actor` defects below were found, on the day the shelter was removed:
  //
  //   - `server.ts` spelled an API-key caller `key:<display>`, and `key` is not an `ActorKind`.
  //   - `server.ts` spelled the erasure path `system:identity`, and `system` is the one
  //     kind that takes NO subject (`parseActor`, contracts index.ts).
  //
  // Both are fixed, and `DomainEvent.actor` is now the contract's `Actor` type so neither spelling
  // can be written again — the same trick `version` already used. See `outbox.ts`.
  'devplatform.project.created': {
    reason:
      'A project is the unit everything else in this service hangs off. billing and analytics both have a reason to hear it and neither can today.',
    spec: {
      producer: 'devplatform',
      payloadType: 'ProjectCreated',
      version: '1.0',
      keyedBy: 'project_id',
      description: 'A developer project was created under an organisation.',
    },
  },
  'devplatform.webhook_endpoint.created': {
    reason:
      'An endpoint registered to receive somebody else\'s events is a security-relevant fact, and the only record of it today is a row in this database.',
    spec: {
      producer: 'devplatform',
      payloadType: 'WebhookEndpointCreated',
      version: '1.0',
      keyedBy: 'endpoint_id',
      description: 'A webhook endpoint was registered, with the topics it subscribes to.',
    },
  },
  'devplatform.quota.exceeded': {
    reason:
      'A developer whose integration just started failing needs to know it was a quota rather than a bug, and notify is the only thing that can tell them before they open a ticket.',
    spec: {
      producer: 'devplatform',
      payloadType: 'QuotaExceeded',
      version: '1.0',
      keyedBy: 'quota_id',
      description: 'A project exceeded a quota window, with the limit and the window.',
    },
  },
})

/* ------------------------------------------------------------------ reconciliation */

/** Topics this service emits that no registry names and no proposal explains — always a defect. */
export function undeclaredTopics(emitted: readonly string[]): readonly string[] {
  return emitted
    .filter((topic) => !isRegisteredTopic(topic) && !Object.hasOwn(AWAITING_REGISTRATION, topic))
    .sort()
}

/**
 * Registry topics this service owns and never emits — a feature that can never fire.
 *
 * The direction that is easiest to miss, because nothing breaks and nothing logs: consumers
 * classify the topic, the code path renders it, and nothing ever arrives. It used to be empty
 * vacuously — the registry owned no devplatform topic, so there was nothing for it to find. Since
 * `8889373` it is a real check with two topics to answer for: delete or rename either `apikeys.ts`
 * emitter and this returns it, naming a consumer that would wait for ever. For
 * `devplatform.key.revoked` that consumer is every key cache in the estate.
 */
export function unemittedOwnedTopics(emitted: readonly string[]): readonly TopicName[] {
  const seen = new Set(emitted)
  return topicsProducedBy(SERVICE).filter((topic) => !seen.has(topic))
}

/** Proposals the registry has since adopted. Non-empty means delete the entry from the quarantine. */
export function adoptedProposals(): readonly string[] {
  return Object.keys(AWAITING_REGISTRATION).filter(isRegisteredTopic).sort()
}

/** A proposal that could not be pasted into the registry as it stands. */
export function malformedProposals(): readonly string[] {
  return Object.entries(AWAITING_REGISTRATION)
    .filter(([topic, proposal]) => {
      if (!isValidTopicName(topic) || !topic.startsWith(`${SERVICE}.`)) return true
      if (proposal.spec.producer !== SERVICE) return true
      if (proposal.spec.keyedBy.trim() === '') return true
      if (proposal.reason.trim().length < 20) return true
      return false
    })
    .map(([topic]) => topic)
    .sort()
}

/* ------------------------------------------------------------------ the envelope */

/**
 * Every reason a contract-following consumer would refuse this envelope.
 *
 * The check itself is `classifyEnvelope`, and it is the contract's — the exact check `activity` and
 * `notify` run on a delivered body. Running it here, on an envelope this service's relay actually
 * built, is the only way a producer finds out it is unreadable without waiting for two services to
 * be composed, which is how this was found the first time, months late.
 *
 * ## Why this is now four lines and not sixteen
 *
 * It used to make the "malformed" / "not in this registry" distinction itself, by comparing against
 * the contract's exact error SENTENCE:
 *
 *     const excused = `topic: "${topic}" is not in this registry; contracts-events may be behind`
 *     return verdict.errors.filter((error) => error !== excused)
 *
 * `market`, `trade` and `community` each carried that byte for byte. **A prose message is not
 * an interface.** Reword it in `contracts-events` by one character and all four copies silently
 * stop excusing anything: every quarantined topic starts reading as a producer bug and four suites
 * go red for a reason unrelated to what they test. Nothing here tied the literal to its source.
 * `classifyEnvelope` carries the distinction as STRUCTURE — `unregisteredTopic` is a field, not a
 * sentence — so there is no longer a string that can drift.
 *
 * ## What this file still decides, and the contract cannot
 *
 * **Which** unregistered topics are excused: the ones `AWAITING_REGISTRATION` above proposes. A
 * consumer lagging its producers is normal when twenty-two services deploy independently, and
 * `activity` quarantines rather than drops. Everything else the contract found is returned — a
 * version in the wrong shape, a missing correlation id, an id that is not a UUID, a producer that
 * does not own its topic — because each of those is this service emitting the unreadable.
 *
 * ## Why not the contract's own `envelopeDefects(value, awaitingRegistration)`
 *
 * It ships beside `classifyEnvelope` and looks like a drop-in for this function. It is not, and the
 * difference is the one this whole exercise is about. It flattens the verdict back to `string[]`,
 * and in flattening it **drops `unregisteredTopic` whenever any other defect is present** — so an
 * envelope on a topic nobody proposed that is ALSO malformed reports only the malformation, the
 * author fixes it, re-runs, and only then learns about the topic. That contradicts the wrapper's
 * own package documentation ("an envelope can be both, and `malformed` still reports
 * `unregisteredTopic`, so a producer fixing it needs one round rather than two") and it is exactly
 * the collapse of two facts into one that let eleven `notify` rules name topics no producer emits.
 * `classifyEnvelope` itself is right; only the convenience wrapper loses the fact. So this reads the
 * structured verdict and keeps both. Reported to `micro-contracts`; the test named "an unproposed
 * topic AND a broken version are reported together" is what stops a future tidy-up from adopting
 * the wrapper and losing a fact while every other assertion here stays green.
 */
export function envelopeDefects(envelope: unknown): readonly string[] {
  const verdict = classifyEnvelope(envelope)
  // Reported FIRST, where `validateEnvelope` has always put it, so a reader of a failure sees the
  // registry question before the envelope's own faults.
  const unexplained =
    verdict.unregisteredTopic !== null &&
    !Object.hasOwn(AWAITING_REGISTRATION, verdict.unregisteredTopic)
      ? [`topic: "${verdict.unregisteredTopic}" is not in the registry, and AWAITING_REGISTRATION does not propose it`]
      : []
  return [...unexplained, ...verdict.defects]
}

/* ------------------------------------------------------------------ the person */

const UUID_SUBJECT = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

/**
 * **Which PERSON a delivered envelope reaches — the consumers' own rule, transcribed.**
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * A valid envelope is not a delivered one. `envelopeDefects` above answers "would a consumer refuse
 * this?", and every check in this repository stopped there — which is exactly far enough to miss
 * the defect this function exists for. `devplatform.key.revoked` passed every envelope check ever
 * written here while the organisation-erasure path reached NOBODY: the actor was `service:identity`,
 * the payload named no user, so both consumers resolved no recipient and were right to. A test
 * asserting "the envelope is acceptable" is green throughout that. So is a test asserting a field
 * is PRESENT. Only a test that asks who the event lands on can fail.
 *
 * ## Whose rule this is, line by line
 *
 * The order is `notify`'s `userIdOf` (`notify/src/catalogue.ts`), which every rule built
 * with `forUser` uses, and which `activity` matches with `userFromPayload` then `userFromActor`
 * (`activity/src/classify.ts` and):
 *
 *   1. the payload's `user_id` / `userId`;
 *   2. the envelope key, for a topic the registry says is `keyedBy: 'user_id'` — neither of this
 *      service's registered topics is, both are `key_id`, and the branch is kept anyway because
 *      dropping a step of somebody else's rule is how a transcription stops being one;
 *   3. an `actor` of `user:<id>`, last, because the actor is who ACTED and the record belongs to
 *      whose news it is. Those coincide often and diverge where it costs most.
 *
 * ## Two deliberate strictnesses, and why they are the safe direction
 *
 * `parseActor` rather than `actor.startsWith('user:')` — `activity` uses the contract's parser and
 * says why: this service shipped `key:<display>` and `system:identity`, and a local prefix test
 * reads both as "not a user" for the right answer by luck rather than refusing them as illegal.
 * And the subject must be a UUID, which `activity` requires and `notify` does not. Both make this
 * the STRICTER of the two consumers, so a user it resolves is a user BOTH of them reach. A model
 * that is easier to satisfy than the real reader is a model that passes for envelopes the estate
 * drops, which is the class of self-agreeing fake this whole file exists to stop.
 *
 * It is a transcription, so it can drift from the services it copies. What stops that mattering is
 * that it is only ever used to prove reachability is NON-empty, on envelopes this service's own
 * relay built — the direction where being wrong means a red build here, not a silent gap there.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export function recipientOf(envelope: unknown): string | null {
  if (typeof envelope !== 'object' || envelope === null) return null
  const record = envelope as Record<string, unknown>
  const payload =
    typeof record['payload'] === 'object' && record['payload'] !== null
      ? (record['payload'] as Record<string, unknown>)
      : {}

  for (const field of ['user_id', 'userId']) {
    const value = payload[field]
    if (typeof value === 'string' && UUID_SUBJECT.test(value)) return value
  }

  const topic = record['topic']
  const spec = typeof topic === 'string' && isRegisteredTopic(topic) ? REGISTRY[topic] : undefined
  const key = record['key']
  if (spec?.keyedBy === 'user_id' && typeof key === 'string' && UUID_SUBJECT.test(key)) return key

  const actor = record['actor']
  if (typeof actor !== 'string') return null
  const parsed = parseActor(actor)
  if (!parsed.ok || parsed.value.kind !== 'user') return null
  const id = parsed.value.id
  return id !== null && UUID_SUBJECT.test(id) ? id : null
}

