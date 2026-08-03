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
 *      `validateEnvelope`.
 *
 * ## Nothing this service emits is registered, and one of the five is load-bearing
 *
 * `devplatform` IS a valid `ProducerService` in the contract's union and owns **zero** topics in
 * `TOPICS`. All five below therefore sit in the quarantine, each carrying the exact `TopicSpec`
 * `micro-contracts` should paste.
 *
 * `devplatform.key.revoked` is the one that is not merely tidiness.
 * `11-data-and-contract-strategy.md:363` says key validation is cached 30 s by the gateway and
 * that "revocation propagates via `devplatform.key.revoked`" — so that topic IS the mechanism by
 * which a revoked API key stops working everywhere rather than only here. A topic no registry
 * names is a topic no consumer can classify, which means the documented propagation path does not
 * exist. Revocation is still immediate in THIS service; it is immediate nowhere else.
 *
 * Note also what saved this repository from the version defect and will stop saving it:
 * `activity`'s ingest takes its unregistered-topic branch for every `devplatform.*` event and
 * quarantines rather than validating, so the integer version was never the thing that refused
 * them. Register `devplatform.key.revoked` without fixing the envelope and every delivery starts
 * being refused instead. Both halves landed together.
 */

import {
  isRegisteredTopic,
  isValidTopicName,
  topicsProducedBy,
  validateEnvelope,
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
  'devplatform.key.revoked': {
    reason:
      '11-data-and-contract-strategy.md:363 names THIS TOPIC as the mechanism by which a revoked API key stops working at every 30-second gateway cache in the estate. Unregistered, no consumer can classify it, so the documented propagation path does not exist and revocation is immediate only inside this service.',
    spec: {
      producer: 'devplatform',
      payloadType: 'ApiKeyRevoked',
      version: '1.0',
      keyedBy: 'key_id',
      description:
        'An API key was revoked. Every cache holding a verification result for it must drop it.',
    },
  },
  'devplatform.key.issued': {
    reason:
      "The other half of revoked, and a key issued by somebody other than its owner is the first thing a compromise looks like. Nothing can tell the owner today.",
    spec: {
      producer: 'devplatform',
      payloadType: 'ApiKeyIssued',
      version: '1.0',
      keyedBy: 'key_id',
      description: 'An API key was issued for a project, with its scopes and prefix.',
    },
  },
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
 * classify the topic, the code path renders it, and nothing ever arrives. Empty today only
 * because the registry owns no devplatform topic at all, which is the gap the quarantine
 * describes.
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
 * `validateEnvelope` is the contract's own function and is the exact check that `activity` and
 * `notify` run on a delivered body. Running it here, on an envelope this service's relay actually
 * built, is the only way a producer finds out it is unreadable without waiting for two services to
 * be composed — which is how this was found the first time, months late.
 *
 * **One error is tolerated and only one:** "not in this registry", and only for a topic the
 * quarantine above explains. That is a consumer being behind its producers, which is a normal
 * consequence of deploying twenty-two services independently and which `activity` handles by
 * quarantining rather than dropping. Every other error — a version in the wrong shape, a missing
 * correlation id, an id that is not a UUID, a producer that does not own its topic — is this
 * service emitting something nobody can read, and is returned.
 */
export function envelopeDefects(envelope: unknown): readonly string[] {
  const verdict = validateEnvelope(envelope)
  if (verdict.ok) return []
  const topic =
    typeof envelope === 'object' && envelope !== null
      ? (envelope as Record<string, unknown>)['topic']
      : undefined
  const excused =
    typeof topic === 'string' && Object.hasOwn(AWAITING_REGISTRATION, topic)
      ? `topic: "${topic}" is not in this registry; contracts-events may be behind`
      : null
  return verdict.errors.filter((error) => error !== excused)
}
