/**
 * Outbox, relay and inbox — the internal event path.
 *
 * Rule 5 of docs/ecosystem/03 §2: every state change others care about writes an outbox row **in
 * the same transaction as the change**. A publish after commit is a publish that is skipped when
 * the process dies in between; a publish before commit is a publish of something that never
 * happened. Both are silent and both are unrecoverable after the fact.
 *
 * No broker. Postgres already has transactions and `SKIP LOCKED` — AD-10 records the four measured
 * conditions under which that stops being true, and none of them holds here.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE EVENT THAT MATTERS: A REVOKED KEY.**
 *
 * `11-data-and-contract-strategy.md` says key validation is "cached 30 s" by the gateway and
 * that "revocation propagates via `devplatform.key.revoked`". So the outbox row written in the
 * same transaction as the revocation is the mechanism by which a revoked key actually stops
 * working at every cache in the estate. Revocation is immediate in *this* service — the row is
 * updated and the next verification here refuses — and the event is what makes it immediate
 * everywhere else.
 *
 * **THAT MECHANISM NOW EXISTS. IT DID NOT BEFORE.** `devplatform.key.revoked` was not a registered
 * topic for the whole life of this service: `contracts/packages/events/src/index.ts` freezes
 * `TOPICS` and `TopicName = keyof typeof TOPICS` closes the set, and `devplatform` was a legal
 * `ProducerService` with no topic of its own in it. So the mechanism 11:363 names by string could
 * not be constructed through `makeEvent`, which takes a `TopicName`, and no consumer could classify
 * what this service emitted. Revocation was immediate here and immediate nowhere else.
 *
 * `micro-contracts` `8889373` adopted `devplatform.key.issued` and `devplatform.key.revoked`
 * verbatim from the quarantine in `topics.ts`, which is that quarantine doing what it was built to
 * do — the entries were deleted the same day, because the test there fails while an adopted entry
 * remains. The three topics below that are still unregistered stay local constants, validated with
 * `isValidTopicName` (the shape check, which they pass) rather than `isRegisteredTopic` (which they
 * cannot pass yet), and `topics.ts` still carries the spec each is asking for.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ## The envelope was unreadable, and the signature being right hid it
 *
 * This file already signs with the contract (`signDelivery`, `cf-signature`), which is more than
 * four siblings could say. It made the remaining defect harder to see rather than easier: the
 * relay copied the STORED INTEGER version onto the wire, where the contract types
 * `EventEnvelope.version` as `` `${number}.${number}` `` and `validateEnvelope` answers
 * "version: missing". A delivery whose signature verified perfectly was thrown away at the
 * envelope before anything looked at a payload.
 *
 * That never cost this service an event, and only by an accident worth naming: no `devplatform.*`
 * topic was registered, so `activity`'s ingest took the unregistered-topic branch and quarantined
 * WITHOUT validating. `micro-contracts` `8889373` registered the two key topics, so that shelter is
 * gone and every delivery on them is validated on arrival. The version was repaired before that
 * happened, which is the only reason this reads as history.
 *
 * `actor` and `correlation_id` are the same defect wearing a third and fourth hat: both columns are
 * nullable, both went straight onto the wire, and the contract refuses either as null. See
 * `buildEnvelope`.
 *
 * And `actor` had a second fault of its own that the same shelter hid, found the day it was
 * withdrawn: the value was well-formed but its KIND was not one the contract admits — `actorOf`
 * spelled an API-key caller `key:<display>`, and the organisation-erasure path passed
 * `system:identity` where `system` is the one kind that takes no subject. `DomainEvent.actor` is
 * now the contract's `Actor` rather than `string`, so both are a compile error. That is the same
 * repair `version` got, applied to the field that had quietly acquired the identical defect, and it
 * is why this file imports two contract types rather than one.
 */

import {
  isValidTopicName,
  serviceActor,
  signDelivery,
  verifyDelivery,
  SIGNATURE_HEADER,
  type Actor,
  type EventVersion,
} from '@cloudsforge/contracts-events'
import type { Sql, TransactionSql } from 'postgres'
import { HttpClient } from '@cloudsforge/http'
import type { Logger } from '@cloudsforge/telemetry'
import type { Handler } from '@cloudsforge/jobs'

export type Db = Sql
export type Tx = TransactionSql

export { SIGNATURE_HEADER }

/**
 * The topics this service produces.
 *
 * Local constants because the contract package that should own them has not been cut — see the
 * file header. Every one is checked against `isValidTopicName` at module load, so a typo is a
 * boot failure rather than an event nobody subscribes to.
 */
export const TOPICS = Object.freeze({
  keyIssued: 'devplatform.key.issued',
  keyRevoked: 'devplatform.key.revoked',
  projectCreated: 'devplatform.project.created',
  webhookEndpointCreated: 'devplatform.webhook_endpoint.created',
  quotaExceeded: 'devplatform.quota.exceeded',
} as const)

for (const topic of Object.values(TOPICS)) {
  if (!isValidTopicName(topic)) {
    throw new Error(`'${topic}' is not a well-formed topic name`)
  }
}

/** What a caller emits. The envelope's `id`, `occurredAt` and `producer` are added here. */
export interface DomainEvent {
  readonly topic: string
  /** Ordering is per `(topic, key)` only. Choose the aggregate id, never a timestamp. */
  readonly key: string
  readonly payload: Record<string, unknown>
  /**
   * The contract's `Actor`, imported rather than restated — the same repair `version` already had,
   * applied to the field that had quietly acquired the identical defect.
   *
   * This was `string`, and a `string` is what let two unspellable actors reach the wire and stay
   * there. `server.ts` returned `` `key:${display}` `` for an API-key caller, and
   * `server.ts` passed `'system:identity'` from the organisation-erasure path. The contract
   * admits `user`, `service`, `operator` and the BARE word `system` and nothing else
   * (`parseActor`, `contracts/packages/events/src/index.ts`), so both were refused on arrival
   * with `actor: unknown kind …` — the whole envelope discarded before any consumer read a
   * payload, which is precisely how the integer `version` cost six producers every event they ever
   * relayed.
   *
   * Typed, both are a `tsc --noEmit` error rather than a runtime refusal a consumer absorbs
   * silently: `` `key:${string}` `` matches no member of the union, and `'system:identity'` is not
   * the string literal `'system'`. That is `pnpm typecheck`, which is the build, which is CI. A
   * runtime guard alone could not have done this — `topics.test.ts` built its envelope from one
   * fixture row whose actor was a well-formed `user:…`, so it was green throughout.
   */
  readonly actor?: Actor
  readonly correlationId?: string
  readonly version?: number
}

/**
 * The wire version, in the CONTRACT's shape.
 *
 * The stored column stays an integer — storage records the major — and the mapping happens here,
 * at the wire, in one place. `EventVersion` is IMPORTED rather than restated: a local copy of a
 * contract type is a copy that can drift, which is the whole reason this function exists.
 */
const wireVersion = (v: number): EventVersion => `${v}.0` as EventVersion

/**
 * The wire envelope. Additive-only, versioned per topic, schema-diff enforced — AD-02.
 *
 * **`actor` and `correlationId` are `string`, not `string | null`.** They were nullable here
 * because the columns are nullable. `validateEnvelope` refuses a null actor ("actor: missing") and
 * a null correlation id ("correlationId: missing; a cross-service investigation stops here"). A
 * nullable column is a storage fact; the wire has no such freedom.
 */
export interface EventEnvelope {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurredAt: string
  readonly producer: string
  readonly version: EventVersion
  readonly actor: string
  readonly correlationId: string
  readonly payload: Record<string, unknown>
}

export type Emit = (event: DomainEvent) => void

/**
 * Run a domain change and its events in one transaction.
 *
 * `emit` collects rather than writes, so the events land after the handler has succeeded and a
 * caller cannot accidentally publish an event for a change it then rolled back.
 */
export async function withOutbox<T>(
  sql: Db,
  producer: string,
  fn: (tx: Tx, emit: Emit) => Promise<T>,
): Promise<T> {
  const outcome = await sql.begin(async (tx) => {
    const pending: DomainEvent[] = []
    const value = await fn(tx, (event) => {
      pending.push(event)
    })
    for (const event of pending) await emitOn(tx, producer, event)
    // Wrapped so postgres.js does not treat an array-shaped result as a list of promises to
    // unwrap, which would rewrite the caller's return type.
    return { value }
  })
  return outcome.value
}

/** Write one outbox row on a transaction the caller already holds. Same guarantee. */
export async function emitOn(tx: Tx, producer: string, event: DomainEvent): Promise<void> {
  await tx`
    insert into outbox (topic, key, producer, version, actor, correlation_id, payload)
    values (
      ${event.topic},
      ${event.key},
      ${producer},
      ${event.version ?? 1},
      ${event.actor ?? null},
      ${event.correlationId ?? null},
      ${tx.json(event.payload as Record<string, never>)}
    )
  `
}

/* ------------------------------------------------------------------------ signing */

/**
 * `t=<seconds>,v1=<hex>` over the exact bytes sent — the estate's delivery scheme, from
 * `@cloudsforge/contracts-events`.
 *
 * Chosen over a bare `sha256=<hex>` MAC because the timestamp is in the signed material, so a
 * captured delivery cannot be replayed outside the tolerance window. `activity/src/ingest.ts`
 * is the sibling that already uses it.
 */
export function signEvent(body: string, secret: string, at?: number): string {
  return at === undefined ? signDelivery(body, secret) : signDelivery(body, secret, at)
}

export type SignatureCheck =
  | { readonly ok: true; readonly keyIndex: number }
  | { readonly ok: false; readonly reason: string }

/**
 * Verify a signature over the RAW BYTES, before anything is parsed.
 *
 * The ordering is the whole control. A handler that parses first and verifies second has already
 * run an untrusted document through a parser, and has already made decisions — content type,
 * field coercion, size — on input nobody authenticated. `verifyDelivery` compares with
 * `timingSafeEqual` after a length check, because a byte-at-a-time comparison of a MAC is a
 * byte-at-a-time forgery oracle.
 */
export function verifyEventSignature(
  rawBody: string,
  header: string | undefined,
  secrets: readonly string[],
  now?: number,
): SignatureCheck {
  if (!header) return { ok: false, reason: 'missing_signature' }
  const result = verifyDelivery(rawBody, header, secrets, now === undefined ? {} : { now })
  return result.ok ? { ok: true, keyIndex: result.keyIndex } : { ok: false, reason: result.reason }
}

/* ------------------------------------------------------------------------ relay */

export interface RelayDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly signingSecret: string
  readonly batchSize?: number
  readonly deadlineMs?: number
  /** Test seam. Production builds one `HttpClient` per subscription URL. */
  readonly clientFor?: (url: string) => Pick<HttpClient, 'request'>
}

interface OutboxRow {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurred_at: Date
  readonly producer: string
  readonly version: number
  readonly actor: string | null
  readonly correlation_id: string | null
  readonly payload: Record<string, unknown>
}

interface SubscriptionRow {
  readonly id: string
  readonly url: string
}

/**
 * One outbox row → one wire envelope. **The only place an envelope is built.**
 *
 * Exported so `topics.test.ts` can hand the real thing to the contract's own `validateEnvelope`
 * rather than to a copy. That distinction is the point: every service's suite in this estate was
 * green while every event it emitted was refused, because both sides tested against imagined
 * counterparts. A guard that builds its own envelope proves only that the guard can build one.
 *
 * The two defaults are the contract's own semantics, not inventions:
 *
 *   - **`correlationId` falls back to the event id.** `makeEvent` does exactly this — "an event
 *     that starts a story rather than continuing one is its own correlation root".
 *   - **`actor` falls back to `service:devplatform`.** `emitKeyRevoked` is called with
 *     `'service:identity'` from the erasure path and with a caller subject from the route; an emit
 *     with neither was this service acting on its own behalf, which is what `serviceActor` spells.
 *     `null` is not an actor the contract has a word for.
 *
 * The erasure path said `'system:identity'` until `micro-contracts` `8889373` registered
 * `devplatform.key.revoked` and made it matter. `system` is the one kind the contract gives no
 * subject to, so that string was refused as an unknown kind and the whole envelope discarded. The
 * column is `string | null` here because it is read back out of Postgres and a database can hold
 * anything; what goes IN is `DomainEvent.actor`, which is now the contract's `Actor` and cannot be
 * written wrongly again.
 */
export function buildEnvelope(row: OutboxRow): EventEnvelope {
  return {
    id: row.id,
    topic: row.topic,
    key: row.key,
    occurredAt: row.occurred_at.toISOString(),
    producer: row.producer,
    version: wireVersion(row.version),
    actor: row.actor ?? serviceActor('devplatform'),
    correlationId: row.correlation_id ?? row.id,
    payload: row.payload,
  }
}

/**
 * The relay job.
 *
 * A leased job rather than a `setInterval`, for the reason rule 8 exists: two replicas running an
 * interval-driven relay both read the same unpublished rows and every subscriber receives every
 * event twice. The lease key names the contended resource — the outbox stream — so exactly one
 * replica relays at a time whatever the replica count is.
 */
export function createRelay(deps: RelayDeps): Handler {
  const batchSize = deps.batchSize ?? 50
  const deadlineMs = deps.deadlineMs ?? 5_000
  // Cached for the life of the process so a circuit breaker accumulates state across ticks. A
  // fresh client per tick has a permanently closed circuit and hammers a dead subscriber.
  const clients = new Map<string, Pick<HttpClient, 'request'>>()
  const clientFor =
    deps.clientFor ??
    ((url: string) => {
      const existing = clients.get(url)
      if (existing) return existing
      const parsed = new URL(url)
      const client = new HttpClient({ baseUrl: parsed.origin, name: `subscriber:${parsed.host}` })
      clients.set(url, client)
      return client
    })

  return async (_job, ctx) => {
    const events = await deps.sql<OutboxRow[]>`
      select id, topic, key, occurred_at, producer, version, actor, correlation_id, payload
        from outbox
       where published_at is null
       order by occurred_at
       limit ${batchSize}
    `

    for (const event of events) {
      if (ctx.signal.aborted) return

      const subscriptions = await deps.sql<SubscriptionRow[]>`
        select id, url from event_subscriptions where topic = ${event.topic} and active = true
      `

      const envelope = buildEnvelope(event)
      const signature = signEvent(JSON.stringify(envelope), deps.signingSecret)

      for (const subscription of subscriptions) {
        await deliver(deps, clientFor, subscription, envelope, signature, deadlineMs)
      }

      // Only when nothing is outstanding.
      //
      // THE GUARANTEE THIS USED TO CLAIM IS FALSE, and it was carried verbatim by eighteen
      // repositories. It said "a subscriber added after the event was written still receives it",
      // which holds only while some OTHER subscriber is still undelivered. With no active
      // subscription for the topic — the ordinary case for a new event type — the count below is
      // zero on the first pass, the row is published immediately, and it is never reconsidered. A
      // subscriber added afterwards gets nothing.
      //
      // The behaviour is right: an outbox row that stays unpublished because nobody is listening
      // is a backlog that grows for ever. It is the promise that was wrong, and a false guarantee
      // is worse than none, because an integrator plans around it — "register the subscription
      // whenever, the outbox will catch up" is a reasonable thing to believe from the old wording
      // and will silently lose every event published before the subscription existed.
      //
      // Delivery rows ARE computed from the live subscription set on every pass, which is what
      // makes a subscriber added mid-flight receive the remainder. That is the true half.
      const outstanding = await deps.sql<{ n: number }[]>`
        select count(*)::int as n
          from event_subscriptions s
          left join outbox_deliveries d
            on d.subscription_id = s.id and d.event_id = ${event.id}
         where s.topic = ${event.topic}
           and s.active = true
           and d.delivered_at is null
      `
      if ((outstanding[0]?.n ?? 0) === 0) {
        await deps.sql`update outbox set published_at = now() where id = ${event.id}`
      }

      // A long backlog must not outlive the lease and hand the same events to a second replica.
      await ctx.heartbeat()
    }
  }
}

async function deliver(
  deps: RelayDeps,
  clientFor: (url: string) => Pick<HttpClient, 'request'>,
  subscription: SubscriptionRow,
  envelope: EventEnvelope,
  signature: string,
  deadlineMs: number,
): Promise<boolean> {
  const claimed = await deps.sql<{ delivered_at: Date | null }[]>`
    insert into outbox_deliveries (event_id, subscription_id, attempts)
    values (${envelope.id}, ${subscription.id}, 0)
    on conflict (event_id, subscription_id) do update set attempts = outbox_deliveries.attempts + 1
    returning delivered_at
  `
  if (claimed[0]?.delivered_at) return true

  const parsed = new URL(subscription.url)
  try {
    await clientFor(subscription.url).request(`${parsed.pathname}${parsed.search}`, {
      method: 'POST',
      body: envelope,
      deadlineMs,
      // The event id is the idempotency key, which is what makes this POST safe to retry and is
      // the same value the subscriber dedupes on.
      idempotencyKey: envelope.id,
      headers: { [SIGNATURE_HEADER]: signature, 'cf-event-id': envelope.id },
      ...(envelope.correlationId ? { requestId: envelope.correlationId } : {}),
    })
    await deps.sql`
      update outbox_deliveries set delivered_at = now(), last_error = null
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    return true
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    await deps.sql`
      update outbox_deliveries set last_error = ${message.slice(0, 2_000)}
       where event_id = ${envelope.id} and subscription_id = ${subscription.id}
    `
    // Logged, not thrown: one unreachable subscriber must not stop the others or the rest of the
    // batch. The job succeeds; the undelivered row is the durable record and the next pass retries.
    deps.logger.warn('event delivery failed', {
      topic: envelope.topic,
      eventId: envelope.id,
      subscriptionId: subscription.id,
      err: message,
    })
    return false
  }
}

/* ------------------------------------------------------------------------ inbox */

export type InboxOutcome<T> =
  | { readonly status: 'processed'; readonly value: T }
  | { readonly status: 'duplicate' }

/**
 * Run an inbound event's handler exactly once, deduped on the SOURCE's event id.
 *
 * The insert and the handler share one transaction, so a handler that fails leaves no inbox row
 * and the redelivery is processed rather than swallowed — the mistake that makes a naive "record
 * then handle" dedupe lose events.
 */
export async function withInbox<T>(
  sql: Db,
  topic: string,
  sourceEventId: string,
  handle: (tx: Tx) => Promise<T>,
): Promise<InboxOutcome<T>> {
  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ source_event_id: string }[]>`
      insert into inbox (topic, source_event_id) values (${topic}, ${sourceEventId})
      on conflict (topic, source_event_id) do nothing
      returning source_event_id
    `
    if (claimed.length === 0) return { result: { status: 'duplicate' } as InboxOutcome<T> }
    const value = await handle(tx)
    return { result: { status: 'processed', value } as InboxOutcome<T> }
  })
  return outcome.result
}
