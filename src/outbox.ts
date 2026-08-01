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
 * `11-data-and-contract-strategy.md:363` says key validation is "cached 30 s" by the gateway and
 * that "revocation propagates via `devplatform.key.revoked`". So the outbox row written in the
 * same transaction as the revocation is the mechanism by which a revoked key actually stops
 * working at every cache in the estate. Revocation is immediate in *this* service — the row is
 * updated and the next verification here refuses — and the event is what makes it immediate
 * everywhere else.
 *
 * **A DEFECT IN THE INHERITED CONTRACT, RECORDED NOT FIXED.** `devplatform.key.revoked` is not a
 * registered topic. `contracts/packages/events/src/index.ts:222` freezes `TOPICS` and
 * `TopicName = keyof typeof TOPICS` (:351) closes the set; `devplatform` is a legal
 * `ProducerService` (:194) but has no topic of its own in the registry. So the mechanism
 * 11:363 names by string cannot be constructed through `makeEvent`, which takes a `TopicName`.
 * `micro-contracts` is another repository and out of scope, so the topic names are local
 * constants here, validated with `isValidTopicName` — the shape check, which they pass — rather
 * than `isRegisteredTopic`, which they cannot until the contract package adds them. `topics.ts`
 * carries the list a future `contracts-devplatform` should adopt verbatim.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { isValidTopicName, signDelivery, verifyDelivery, SIGNATURE_HEADER } from '@cloudsforge/contracts-events'
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
  readonly actor?: string
  readonly correlationId?: string
  readonly version?: number
}

export interface EventEnvelope {
  readonly id: string
  readonly topic: string
  readonly key: string
  readonly occurredAt: string
  readonly producer: string
  readonly version: number
  readonly actor: string | null
  readonly correlationId: string | null
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
 * captured delivery cannot be replayed outside the tolerance window. `activity/src/ingest.ts:82`
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

      const envelope: EventEnvelope = {
        id: event.id,
        topic: event.topic,
        key: event.key,
        occurredAt: event.occurred_at.toISOString(),
        producer: event.producer,
        version: event.version,
        actor: event.actor,
        correlationId: event.correlation_id,
        payload: event.payload,
      }
      const signature = signEvent(JSON.stringify(envelope), deps.signingSecret)

      for (const subscription of subscriptions) {
        await deliver(deps, clientFor, subscription, envelope, signature, deadlineMs)
      }

      // Only when nothing is outstanding. A subscriber added after the event was written still
      // receives it, because the delivery set is computed from the live subscriptions on every
      // pass rather than fixed when the event was produced.
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
