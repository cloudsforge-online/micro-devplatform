/**
 * Webhook endpoints, their signing secrets, and delivery.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE HONEST EXCEPTION: THIS SECRET IS STORED RECOVERABLY, AND IT HAS TO BE.**
 *
 * Everything else in this service is shown once and stored under scrypt. A webhook secret cannot
 * be, and pretending otherwise would be worse than the exception: HMAC is a keyed function of the
 * payload, and signing every delivery requires the key material itself. A hash of the secret cannot
 * sign anything. There is no arrangement in which this service both signs deliveries and does not
 * hold the secret — short of moving signing into the subscriber, which is the same problem one hop
 * further on.
 *
 * So `webhook_secrets.secret` is plaintext, and the compensating controls are the ones that are
 * actually available:
 *
 *   - **It is shown once.** `createEndpoint` and `rotateSecret` return it; no route reads it back,
 *     and `server.test.ts` proves that by enumerating every route's response.
 *   - **It grants nothing.** Unlike an API key, this secret authenticates US to the SUBSCRIBER. A
 *     leaked webhook secret lets an attacker forge deliveries to one customer's endpoint. That is
 *     bad; it is not "read or write the customer's data", which is what a leaked API key would be.
 *   - **It is rotatable without an outage,** which is the control that matters most, below.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **ROTATION KEEPS TWO SECRETS LIVE, BECAUSE THE INSTANT DOES NOT EXIST.**
 *
 * A single-value rotation requires the subscriber to change its configuration in the same instant
 * this service does. That instant does not exist: there is a deploy in between, and every delivery
 * during it is signed with a secret the subscriber has not got. The result is a customer who
 * rotates a secret and silently loses events — which they discover days later, from missing data.
 *
 * So rotation writes a NEW row and stamps `retires_at` on the old one. Both verify during the
 * overlap, and `signingSecret` always signs with the newest. This is the same shape as
 * `DEVPLATFORM_INGEST_SECRETS` in `env.ts` and as `activity`'s ingest list, and it is why
 * `verifyDelivery` in `@cloudsforge/contracts-events` takes a LIST of secrets rather than one.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A SIGNATURE IS VERIFIED OVER THE RAW BYTES, BEFORE ANYTHING IS PARSED.** That ordering is the
 * control, not a detail. A handler that parses first has already run an attacker's document through
 * a parser and already made decisions — content type, numeric coercion, key collision, size — on
 * input nobody authenticated. `verifyInbound` below takes a `Buffer` for exactly that reason: it is
 * not possible to call it with a parsed object, because the type will not allow one.
 */

import { randomBytes, timingSafeEqual } from 'node:crypto'
import type { HttpClient } from '@cloudsforge/http'
import type { Actor } from '@cloudsforge/contracts-events'
import type { Db, Emit, EventEnvelope, Tx } from './outbox.ts'
import { TOPICS, signEvent, verifyEventSignature } from './outbox.ts'
import { NotFoundError, ValidationError } from './orgs.ts'

/** 32 bytes, hex. Long enough that `webhook_secrets_secret_length` passes and brute force does not. */
const SECRET_BYTES = 32
export const SECRET_PREFIX = 'whsec_'

export function mintWebhookSecret(): string {
  return `${SECRET_PREFIX}${randomBytes(SECRET_BYTES).toString('hex')}`
}

export interface WebhookEndpoint {
  readonly id: string
  readonly projectId: string
  readonly environmentId: string
  readonly url: string
  readonly topics: readonly string[]
  readonly description: string
  readonly disabledAt: Date | null
  readonly createdAt: Date
}

interface EndpointRow {
  readonly id: string
  readonly project_id: string
  readonly environment_id: string
  readonly url: string
  readonly topics: readonly string[]
  readonly description: string
  readonly disabled_at: Date | null
  readonly created_at: Date
}

function toEndpoint(row: EndpointRow): WebhookEndpoint {
  return {
    id: row.id,
    projectId: row.project_id,
    environmentId: row.environment_id,
    url: row.url,
    topics: row.topics,
    description: row.description,
    disabledAt: row.disabled_at,
    createdAt: row.created_at,
  }
}

/**
 * Validate a subscriber URL.
 *
 * https only, and the schema enforces it too. A plaintext delivery carries a signed payload over a
 * wire anyone can read: the signature proves ORIGIN, it does not provide CONFIDENTIALITY, and a
 * webhook body is customer data.
 *
 * Loopback and link-local are refused as well. A subscriber URL is a destination this service
 * dials from inside the application network, so an unchecked one is a server-side request forgery
 * primitive: a customer registers `https://169.254.169.254/…` and this service obligingly fetches
 * the cloud instance metadata endpoint and reports the response status back to them.
 */
export function assertSubscriberUrl(raw: string): string {
  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    throw new ValidationError('a webhook url must be an absolute https URL')
  }
  if (url.protocol !== 'https:') {
    throw new ValidationError('a webhook url must use https — a signature proves origin, not confidentiality')
  }
  if (url.username !== '' || url.password !== '') {
    throw new ValidationError('a webhook url must not carry credentials in its authority')
  }
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '::1' ||
    /^127\./.test(host) ||
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^172\.(1[6-9]|2[0-9]|3[01])\./.test(host) ||
    /^(fc|fd)[0-9a-f]{2}:/.test(host) ||
    /^fe80:/.test(host)
  ) {
    throw new ValidationError('a webhook url must not point at a private or loopback address')
  }
  return url.toString()
}

export interface CreateEndpointInput {
  readonly projectId: string
  readonly environmentId: string
  readonly url: string
  readonly topics: readonly string[]
  readonly description?: string
}

export interface CreatedEndpoint {
  readonly endpoint: WebhookEndpoint
  /** Shown once. No route returns it afterwards. See the file header for why it is recoverable. */
  readonly secret: string
}

export async function createEndpoint(tx: Tx, input: CreateEndpointInput): Promise<CreatedEndpoint> {
  const url = assertSubscriberUrl(input.url)
  const topics = [...new Set(input.topics.map((topic) => topic.trim()).filter((t) => t.length > 0))].sort()
  if (topics.length === 0) {
    // An endpoint that receives everything by default is an endpoint nobody meant to subscribe, and
    // it is how a customer's integration starts seeing events they never asked to be sent.
    throw new ValidationError('name at least one topic — an endpoint with no topics receives nothing')
  }
  if (topics.some((topic) => topic.includes('*'))) {
    throw new ValidationError('there is no wildcard topic: name every topic the endpoint wants')
  }

  const environments = await tx<{ id: string }[]>`
    select id from environments where id = ${input.environmentId} and project_id = ${input.projectId}
  `
  if (!environments[0]) throw new NotFoundError('no such environment in this project')

  const rows = await tx<EndpointRow[]>`
    insert into webhook_endpoints (project_id, environment_id, url, topics, description)
    values (${input.projectId}, ${input.environmentId}, ${url}, ${tx.array(topics)},
            ${(input.description ?? '').trim().slice(0, 2_000)})
    on conflict (environment_id, url) do nothing
    returning id, project_id, environment_id, url, topics, description, disabled_at, created_at
  `
  const row = rows[0]
  if (!row) throw new ValidationError('this environment already has an endpoint for that url')

  const secret = mintWebhookSecret()
  await tx`insert into webhook_secrets (endpoint_id, secret) values (${row.id}, ${secret})`
  return { endpoint: toEndpoint(row), secret }
}

export function emitEndpointCreated(emit: Emit, endpoint: WebhookEndpoint, actor: Actor): void {
  emit({
    topic: TOPICS.webhookEndpointCreated,
    key: endpoint.id,
    actor,
    payload: {
      endpointId: endpoint.id,
      projectId: endpoint.projectId,
      environmentId: endpoint.environmentId,
      // The URL is a fact about the customer's own infrastructure, not a secret, and an operator
      // reading an event stream needs to know which endpoint an event concerns.
      url: endpoint.url,
      topics: [...endpoint.topics],
    },
  })
}

export async function listEndpoints(sql: Tx | Db, projectId: string): Promise<readonly WebhookEndpoint[]> {
  const rows = await sql<EndpointRow[]>`
    select id, project_id, environment_id, url, topics, description, disabled_at, created_at
      from webhook_endpoints where project_id = ${projectId} order by created_at desc
  `
  return rows.map(toEndpoint)
}

export async function findEndpoint(sql: Tx | Db, id: string): Promise<WebhookEndpoint | null> {
  const rows = await sql<EndpointRow[]>`
    select id, project_id, environment_id, url, topics, description, disabled_at, created_at
      from webhook_endpoints where id = ${id}
  `
  const row = rows[0]
  return row ? toEndpoint(row) : null
}

export async function setEndpointDisabled(
  sql: Tx | Db,
  id: string,
  disabled: boolean,
): Promise<WebhookEndpoint> {
  const rows = await sql<EndpointRow[]>`
    update webhook_endpoints set disabled_at = ${disabled ? new Date() : null} where id = ${id}
    returning id, project_id, environment_id, url, topics, description, disabled_at, created_at
  `
  const row = rows[0]
  if (!row) throw new NotFoundError('no such webhook endpoint')
  return toEndpoint(row)
}

export async function deleteEndpoint(sql: Tx | Db, id: string): Promise<boolean> {
  const rows = await sql<{ id: string }[]>`delete from webhook_endpoints where id = ${id} returning id`
  return rows.length > 0
}

/* ------------------------------------------------------------------ secrets */

/**
 * Rotate. Writes the new secret and retires the old one at the end of the overlap window.
 *
 * The old rows are RETIRED rather than deleted, and only rows that are still live are retired — so
 * rotating twice inside one overlap window does not extend the first secret's life by resetting its
 * `retires_at`.
 */
export async function rotateSecret(
  tx: Tx,
  endpointId: string,
  overlapMinutes: number,
): Promise<string> {
  const endpoints = await tx<{ id: string }[]>`select id from webhook_endpoints where id = ${endpointId}`
  if (!endpoints[0]) throw new NotFoundError('no such webhook endpoint')

  const retiresAt = new Date(Date.now() + overlapMinutes * 60_000)
  await tx`
    update webhook_secrets set retires_at = ${retiresAt}
     where endpoint_id = ${endpointId} and retires_at is null
  `
  const secret = mintWebhookSecret()
  await tx`insert into webhook_secrets (endpoint_id, secret) values (${endpointId}, ${secret})`
  return secret
}

/**
 * Every secret that is still accepted for an endpoint, newest first.
 *
 * Internal only — no route calls this, and `server.test.ts` enumerates the routes to prove it. It
 * exists so the delivery job can sign with the newest and so a subscriber-side verification helper
 * can be tested against the same list the real verifier would use.
 */
export async function liveSecrets(sql: Db | Tx, endpointId: string): Promise<readonly string[]> {
  const rows = await sql<{ secret: string }[]>`
    select secret from webhook_secrets
     where endpoint_id = ${endpointId} and (retires_at is null or retires_at > now())
     order by created_at desc
  `
  return rows.map((row) => row.secret)
}

/** The secret a new delivery is signed with: the newest live one. */
export async function signingSecret(sql: Db | Tx, endpointId: string): Promise<string | null> {
  const secrets = await liveSecrets(sql, endpointId)
  return secrets[0] ?? null
}

/** Drop secrets whose overlap has elapsed. A retired secret that still verifies is not retired. */
export async function pruneRetiredSecrets(sql: Db): Promise<number> {
  const result = (await sql`
    delete from webhook_secrets where retires_at is not null and retires_at < now()
  `) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}

/* ------------------------------------------------------------------ signing and verifying */

/**
 * Verify an inbound signed body.
 *
 * **Takes a `Buffer`, and that is the whole point.** The bytes are what was signed; a re-serialised
 * object is not, because `JSON.stringify` is not the inverse of `JSON.parse` (key order, number
 * formatting, unicode escapes). Typing the parameter as bytes makes "parse first, verify second"
 * unwriteable rather than merely discouraged.
 *
 * The comparison itself is `timingSafeEqual` inside `verifyDelivery`, after a length check. A
 * byte-at-a-time comparison of a MAC is a byte-at-a-time forgery oracle.
 */
export function verifyInbound(
  rawBody: Buffer,
  header: string | undefined,
  secrets: readonly string[],
  now?: number,
): { readonly ok: boolean; readonly reason: string } {
  const outcome = verifyEventSignature(rawBody.toString('utf8'), header, secrets, now)
  return outcome.ok ? { ok: true, reason: 'ok' } : { ok: false, reason: outcome.reason }
}

/** Constant-time equality for two strings of possibly different length. */
export function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8')
  const right = Buffer.from(b, 'utf8')
  if (left.length !== right.length) return false
  return timingSafeEqual(left, right)
}

/* ------------------------------------------------------------------ delivery */

export interface Delivery {
  readonly id: string
  readonly endpointId: string
  readonly eventId: string
  readonly topic: string
  readonly payload: Record<string, unknown>
  readonly attempts: number
  readonly deliveredAt: Date | null
  readonly lastStatus: number | null
  readonly lastError: string | null
  readonly nextAttemptAt: Date
}

interface DeliveryRow {
  readonly id: string
  readonly endpoint_id: string
  readonly event_id: string
  readonly topic: string
  readonly payload: Record<string, unknown>
  readonly attempts: number
  readonly delivered_at: Date | null
  readonly last_status: number | null
  readonly last_error: string | null
  readonly next_attempt_at: Date
}

function toDelivery(row: DeliveryRow): Delivery {
  return {
    id: row.id,
    endpointId: row.endpoint_id,
    eventId: row.event_id,
    topic: row.topic,
    payload: row.payload,
    attempts: row.attempts,
    deliveredAt: row.delivered_at,
    lastStatus: row.last_status,
    lastError: row.last_error,
    nextAttemptAt: row.next_attempt_at,
  }
}

/**
 * Fan one event out to every endpoint subscribed to its topic.
 *
 * `on conflict (endpoint_id, event_id) do nothing` is what makes this safe to call more than once
 * for the same event — which it WILL be, because the outbox relay is at-least-once. The unique
 * constraint is the mechanism; the `do nothing` is what stops a redelivery becoming a second
 * customer-visible webhook.
 */
export async function enqueueDeliveries(sql: Db | Tx, envelope: EventEnvelope): Promise<number> {
  const rows = await sql<{ id: string }[]>`
    insert into webhook_deliveries (endpoint_id, event_id, topic, payload)
    select e.id, ${envelope.id}, ${envelope.topic}, ${sql.json(envelope as unknown as Record<string, never>)}
      from webhook_endpoints e
     where e.disabled_at is null
       and ${envelope.topic} = any(e.topics)
    on conflict (endpoint_id, event_id) do nothing
    returning id
  `
  return rows.length
}

/**
 * Claim due deliveries.
 *
 * `for update skip locked` on the SELECT and the claim in the same statement, so two workers never
 * take the same row. The `next_attempt_at` push is what makes the claim durable: if this worker
 * dies mid-delivery, the row becomes claimable again only after the backoff, rather than instantly
 * being retried by every other worker in a loop.
 */
export async function claimDeliveries(
  sql: Db,
  limit: number,
  leaseMs: number,
): Promise<readonly Delivery[]> {
  const rows = (await sql.unsafe(
    `update webhook_deliveries
        set attempts = attempts + 1,
            next_attempt_at = now() + ($2 || ' milliseconds')::interval
      where id in (
        select id from webhook_deliveries
         where delivered_at is null
           and next_attempt_at <= now()
         order by next_attempt_at
         limit $1
         for update skip locked
      )
     returning id, endpoint_id, event_id, topic, payload, attempts, delivered_at,
               last_status, last_error, next_attempt_at`,
    [limit, String(leaseMs)],
  )) as unknown as DeliveryRow[]
  return rows.map((row) => ({
    ...toDelivery(row),
    // A parameterised `unsafe` query returns jsonb as text, while the tagged-template path returns
    // it parsed. Normalised here so a handler is never handed a payload whose type depends on how
    // the query was issued — the same defect `@cloudsforge/jobs` documents at index.ts.
    payload:
      typeof row.payload === 'string'
        ? (JSON.parse(row.payload) as Record<string, unknown>)
        : row.payload,
  }))
}

export async function markDelivered(sql: Db, id: string, status: number): Promise<void> {
  await sql`
    update webhook_deliveries
       set delivered_at = now(), last_status = ${status}, last_error = null
     where id = ${id}
  `
}

/**
 * Record a failed attempt and schedule the next.
 *
 * Past `maxAttempts` the row is left with `delivered_at` null and `next_attempt_at` far in the
 * future rather than deleted. The row is the only durable record that a customer's endpoint was
 * sent an event and never took it, and an operator answering "why did my integration miss this?"
 * has nowhere else to look.
 */
export async function markFailed(
  sql: Db,
  delivery: Delivery,
  status: number | null,
  error: string,
  maxAttempts: number,
): Promise<'retry' | 'abandoned'> {
  const exhausted = delivery.attempts >= maxAttempts
  const backoffMs = exhausted ? 365 * 24 * 3_600_000 : backoffFor(delivery.attempts)
  await sql`
    update webhook_deliveries
       set last_status = ${status},
           last_error = ${error.slice(0, 2_000)},
           next_attempt_at = now() + ${`${backoffMs} milliseconds`}::interval
     where id = ${delivery.id}
  `
  return exhausted ? 'abandoned' : 'retry'
}

/** Exponential with full jitter, capped at an hour. */
export function backoffFor(attempt: number, random: () => number = Math.random): number {
  const cap = Math.min(1_000 * 2 ** Math.max(0, attempt - 1), 3_600_000)
  return Math.floor(cap * (0.5 + 0.5 * random()))
}

export interface DeliverDeps {
  readonly sql: Db
  readonly deadlineMs: number
  readonly maxAttempts: number
  /** Test seam. Production builds one `HttpClient` per subscriber origin. */
  readonly clientFor: (url: string) => Pick<HttpClient, 'request'>
}

export type DeliveryOutcome = 'delivered' | 'retry' | 'abandoned' | 'no_secret' | 'gone'

/**
 * Deliver one claimed row.
 *
 * The signature is computed over the EXACT string that is sent. `signEvent` produces
 * `t=<seconds>,v1=<hex>` and the body is `JSON.stringify(payload)` computed once and used for both
 * — a second `JSON.stringify` for the body would be a different string in principle and the
 * subscriber would reject every delivery for reasons nobody could reproduce.
 */
export async function deliverOne(deps: DeliverDeps, delivery: Delivery): Promise<DeliveryOutcome> {
  const endpoint = await findEndpoint(deps.sql, delivery.endpointId)
  if (!endpoint || endpoint.disabledAt !== null) {
    // The endpoint was deleted or disabled after the row was queued. Not a failure: mark it done so
    // it stops being claimed, with a status that says why.
    await markDelivered(deps.sql, delivery.id, 410)
    return 'gone'
  }

  const secret = await signingSecret(deps.sql, delivery.endpointId)
  if (!secret) {
    await markFailed(deps.sql, delivery, null, 'the endpoint has no live signing secret', deps.maxAttempts)
    return 'no_secret'
  }

  const body = JSON.stringify(delivery.payload)
  const signature = signEvent(body, secret)
  const target = new URL(endpoint.url)

  try {
    await deps.clientFor(endpoint.url).request(`${target.pathname}${target.search}`, {
      method: 'POST',
      body: delivery.payload,
      deadlineMs: deps.deadlineMs,
      // The event id is the idempotency key, which is what makes this POST safe to retry and is the
      // same value a well-built subscriber dedupes on.
      idempotencyKey: delivery.eventId,
      headers: {
        'cf-signature': signature,
        'cf-event-id': delivery.eventId,
        'cf-topic': delivery.topic,
      },
    })
    await markDelivered(deps.sql, delivery.id, 200)
    return 'delivered'
  } catch (err) {
    const status = (err as { status?: number }).status ?? null
    const outcome = await markFailed(
      deps.sql,
      delivery,
      status,
      err instanceof Error ? err.message : String(err),
      deps.maxAttempts,
    )
    return outcome
  }
}

export async function listDeliveries(
  sql: Db | Tx,
  endpointId: string,
  limit = 50,
): Promise<readonly Delivery[]> {
  const rows = await sql<DeliveryRow[]>`
    select id, endpoint_id, event_id, topic, payload, attempts, delivered_at,
           last_status, last_error, next_attempt_at
      from webhook_deliveries where endpoint_id = ${endpointId}
     order by created_at desc limit ${Math.min(Math.max(limit, 1), 200)}
  `
  return rows.map(toDelivery)
}
