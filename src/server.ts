/**
 * The HTTP surface.
 *
 * Rule 4 of docs/ecosystem/03 §2: `/livez`, `/readyz` and `/metrics` on every service, or it does
 * not pass CI.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PATHS ARE `/v1/…`, BECAUSE THE PUBLIC SURFACE NOW EXISTS AND SAYS SO.**
 *
 * `deploy/gateway/dynamic/public-api.yml` mounts `api.<apex>/v1/<resource>` uniformly and strips
 * `/v1` for the four services that do not serve it themselves. Serving `/v1` natively puts this
 * service in the wallet/market/mint/worlds half — forwarded unchanged, no rewrite middleware — and
 * that is the half to be in: a strip rule is a second place the public path is decided, and it
 * drifts.
 *
 * The resource names were chosen against the 52 paths in `sdk/openapi.json`, not against a guess.
 * The gateway routes by resource rather than by service precisely because there is no method+path
 * collision across the estate, and adding one here would break that property for everyone. So:
 * `organisations`, `projects`, `keys`, `webhook-endpoints`, `oauth-clients`, `quotas`, `usage`,
 * `apps`. Note what is NOT used: `/v1/tokens` is mint's, `/v1/auth` is identity's.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`GET /v1/keys/self` IS THE WHOAMI A MACHINE CREDENTIAL DID NOT HAVE.**
 *
 * 18-build-status.md §3.3d(4): `identity/src/server.ts:540` refuses a service token on
 * `GET /auth/me`, so a machine credential has no way to ask what it is. That finding is correct and
 * its remedy is not in identity, for a reason the finding could not have known before this service
 * existed: **an API key is not a JWT.** `identity`'s `/auth/me` verifies a signed token and reads
 * its claims (`authenticate` at `identity/src/server.ts:513`); a `cfk_live_…` string has no
 * signature, no claims and no issuer, and identity holds neither the row nor the scrypt hash that
 * would let it decide anything about one. Relaxing line 540 would let a SERVICE token — a different
 * credential entirely — read `/auth/me`, which is a separate question and one this service does not
 * own.
 *
 * So: **the service that issued the credential introspects it.** `GET /v1/keys/self` is
 * authenticated by the key itself, needs no scope, and answers the display string, the environment,
 * the project, the organisation and the exact scope list. It is the mirror of `/auth/me` for the
 * other kind of principal, and it is mounted on a resource the gateway can forward unchanged.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THREE PRINCIPALS, AND EACH ROUTE NAMES WHICH IT ACCEPTS.**
 *
 *   USER      An identity JWT. The developer console. Authority over an organisation is asked of
 *             identity per request (`membership.ts`) with the caller's own token forwarded.
 *   KEY       A `cfk_…` string. May act only within its OWN project, and only with the
 *             `devplatform:read` / `devplatform:write` scope. A key can therefore rotate its
 *             siblings but can never reach another customer's project, because the project id is
 *             taken from the ROW, never from the request.
 *   SERVICE   An identity-issued service JWT. On `/internal` — which
 *             `deploy/gateway/dynamic/policy.yml` refuses from outside at a priority nothing can
 *             outrank — and on the four OPERATOR routes, where it must carry `devplatform:admin`.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **AN OPERATOR IS NOT A MEMBER OF THE CUSTOMER'S ORGANISATION, AND MUST NOT HAVE TO BE.**
 *
 * Four things on this surface are the PLATFORM's decision about a customer rather than the
 * customer's decision about themselves: raising a quota, listing an application, rejecting one, and
 * reading the review queue. `isOperator` admits two principals for them and no third —
 *
 *   a SERVICE token carrying the exact scope `devplatform:admin`, or
 *   a USER token carrying the platform role `admin` (`runtime/packages/auth`'s `Role`, :24).
 *
 * — which is `market/src/server.ts:1335-1342`'s `requireOperator`, adopted rather than reinvented.
 * **An API key is never an operator**, whatever it carries: `devplatform:admin` is deliberately
 * absent from `scopes.ts`, so `validateScopes` refuses it at issuance and a key cannot hold it.
 *
 * This does not contradict the rule three paragraphs up. That rule refuses a service token that
 * names no scope, on routes that decide a customer's credentials by membership; these routes check
 * an EXACT scope with `includes`, which is the same control `/internal/keys/verify` uses and for
 * the same reason — `runtime/packages/auth`'s `hasScope` would admit `devplatform:*`.
 *
 * The membership check is SKIPPED for an operator rather than added to, and that is the point: an
 * operator asked to be a member of every organisation they ever act on would either be added to
 * thousands of them or given a token that is a member of all of them, and the second is the shape
 * of the omnipotent credential SD-05 exists to retire.
 *
 * **EVERY REFUSAL OF A CREDENTIAL IS THE SAME 401 WITH THE SAME MESSAGE.** `authenticateKey`
 * returns a reason — `unknown`, `revoked`, `expired`, `org_suspended` — and it goes to the log and
 * to a metric label and never to the wire. A caller who can tell `revoked` from `unknown` can tell
 * "this account exists and someone is watching" from "this key never existed".
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`POST /v1/events` IS SIGNATURE-CHECKED OVER THE RAW BYTES, BEFORE IT IS PARSED.**
 *
 * It consumes `identity.organisation.deleted` and `identity.user.deleted`, and acting on either
 * revokes credentials. Unsigned, it is a revoke-anybody's-integration endpoint reachable by
 * anything that can open a socket to the app network. The body is read as a `Buffer`, verified
 * against `DEVPLATFORM_INGEST_SECRETS` with a timing-safe comparison, and only then parsed.
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { ForbiddenError, TokenError, bearerFrom, statusFor, type Principal } from '@cloudsforge/auth'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { SIGNATURE_HEADER, withInbox, withOutbox, type Db, type Emit, type Tx } from './outbox.ts'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import {
  ConflictError,
  NotFoundError,
  ValidationError,
  createProject,
  enrolOrg,
  findEnvironment,
  findOrg,
  findOrgByIdentityId,
  findProject,
  listProjects,
  setOrgStatus,
  emitProjectCreated,
  type Project,
} from './orgs.ts'
import {
  authenticateKey,
  createServiceAccount,
  emitKeyIssued,
  emitKeyRevoked,
  findApiKey,
  introspect,
  issueApiKey,
  listApiKeys,
  listServiceAccounts,
  revokeApiKey,
  revokeOrgKeys,
  touchLastUsed,
  type ApiKeySummary,
} from './apikeys.ts'
import { SCOPES, SCOPE_NAMES, UnknownScopeError, grantsScope, type Scope } from './scopes.ts'
import { isKeyEnvironment, type Kdf, type KeyEnvironment, type ScryptParams } from './keys.ts'
import {
  API_REQUESTS,
  MAX_UNITS_CEILING,
  consumeAll,
  currentUsage,
  emitQuotaExceeded,
  findQuota,
  isPeriod,
  listQuotas,
  listUsage,
  quotasFor,
  recordUsage,
  seedDefaultQuotas,
  setQuota,
} from './quotas.ts'
import {
  createEndpoint,
  deleteEndpoint,
  emitEndpointCreated,
  findEndpoint,
  listDeliveries,
  listEndpoints,
  rotateSecret,
  setEndpointDisabled,
  verifyInbound,
} from './webhooks.ts'
import {
  listClients,
  registerClient,
  revokeClient,
  verifyClientSecret,
} from './oauth.ts'
import {
  OPERATOR_STATUSES,
  findApplicationByProject,
  findListedApplication,
  listDirectory,
  listForReview,
  setApplicationStatus,
  submitForReview,
  upsertApplication,
  isApplicationStatus,
} from './applications.ts'
import {
  ADMIN_ROLES,
  MembershipUnavailableError,
  READ_ROLES,
  permits,
  type MembershipClient,
  type OrgRole,
} from './membership.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

export const READ_SCOPE: Scope = 'devplatform:read'
export const WRITE_SCOPE: Scope = 'devplatform:write'

/** The service scope an internal caller needs to introspect a credential. */
export const INTROSPECT_SCOPE = 'devplatform:introspect'

/**
 * The service scope that makes a caller a platform OPERATOR.
 *
 * Deliberately absent from `scopes.ts`: that file is the vocabulary a customer's API key may carry,
 * `validateScopes` refuses anything outside it at issuance, and a key that could raise its own
 * project's quota would be the defect this scope exists to close. Matched with `includes`, never
 * with `hasScope` — see the file header.
 */
export const ADMIN_SCOPE = 'devplatform:admin'

/** The platform role on a USER token that makes its holder an operator. `runtime/packages/auth`:24. */
export const ADMIN_ROLE = 'admin'

export const ORG_DELETED_TOPIC = 'identity.organisation.deleted'
export const USER_DELETED_TOPIC = 'identity.user.deleted'

export const IDEMPOTENCY_HEADER = 'idempotency-key'
const SAFE_IDEMPOTENCY_KEY = /^[A-Za-z0-9._:-]{8,200}$/
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

const MAX_BODY_BYTES = 256 * 1024

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  readonly membership: MembershipClient
  readonly sql: Db
  readonly producer: string
  /** Verifies inbound event signatures on `POST /v1/events`. A LIST, so rotation has an overlap. */
  readonly ingestSecrets: readonly string[]
  readonly defaultQuotaPerMinute: number
  readonly defaultQuotaPerMonth: number
  readonly webhookRotationOverlapMinutes: number
  /** Test seams. Production leaves both undefined and hashes at `CURRENT_PARAMS`. */
  readonly scryptParams?: ScryptParams
  readonly kdf?: Kdf
  readonly beforeScrape?: () => Promise<void>
}

/** Domain metrics, declared rather than inferred from a log line — AD-20. */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'devplatform_up',
      help: 'Always 1. The series that proves the scrape reached devplatform at all.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'devplatform_keys_issued_total',
      help: 'API keys minted, by environment. Every one of these is a credential in a customer\'s hands.',
      kind: 'counter',
      labels: ['environment'],
    })
    .register({
      name: 'devplatform_keys_revoked_total',
      help: 'API keys revoked, by whether a human or an inbound event did it.',
      kind: 'counter',
      labels: ['source'],
    })
    .register({
      name: 'devplatform_key_refusals_total',
      help: 'Credential refusals by reason. This is where the reason goes — never into a response body. A climbing `unknown` is enumeration; a climbing `revoked` is a client that has not noticed.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'devplatform_quota_refusals_total',
      help: 'Requests refused by a quota, by period. Counted in Postgres, so this number is the estate\'s and not one replica\'s.',
      kind: 'counter',
      labels: ['period'],
    })
    .register({
      name: 'devplatform_webhook_deliveries_total',
      help: 'Webhook delivery attempts, by outcome. A climbing `abandoned` is customers silently missing events.',
      kind: 'counter',
      labels: ['outcome'],
    })
    .register({
      name: 'devplatform_webhook_pending',
      help: 'Webhook deliveries still queued.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'devplatform_webhook_abandoned',
      help: 'Webhook deliveries past their attempt ceiling. Retained rather than deleted, because the row is the only record that a customer was sent an event and never took it.',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'devplatform_events_rejected_total',
      help: 'Inbound events refused, by reason. `bad_signature` above zero means something is posting unsigned events at the inbox.',
      kind: 'counter',
      labels: ['reason'],
    })
}

/* ------------------------------------------------------------------ plumbing */

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
}

interface Route {
  readonly method: string
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':')
        ? `(?<${segment.slice(1)}>[^/]+)`
        : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

/**
 * Every credential refusal, carrying the reason for the LOG and nothing for the wire.
 *
 * One class rather than four, deliberately: with four the mapping in `handle` would have to
 * remember to render all four identically, and the day somebody adds a fifth is the day one of them
 * gets its own message.
 */
class UnauthenticatedError extends Error {
  readonly reason: string
  constructor(reason: string) {
    super('a valid credential is required')
    this.name = 'UnauthenticatedError'
    this.reason = reason
  }
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', { method, route: routeLabel, status: String(status) })
      deps.metrics.observe('http_request_duration_ms', durationMs, { method, route: routeLabel })
    }

    void handle(matched, { req, url, requestId, log, params }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status)
      })
      .catch((err: unknown) => {
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500)
      })
  })
}

async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await route.handle(ctx, deps)
  } catch (err) {
    if (err instanceof UnauthenticatedError) {
      // The reason goes here and nowhere else. See the file header.
      ctx.log.info('credential refused', { reason: err.reason })
      deps.metrics.increment('devplatform_key_refusals_total', { reason: err.reason })
      return errorReply(401, 'unauthenticated', 'a valid credential is required', ctx.requestId)
    }
    if (err instanceof MembershipUnavailableError) {
      // Identity is unreachable, so we do not KNOW whether the caller is a member. 503, never 403.
      ctx.log.error('membership check unavailable', { err })
      return errorReply(503, 'membership_unavailable', 'authorisation is temporarily unavailable', ctx.requestId)
    }
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid credential is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof IdempotencyKeyReuseError) {
      return errorReply(409, 'idempotency_key_reuse', err.message, ctx.requestId)
    }
    if (err instanceof IdempotencyInFlightError) {
      return errorReply(409, 'idempotency_in_flight', err.message, ctx.requestId)
    }
    if (err instanceof UnknownScopeError) return errorReply(400, 'unknown_scope', err.message, ctx.requestId)
    if (err instanceof NotFoundError) return errorReply(404, 'not_found', err.message, ctx.requestId)
    if (err instanceof ConflictError) return errorReply(409, 'conflict', err.message, ctx.requestId)
    if (err instanceof ValidationError) return errorReply(400, 'invalid', err.message, ctx.requestId)
    if (err instanceof BadRequestError) return errorReply(400, 'bad_request', err.message, ctx.requestId)
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------ principals */

interface UserPrincipal {
  readonly kind: 'user'
  readonly userId: string
  /** The raw token, kept so it can be forwarded to identity's membership route. Never logged. */
  readonly token: string
  /**
   * Platform roles from the token, verbatim. `admin` is the estate's operator.
   *
   * Carried rather than discarded because this is the ONLY thing that distinguishes a platform
   * operator from any other developer on the console surface: there is no operator table here, and
   * a service that invented one would be answering a question identity owns.
   */
  readonly roles: readonly string[]
}

interface KeyPrincipal {
  readonly kind: 'key'
  readonly key: ApiKeySummary
  readonly orgId: string
}

interface ServicePrincipal {
  readonly kind: 'service'
  readonly service: string
  readonly scopes: readonly string[]
}

/** The two principals the customer surface admits. A service token is not one of them. */
type CallerPrincipal = UserPrincipal | KeyPrincipal

/** Everything that can present a credential, including the operator's service token. */
type AnyPrincipal = CallerPrincipal | ServicePrincipal

/**
 * Resolve whoever is calling, service tokens included.
 *
 * A `cfk_` string is tried FIRST, by prefix, and that ordering is not an optimisation: handing a
 * key to `Verifier.principal` would dial the JWKS endpoint for a string that is provably not a JWT,
 * so a burst of malformed keys would become a burst of outbound requests to identity — an
 * amplification an unauthenticated caller controls the rate of.
 *
 * This is the only function that reads the Authorization header for a route, so a route resolves
 * its caller ONCE. `authenticate` narrows it for the customer surface; the operator routes keep the
 * wider type and ask `isOperator`.
 */
async function authenticateAny(ctx: RequestContext, deps: ServerDeps): Promise<AnyPrincipal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  if (!token) throw new UnauthenticatedError('missing')

  if (token.startsWith('cfk_')) {
    const outcome = await authenticateKey(deps.sql, token, {
      ...(deps.kdf ? { kdf: deps.kdf } : {}),
      ...(deps.scryptParams ? { params: deps.scryptParams } : {}),
    })
    if (!outcome.ok) throw new UnauthenticatedError(outcome.reason)
    // Fire and forget. An awaited UPDATE per authenticated request serialises every concurrent
    // caller of one key on one row; the write is coarsened to once a minute inside `touchLastUsed`.
    void touchLastUsed(deps.sql, outcome.key.id).catch(() => undefined)
    return { kind: 'key', key: outcome.key, orgId: outcome.orgId }
  }

  const principal = await deps.verifier.principal(token)
  if (principal.kind === 'service') {
    return { kind: 'service', service: principal.service, scopes: principal.scopes }
  }
  return { kind: 'user', userId: principal.userId, token, roles: principal.roles }
}

/**
 * Resolve the caller on the CUSTOMER surface.
 *
 * A service token is not "close enough" here. It names no user, so there is no membership to check,
 * and accepting one would make every service in the estate an administrator of every customer's
 * credentials. The operator routes are the exception and they say so, by requiring an exact scope
 * rather than by relaxing this.
 */
async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<CallerPrincipal> {
  const caller = await authenticateAny(ctx, deps)
  if (caller.kind === 'service') throw new ForbiddenError('this route requires a user token')
  return caller
}

/**
 * Is this the platform, acting on a customer?
 *
 * **An API key is never an operator.** Not "does not usually carry the scope" — `devplatform:admin`
 * is not in `scopes.ts`, so `validateScopes` refuses it at issuance and no row can hold it. That is
 * the property that stops the whole quota defect coming back through a different door: a key that
 * could make itself an operator could still raise its own project's limit.
 */
function isOperator(caller: AnyPrincipal): boolean {
  if (caller.kind === 'service') return caller.scopes.includes(ADMIN_SCOPE)
  if (caller.kind === 'user') return caller.roles.includes(ADMIN_ROLE)
  return false
}

/** `market/src/server.ts:1335`'s shape: the scope or the role, and nothing else. */
function requireOperator(caller: AnyPrincipal): void {
  if (!isOperator(caller)) throw new ForbiddenError(`${ADMIN_SCOPE} or role:admin`)
}

/** A user token only. The console surface. */
async function authenticateUser(ctx: RequestContext, deps: ServerDeps): Promise<UserPrincipal> {
  const caller = await authenticate(ctx, deps)
  if (caller.kind !== 'user') throw new ForbiddenError('this route requires a user token')
  return caller
}

/** An API key only, whatever its scopes. Used by the whoami. */
async function authenticateKeyOnly(ctx: RequestContext, deps: ServerDeps): Promise<KeyPrincipal> {
  const caller = await authenticate(ctx, deps)
  if (caller.kind !== 'key') throw new ForbiddenError('this route requires an api key')
  return caller
}

/** An internal service token carrying the named scope. `/internal` only. */
async function authenticateService(
  ctx: RequestContext,
  deps: ServerDeps,
  required: string,
): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  if (!token) throw new TokenError('no credential presented', 'missing')
  const principal = await deps.verifier.principal(token)
  if (principal.kind !== 'service') throw new ForbiddenError('this route requires a service token')
  // EXACT match, not `hasScope`. `runtime/packages/auth`'s `hasScope` honours one wildcard level, so
  // a token carrying `devplatform:*` would be admitted here — and this route reads credentials.
  // See scopes.ts for the divergence between the two matchers in the estate.
  if (!principal.scopes.includes(required)) throw new ForbiddenError(required)
  return principal
}

/**
 * The authority a caller has over a project.
 *
 * **The project's organisation is read from the ROW, never from the request.** A key acting on
 * `/v1/projects/:id/keys` proves its authority by its own `projectId` matching the path, so there
 * is no parameter a caller can vary to reach another customer's project. For a user, the identity
 * organisation is looked up from the project and then asked of identity with the user's own token.
 */
async function authoriseProject(
  ctx: RequestContext,
  deps: ServerDeps,
  projectId: string,
  need: 'read' | 'write',
): Promise<{ caller: CallerPrincipal; project: Project }> {
  return authoriseProjectAs(await authenticate(ctx, deps), deps, projectId, need)
}

/**
 * The same decision, for a route that has already resolved its caller.
 *
 * Split out for `PUT /v1/projects/:id/quotas`, which has to know whether the caller is an operator
 * BEFORE it knows which authorisation to apply, and must not verify the token twice to find out.
 * The body is unchanged; `authoriseProject` is now the two-line wrapper it always was.
 */
async function authoriseProjectAs(
  caller: CallerPrincipal,
  deps: ServerDeps,
  projectId: string,
  need: 'read' | 'write',
): Promise<{ caller: CallerPrincipal; project: Project }> {
  const project = await findProject(deps.sql, projectId)
  // 404 rather than 403 for a project the caller cannot see. A 403 confirms the id exists, which
  // makes project ids enumerable across customers.
  if (!project) throw new NotFoundError('no such project')

  if (caller.kind === 'key') {
    if (caller.key.projectId !== project.id) throw new NotFoundError('no such project')
    const scope = need === 'write' ? WRITE_SCOPE : READ_SCOPE
    // Exact match. A key with no scopes reaches nothing; there is no wildcard. See scopes.ts.
    if (!grantsScope(caller.key.scopes, scope)) throw new ForbiddenError(scope)
    return { caller, project }
  }

  const role = await roleInOrg(deps, caller, project.orgId)
  if (!permits(role, need === 'write' ? ADMIN_ROLES : READ_ROLES)) {
    throw new NotFoundError('no such project')
  }
  return { caller, project }
}

async function authoriseOrg(
  ctx: RequestContext,
  deps: ServerDeps,
  orgId: string,
  need: 'read' | 'write',
): Promise<UserPrincipal> {
  const caller = await authenticateUser(ctx, deps)
  const role = await roleInOrg(deps, caller, orgId)
  if (!permits(role, need === 'write' ? ADMIN_ROLES : READ_ROLES)) {
    throw new NotFoundError('no such developer organisation')
  }
  return caller
}

async function roleInOrg(
  deps: ServerDeps,
  caller: UserPrincipal,
  orgId: string,
): Promise<OrgRole | null> {
  const org = await findOrg(deps.sql, orgId)
  if (!org) return null
  return deps.membership.roleFor(caller.token, org.identityOrgId, caller.userId)
}

function actorOf(caller: CallerPrincipal): string {
  return caller.kind === 'user' ? `user:${caller.userId}` : `key:${caller.key.display}`
}

/* ------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  const define = (
    method: string,
    path: string,
    handler: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>,
  ): Route => ({ method, path, pattern: compile(path), handle: handler })

  return [
    /* ---------------------------------------------------------------- health */

    define('GET', '/livez', async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() })),

    define('GET', '/readyz', async (_ctx, deps) => {
      const report = await deps.lifecycle.readyz()
      return { status: report.ready ? 200 : 503, body: report }
    }),

    define('GET', '/metrics', async (ctx, deps) => {
      try {
        await deps.beforeScrape?.()
      } catch (err) {
        ctx.log.warn('gauge refresh failed; serving the previous values', { err })
      }
      return {
        status: 200,
        text: deps.metrics.render(),
        contentType: 'text/plain; version=0.0.4; charset=utf-8',
      }
    }),

    /* ---------------------------------------------------------------- the scope vocabulary */

    /**
     * The scopes a key may carry, with their descriptions. Public and unauthenticated: it is a
     * property of the platform rather than of any customer, and a developer choosing scopes before
     * they have a key is exactly who needs it.
     */
    define('GET', '/v1/scopes', async () => ({
      status: 200,
      body: {
        scopes: SCOPE_NAMES.map((name) => ({ name, ...SCOPES[name] })),
        // Said out loud, because "I'll just use the wildcard" is the first thing a developer tries.
        wildcard: null,
        note: 'There is no wildcard scope. Name every scope a key needs; an unknown scope is refused at issuance.',
      },
    })),

    /* ---------------------------------------------------------------- whoami */

    /**
     * The credential's own introspection. See the file header — this is the answer to
     * 18-build-status.md §3.3d(4).
     *
     * No scope is required. A credential that cannot ask what it is cannot be diagnosed, and
     * gating this behind `devplatform:read` would mean the keys most likely to be misconfigured —
     * the ones with no scopes at all — are exactly the ones that cannot find out.
     */
    define('GET', '/v1/keys/self', async (ctx, deps) => {
      const caller = await authenticateKeyOnly(ctx, deps)
      return { status: 200, body: introspect(caller.key, caller.orgId) }
    }),

    /* ---------------------------------------------------------------- organisations */

    /**
     * Enrol an identity organisation in the developer platform.
     *
     * Not wrapped: `developer_orgs_identity_uniq` makes the identity organisation the natural key,
     * and `enrolOrg` is `on conflict do nothing` then read — so a second enrolment IS the first.
     */
    define('POST', '/v1/organisations', async (ctx, deps) => {
      const caller = await authenticateUser(ctx, deps)
      const body = await readJson(ctx.req)
      const identityOrgId = requireString(body, 'identityOrgId')
      // The caller must already be an administrator of the identity organisation they are
      // enrolling. Without this check, any authenticated user could enrol any organisation id they
      // could guess and become the owner of its developer platform presence.
      const role = await deps.membership.roleFor(caller.token, identityOrgId, caller.userId)
      if (!permits(role, ADMIN_ROLES)) throw new ForbiddenError('an owner or admin of the organisation')

      const org = await enrolOrg(deps.sql, {
        identityOrgId,
        name: requireString(body, 'name'),
        slug: requireString(body, 'slug'),
      })
      return { status: 201, body: { organisation: org } }
    }),

    /**
     * Resolve an identity organisation to its developer-platform enrolment.
     *
     * **The read that stops a console using a mutation as a query.** Before this route the only way
     * to answer "which developer organisation am I in?" was to re-POST `/v1/organisations` and read
     * what came back — idempotent, and therefore harmless, and still a write issued to ask a
     * question. A console that has to mutate to read is one keystroke away from mutating when it
     * meant to read.
     *
     * **It cannot enumerate.** The lookup key is the IDENTITY organisation id, which the caller has
     * to already hold, and authority is asked of identity with the caller's own token before the
     * row is read at all — so this route answers nothing that `authoriseOrg` would not, and a
     * non-member gets the same 404 for "you are not a member" and "there is no such organisation"
     * that identity itself gives. Preserving that ambiguity is the point: resolving it would turn
     * devplatform into an oracle for organisations identity deliberately hides.
     *
     * A MEMBER of an organisation that has never been enrolled gets `200 { organisations: [] }`
     * rather than a 404, and the difference matters to the console: "you are in this company but it
     * has no developer platform presence yet" is an enrolment button, whereas a 404 is a dead end.
     * It leaks nothing — identity has already confirmed the caller is a member.
     */
    define('GET', '/v1/organisations', async (ctx, deps) => {
      const caller = await authenticateUser(ctx, deps)
      const identityOrgId = (ctx.url.searchParams.get('identityOrgId') ?? '').trim()
      if (identityOrgId === '') {
        throw new BadRequestError(
          'identityOrgId is required: this route resolves ONE identity organisation to its ' +
            'enrolment. There is no listing, because this service holds no membership rows to list from',
        )
      }
      const role = await deps.membership.roleFor(caller.token, identityOrgId, caller.userId)
      if (!permits(role, READ_ROLES)) throw new NotFoundError('no such developer organisation')
      const org = await findOrgByIdentityId(deps.sql, identityOrgId)
      return { status: 200, body: { organisations: org ? [org] : [] } }
    }),

    define('GET', '/v1/organisations/:id', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      await authoriseOrg(ctx, deps, id, 'read')
      const org = await findOrg(deps.sql, id)
      if (!org) throw new NotFoundError('no such developer organisation')
      return { status: 200, body: { organisation: org } }
    }),

    define('GET', '/v1/organisations/:id/projects', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      await authoriseOrg(ctx, deps, id, 'read')
      return { status: 200, body: { projects: await listProjects(deps.sql, id) } }
    }),

    /* ---------------------------------------------------------------- projects */

    define('POST', '/v1/projects', async (ctx, deps) => {
      const body = await readJson(ctx.req)
      const orgId = requireString(body, 'orgId')
      const caller = await authoriseOrg(ctx, deps, orgId, 'write')
      return withIdempotentRoute(ctx, deps, '/v1/projects', actorOf(caller), body, async (tx, emit) => {
        const project = await createProject(tx, {
          orgId,
          name: requireString(body, 'name'),
          slug: requireString(body, 'slug'),
        })
        // The project, its two environments and its default quotas are one fact. A project that
        // exists with no quota row is a project whose first request is unmetered.
        await seedDefaultQuotas(tx, {
          projectId: project.id,
          environmentIds: project.environments.map((environment) => environment.id),
          perMinute: deps.defaultQuotaPerMinute,
          perMonth: deps.defaultQuotaPerMonth,
        })
        emitProjectCreated(emit, project, actorOf(caller))
        return { response: { project }, artefactId: project.id }
      })
    }),

    define('GET', '/v1/projects/:id', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      return { status: 200, body: { project } }
    }),

    /* ---------------------------------------------------------------- service accounts */

    /**
     * Not wrapped: `service_accounts_name_uniq` makes `(project, name)` the natural key and
     * `createServiceAccount` is `on conflict do nothing` then read, so a retry returns the first
     * account rather than creating a second.
     */
    define('POST', '/v1/projects/:id/service-accounts', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      const body = await readJson(ctx.req)
      const account = await createServiceAccount(deps.sql, {
        projectId: project.id,
        name: requireString(body, 'name'),
        description: optionalString(body, 'description') ?? '',
      })
      return { status: 201, body: { serviceAccount: account } }
    }),

    define('GET', '/v1/projects/:id/service-accounts', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      return { status: 200, body: { serviceAccounts: await listServiceAccounts(deps.sql, project.id) } }
    }),

    /* ---------------------------------------------------------------- keys */

    /**
     * Issue a key. **The one route in this service that returns a usable credential.**
     *
     * Wrapped, and the wrapper is load-bearing rather than decorative: a double-clicked "Create
     * key" without it mints two credentials, and the second is one the developer never sees and
     * therefore never revokes — a live key with no owner.
     *
     * The stored idempotency response deliberately carries the METADATA only. The secret is
     * re-attached to the first response here and nowhere else, so a replay answers with
     * `secretKey: null` rather than handing the credential out a second time from a `jsonb` column
     * that outlives the request.
     */
    define('POST', '/v1/projects/:id/keys', async (ctx, deps) => {
      const { project, caller } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      const body = await readJson(ctx.req)
      const environment = requireEnvironment(body)
      const scopes = requireStringArray(body, 'scopes')

      let minted: string | null = null
      const reply = await withIdempotentRoute(
        ctx,
        deps,
        '/v1/projects/:id/keys',
        actorOf(caller),
        { projectId: project.id, environment, scopes, name: optionalString(body, 'name') ?? '' },
        async (tx, emit) => {
          const issued = await issueApiKey(
            tx,
            {
              projectId: project.id,
              environment,
              name: optionalString(body, 'name') ?? `${environment} key`,
              scopes,
              createdBy: actorOf(caller),
              serviceAccountId: optionalString(body, 'serviceAccountId') ?? null,
              expiresAt: optionalDate(body, 'expiresAt'),
            },
            {
              ...(deps.scryptParams ? { params: deps.scryptParams } : {}),
              ...(deps.kdf ? { kdf: deps.kdf } : {}),
            },
          )
          minted = issued.secretKey
          emitKeyIssued(emit, issued.key)
          deps.metrics.increment('devplatform_keys_issued_total', { environment })
          return { response: { key: issued.key }, artefactId: issued.key.id }
        },
      )

      // Attached to the RESPONSE, never to the stored row. `minted` is null on a replay because the
      // work did not run — which is precisely the behaviour that makes a replay safe.
      const payload = reply.body as Record<string, unknown>
      return {
        ...reply,
        body: {
          ...payload,
          secretKey: minted,
          ...(minted
            ? {
                note: 'This is the only time this secret is shown. It is stored under scrypt and cannot be recovered.',
              }
            : {}),
        },
      }
    }),

    define('GET', '/v1/projects/:id/keys', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      const includeRevoked = ctx.url.searchParams.get('includeRevoked') === 'true'
      const keys = await listApiKeys(deps.sql, project.id, { includeRevoked })
      return { status: 200, body: { keys } }
    }),

    define('GET', '/v1/keys/:id', async (ctx, deps) => {
      const key = await findApiKey(deps.sql, ctx.params['id'] ?? '')
      if (!key) throw new NotFoundError('no such api key')
      await authoriseProject(ctx, deps, key.projectId, 'read')
      return { status: 200, body: { key } }
    }),

    /**
     * Revoke. DELETE, and therefore idempotent by definition — `revokeApiKey` claims with
     * `where revoked_at is null`, so the second call preserves the first call's time and reason and
     * emits no second event.
     *
     * Immediate here; the outbox event is what makes it immediate at the edge, where
     * 11-data-and-contract-strategy.md:363 records a 30-second validation cache.
     */
    define('DELETE', '/v1/keys/:id', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const existing = await findApiKey(deps.sql, id)
      if (!existing) throw new NotFoundError('no such api key')
      const { caller } = await authoriseProject(ctx, deps, existing.projectId, 'write')
      const reason = ctx.url.searchParams.get('reason') ?? ''

      const outcome = await withOutbox(deps.sql, deps.producer, async (tx, emit) => {
        const revoked = await revokeApiKey(tx, { id, revokedBy: actorOf(caller), reason })
        if (!revoked.alreadyRevoked) emitKeyRevoked(emit, revoked.key, actorOf(caller))
        return revoked
      })
      if (!outcome.alreadyRevoked) {
        deps.metrics.increment('devplatform_keys_revoked_total', { source: 'operator' })
      }
      return { status: 200, body: { key: outcome.key, alreadyRevoked: outcome.alreadyRevoked } }
    }),

    /* ---------------------------------------------------------------- quotas and usage */

    /**
     * Set a quota. PUT, and idempotent by natural key — the upsert is on
     * `(environment_id, meter, period)`, so a retry writes the same row.
     *
     * ════════════════════════════════════════════════════════════════════════════════════════
     * **A QUOTA THE QUOTA'D PARTY CAN RAISE IS NOT A QUOTA.**
     *
     * This route used to require only `project:write` and pass any whole number ≥ 1 to `setQuota`,
     * which had no ceiling — so the owner of a project, and equally any API KEY in it carrying
     * `devplatform:write`, could set their own rate limit to whatever they liked. That is not a
     * limit with a weak check on it; it is a limit whose value is chosen by the party it binds.
     * `micro-devportal-web` declined to call this route at all for exactly that reason, which is
     * why the developer console has no quota editor.
     *
     * **THE DIRECTION IS THE AUTHORITY.** Lowering is a customer's own safety feature — a
     * developer capping their test environment so a runaway loop cannot burn their month's
     * allowance is doing the platform's work for it, and making that need an operator would mean
     * nobody ever does it. Raising is the abuse. So:
     *
     *   LOWER or HOLD   `project:write`, exactly as before. Equal is permitted deliberately: PUT
     *                   is idempotent by natural key and a retry that 403'd would make the
     *                   exemption in `routeidempotency.test.ts` a lie.
     *   RAISE           an operator. `isOperator` — a service token carrying `devplatform:admin`,
     *                   or a user with the platform role `admin`.
     *   CREATE          an operator. A missing row is UNLIMITED, not "zero": `quotasFor` returns
     *                   nothing and `consumeAll` over an empty list allows everything. Treating
     *                   absence as infinity and calling any finite value a reduction would hand
     *                   back the whole defect through the environments that have no row.
     *
     * **AND THE VALUE IS BOUNDED IN THE SCHEMA.** `quotas_max_within_ceiling` (migration 9) refuses
     * a per-minute quota above 10,000,000 and anything else above 10,000,000,000, whatever write
     * path produced it. The check here is the authority; the CHECK is the bound, and it holds
     * against a caller with a database connection, which this handler does not.
     * ════════════════════════════════════════════════════════════════════════════════════════
     */
    define('PUT', '/v1/projects/:id/quotas', async (ctx, deps) => {
      const caller = await authenticateAny(ctx, deps)
      const body = await readJson(ctx.req)
      const environment = requireEnvironment(body)
      const period = requireString(body, 'period')
      if (!isPeriod(period)) throw new BadRequestError('period must be minute, hour, day or month')
      const maxUnits = body['maxUnits']
      if (typeof maxUnits !== 'number') throw new BadRequestError('maxUnits must be a number')

      const operator = isOperator(caller)
      let project: Project
      if (operator) {
        // No membership check. An operator setting a customer's limit is the platform acting on
        // the customer, and requiring membership would mean joining every organisation to do it.
        const found = await findProject(deps.sql, requireUuid(ctx.params['id'] ?? '', 'project id'))
        if (!found) throw new NotFoundError('no such project')
        project = found
      } else if (caller.kind === 'service') {
        // A service token with no operator scope. Not "close enough" — see the file header.
        throw new ForbiddenError(`${ADMIN_SCOPE} or role:admin`)
      } else {
        ;({ project } = await authoriseProjectAs(caller, deps, ctx.params['id'] ?? '', 'write'))
      }

      const target = await findEnvironment(deps.sql, project.id, environment)
      if (!target) throw new NotFoundError('no such project environment')

      if (!operator) {
        const current = await findQuota(deps.sql, target.id, period)
        if (!current) {
          throw new ForbiddenError(
            `${ADMIN_SCOPE} or role:admin — this environment has no ${period} quota, and creating ` +
              'one is an operator decision. A project:write caller may only lower a limit that exists',
          )
        }
        if (maxUnits > current.maxUnits) {
          throw new ForbiddenError(
            `${ADMIN_SCOPE} or role:admin — a project:write caller may lower a quota (currently ` +
              `${current.maxUnits} per ${period}) but never raise it`,
          )
        }
      }

      const quota = await setQuota(deps.sql, {
        projectId: project.id,
        environmentId: target.id,
        period,
        maxUnits,
      })
      return { status: 200, body: { quota, ceiling: MAX_UNITS_CEILING[period] } }
    }),

    define('GET', '/v1/projects/:id/quotas', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      const quotas = await listQuotas(deps.sql, project.id)
      const windows: Record<string, unknown> = {}
      for (const environment of project.environments) {
        windows[environment.name] = await currentUsage(deps.sql, environment.id)
      }
      return { status: 200, body: { quotas, current: windows } }
    }),

    define('GET', '/v1/projects/:id/usage', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      const usage = await listUsage(deps.sql, project.id, {
        limit: clampLimit(ctx.url.searchParams.get('limit'), 200, 1_000),
      })
      return { status: 200, body: { usage } }
    }),

    /* ---------------------------------------------------------------- webhooks */

    define('POST', '/v1/projects/:id/webhook-endpoints', async (ctx, deps) => {
      const { project, caller } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      const body = await readJson(ctx.req)
      const environment = requireEnvironment(body)
      const target = await findEnvironment(deps.sql, project.id, environment)
      if (!target) throw new NotFoundError('no such project environment')

      let secret: string | null = null
      const reply = await withIdempotentRoute(
        ctx,
        deps,
        '/v1/projects/:id/webhook-endpoints',
        actorOf(caller),
        { projectId: project.id, environment, url: requireString(body, 'url'), topics: requireStringArray(body, 'topics') },
        async (tx, emit) => {
          const created = await createEndpoint(tx, {
            projectId: project.id,
            environmentId: target.id,
            url: requireString(body, 'url'),
            topics: requireStringArray(body, 'topics'),
            description: optionalString(body, 'description') ?? '',
          })
          secret = created.secret
          emitEndpointCreated(emit, created.endpoint, actorOf(caller))
          return { response: { endpoint: created.endpoint }, artefactId: created.endpoint.id }
        },
      )
      // Same rule as a key: the secret is attached to the response, never to the stored row.
      return { ...reply, body: { ...(reply.body as Record<string, unknown>), secret } }
    }),

    define('GET', '/v1/projects/:id/webhook-endpoints', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      return { status: 200, body: { endpoints: await listEndpoints(deps.sql, project.id) } }
    }),

    /**
     * Rotate the signing secret. Wrapped, because a retry without it mints a second secret and
     * retires the one the customer has just been shown but has not yet deployed.
     */
    define('POST', '/v1/webhook-endpoints/:id/rotate-secret', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const endpoint = await findEndpoint(deps.sql, id)
      if (!endpoint) throw new NotFoundError('no such webhook endpoint')
      const { caller } = await authoriseProject(ctx, deps, endpoint.projectId, 'write')

      let secret: string | null = null
      const reply = await withIdempotentRoute(
        ctx,
        deps,
        '/v1/webhook-endpoints/:id/rotate-secret',
        actorOf(caller),
        { endpointId: id },
        async (tx) => {
          secret = await rotateSecret(tx, id, deps.webhookRotationOverlapMinutes)
          return { response: { endpointId: id, overlapMinutes: deps.webhookRotationOverlapMinutes }, artefactId: id }
        },
      )
      return { ...reply, body: { ...(reply.body as Record<string, unknown>), secret } }
    }),

    /**
     * Disable an endpoint. Deliveries stop; the endpoint, its secrets and its history survive.
     *
     * The pair with `/enable` below. Disabling used to be the only half that existed — this handler
     * passed `true` unconditionally and there was no inverse — so the only way back was to DELETE
     * the endpoint and create a new one, which mints a new signing secret, drops the delivery
     * history and requires the subscriber to redeploy. An endpoint is disabled DURING an incident,
     * which is precisely the hour in which "you must now rotate your webhook secret" is the worst
     * possible answer.
     */
    define('POST', '/v1/webhook-endpoints/:id/disable', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const endpoint = await findEndpoint(deps.sql, id)
      if (!endpoint) throw new NotFoundError('no such webhook endpoint')
      await authoriseProject(ctx, deps, endpoint.projectId, 'write')
      // A state transition claimed on a column; the second attempt writes the same value. There is
      // no second artefact a retry could create.
      return { status: 200, body: { endpoint: await setEndpointDisabled(deps.sql, id, true) } }
    }),

    /**
     * Re-enable it. `disabled_at` back to null, and the endpoint resumes receiving.
     *
     * A separate route rather than a `{ disabled: boolean }` body on one, because the two are not
     * equally consequential and a boolean makes them look it: one stops a customer's integration
     * and the other starts it, and a client that inverted the flag would silently do the opposite
     * of what its operator intended. Two verbs cannot be inverted.
     *
     * Deliveries enqueued while it was disabled are NOT replayed — `enqueueDeliveries` selects
     * `where e.disabled_at is null` (`webhooks.ts:380`), so nothing was queued. That is stated
     * because the
     * opposite is the reasonable assumption, and an operator who assumed it would wait for a flood
     * that never comes.
     */
    define('POST', '/v1/webhook-endpoints/:id/enable', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const endpoint = await findEndpoint(deps.sql, id)
      if (!endpoint) throw new NotFoundError('no such webhook endpoint')
      await authoriseProject(ctx, deps, endpoint.projectId, 'write')
      // Same shape as `/disable`: a state transition writing a fixed value, so the second attempt
      // writes the same value and creates no second artefact.
      return { status: 200, body: { endpoint: await setEndpointDisabled(deps.sql, id, false) } }
    }),

    define('DELETE', '/v1/webhook-endpoints/:id', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const endpoint = await findEndpoint(deps.sql, id)
      if (!endpoint) throw new NotFoundError('no such webhook endpoint')
      await authoriseProject(ctx, deps, endpoint.projectId, 'write')
      await deleteEndpoint(deps.sql, id)
      return { status: 200, body: { deleted: true } }
    }),

    define('GET', '/v1/webhook-endpoints/:id/deliveries', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const endpoint = await findEndpoint(deps.sql, id)
      if (!endpoint) throw new NotFoundError('no such webhook endpoint')
      await authoriseProject(ctx, deps, endpoint.projectId, 'read')
      return { status: 200, body: { deliveries: await listDeliveries(deps.sql, id) } }
    }),

    /* ---------------------------------------------------------------- oauth clients */

    define('POST', '/v1/projects/:id/oauth-clients', async (ctx, deps) => {
      const { project, caller } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      const body = await readJson(ctx.req)

      let clientSecret: string | null = null
      const reply = await withIdempotentRoute(
        ctx,
        deps,
        '/v1/projects/:id/oauth-clients',
        actorOf(caller),
        {
          projectId: project.id,
          name: requireString(body, 'name'),
          redirectUris: requireStringArray(body, 'redirectUris'),
          scopes: requireStringArray(body, 'scopes'),
        },
        async (tx) => {
          const registered = await registerClient(
            tx,
            {
              projectId: project.id,
              name: requireString(body, 'name'),
              redirectUris: requireStringArray(body, 'redirectUris'),
              scopes: requireStringArray(body, 'scopes'),
            },
            {
              ...(deps.scryptParams ? { params: deps.scryptParams } : {}),
              ...(deps.kdf ? { kdf: deps.kdf } : {}),
            },
          )
          clientSecret = registered.clientSecret
          return { response: { client: registered.client }, artefactId: registered.client.id }
        },
      )
      return { ...reply, body: { ...(reply.body as Record<string, unknown>), clientSecret } }
    }),

    define('GET', '/v1/projects/:id/oauth-clients', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      return { status: 200, body: { clients: await listClients(deps.sql, project.id) } }
    }),

    define('DELETE', '/v1/oauth-clients/:id', async (ctx, deps) => {
      const id = ctx.params['id'] ?? ''
      const rows = await deps.sql<{ project_id: string }[]>`
        select project_id from oauth_clients where id = ${id}
      `
      const row = rows[0]
      if (!row) throw new NotFoundError('no such oauth client')
      await authoriseProject(ctx, deps, row.project_id, 'write')
      return { status: 200, body: { client: await revokeClient(deps.sql, id) } }
    }),

    /* ---------------------------------------------------------------- the directory */

    /** Public. `listDirectory` filters to `status = 'listed'` inside the query, not at the caller. */
    define('GET', '/v1/apps', async (ctx, deps) => ({
      status: 200,
      body: { applications: await listDirectory(deps.sql, { limit: clampLimit(ctx.url.searchParams.get('limit'), 100, 500) }) },
    })),

    /**
     * The review queue. Operator only.
     *
     * **Declared BEFORE `/v1/apps/:slug`, and the shadowing is impossible rather than remembered.**
     * The router takes the first route whose pattern matches (`createServer`, above), so a literal
     * segment has to precede the parameterised one — an ordering somebody will eventually undo
     * while tidying. `applications_slug_not_reserved` (migration 9) refuses `pending` as a slug at
     * the database, so there is no listing this route can shadow even if it is moved.
     *
     * It exists because the approval route below is otherwise unaddressable: it is keyed by project
     * id, an operator is not a member of the project's organisation and so cannot read it through
     * `GET /v1/projects/:id/application`, and `GET /v1/apps` shows only what is already listed. An
     * approval route nobody can find the subject of is a route nothing calls, which is the defect
     * this whole change exists to remove.
     */
    define('GET', '/v1/apps/pending', async (ctx, deps) => {
      requireOperator(await authenticateAny(ctx, deps))
      const applications = await listForReview(deps.sql, {
        limit: clampLimit(ctx.url.searchParams.get('limit'), 100, 500),
      })
      return { status: 200, body: { applications } }
    }),

    define('GET', '/v1/apps/:slug', async (ctx, deps) => {
      const application = await findListedApplication(deps.sql, ctx.params['slug'] ?? '')
      if (!application) throw new NotFoundError('no such application')
      return { status: 200, body: { application } }
    }),

    /** PUT, upserting on `project_id` — one listing per project, so a retry updates. */
    define('PUT', '/v1/projects/:id/application', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      const body = await readJson(ctx.req)
      const application = await upsertApplication(deps.sql, {
        projectId: project.id,
        slug: requireString(body, 'slug'),
        name: requireString(body, 'name'),
        tagline: optionalString(body, 'tagline') ?? '',
        description: optionalString(body, 'description') ?? '',
        homepageUrl: optionalString(body, 'homepageUrl') ?? null,
      })
      return { status: 200, body: { application } }
    }),

    define('GET', '/v1/projects/:id/application', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'read')
      const application = await findApplicationByProject(deps.sql, project.id)
      if (!application) throw new NotFoundError('this project has no application listing')
      return { status: 200, body: { application } }
    }),

    /** A state transition claimed with `where status in (…)`; the second attempt matches no row. */
    define('POST', '/v1/projects/:id/application/submit', async (ctx, deps) => {
      const { project } = await authoriseProject(ctx, deps, ctx.params['id'] ?? '', 'write')
      return { status: 200, body: { application: await submitForReview(deps.sql, project.id) } }
    }),

    /**
     * The decision. Operator only — the transition that completes the lifecycle.
     *
     * `setApplicationStatus` was written on the first day and **called by nothing**: it was
     * imported by this file and never referenced, so a developer could submit a listing and no
     * caller in the estate could approve one. The directory route existed, the submit route
     * existed, and the only path from `in_review` to `listed` was a hand-written UPDATE — which is
     * how `server.test.ts` proved the directory worked, and why nobody noticed.
     *
     * Not `project:write`, at any strength. A directory a developer can publish to unilaterally is
     * a directory that eventually hosts a phishing page wearing this platform's chrome, and the
     * consent screen a user reads before granting an OAuth client authority is rendered from
     * exactly this row.
     *
     * The legal transitions are `applications.ts`'s, claimed in the UPDATE: a status that is not an
     * operator's to set is a 400, and a status that is theirs but unreachable from where the row
     * currently is, is a 409 naming both. `rejected` is one of them, and it is a different fact
     * from `delisted` — see that file's header.
     */
    define('PUT', '/v1/projects/:id/application/status', async (ctx, deps) => {
      requireOperator(await authenticateAny(ctx, deps))
      const body = await readJson(ctx.req)
      const status = requireString(body, 'status')
      if (!isApplicationStatus(status) || !OPERATOR_STATUSES.includes(status)) {
        throw new BadRequestError(`status must be one of ${OPERATOR_STATUSES.join(', ')}`)
      }
      const projectId = requireUuid(ctx.params['id'] ?? '', 'project id')
      const application = await setApplicationStatus(deps.sql, projectId, status)
      ctx.log.info('an application status was decided', { projectId, status })
      return { status: 200, body: { application } }
    }),

    /* ---------------------------------------------------------------- internal */

    /**
     * Credential introspection for the estate.
     *
     * This is the route the gateway — or any service that accepts a devplatform key — calls to turn
     * a presented `cfk_…` string into a principal. It is `/internal`, which `policy.yml` refuses
     * from outside, AND it requires a service token carrying `devplatform:introspect`: two controls,
     * because the first is a deployment fact and the second is a code fact, and neither alone
     * survives a gateway misconfiguration.
     *
     * A refusal is a 200 with `{ ok: false }` rather than a 401. The CALLER's credential was fine;
     * the credential it asked about was not, and conflating the two makes a caller retry its own
     * service token.
     */
    define('POST', '/internal/keys/verify', async (ctx, deps) => {
      await authenticateService(ctx, deps, INTROSPECT_SCOPE)
      const body = await readJson(ctx.req)
      const presented = requireString(body, 'key')
      const outcome = await authenticateKey(deps.sql, presented, {
        ...(deps.kdf ? { kdf: deps.kdf } : {}),
        ...(deps.scryptParams ? { params: deps.scryptParams } : {}),
      })
      if (!outcome.ok) {
        deps.metrics.increment('devplatform_key_refusals_total', { reason: outcome.reason })
        // The reason is NOT returned. An internal caller does not need it and a gateway that logged
        // it would put the distinction back into a place an attacker can observe through timing of
        // downstream behaviour.
        return { status: 200, body: { ok: false } }
      }
      void touchLastUsed(deps.sql, outcome.key.id).catch(() => undefined)
      return { status: 200, body: { ok: true, principal: introspect(outcome.key, outcome.orgId) } }
    }),

    /** The client-secret check identity's token endpoint would call. See `oauth.ts`. */
    define('POST', '/internal/oauth/verify', async (ctx, deps) => {
      await authenticateService(ctx, deps, INTROSPECT_SCOPE)
      const body = await readJson(ctx.req)
      const outcome = await verifyClientSecret(
        deps.sql,
        requireString(body, 'clientId'),
        requireString(body, 'clientSecret'),
        {
          ...(deps.kdf ? { kdf: deps.kdf } : {}),
          ...(deps.scryptParams ? { params: deps.scryptParams } : {}),
        },
      )
      if (!outcome.ok) return { status: 200, body: { ok: false } }
      return {
        status: 200,
        body: {
          ok: true,
          client: {
            clientId: outcome.client.clientId,
            projectId: outcome.client.projectId,
            scopes: outcome.client.scopes,
            redirectUris: outcome.client.redirectUris,
          },
        },
      }
    }),

    /**
     * Meter one call. Called by the gateway or by a service that has accepted a devplatform key.
     *
     * **This is where the quota is actually enforced, and it is enforced in Postgres.** The counter
     * is a row and the increment is one guarded UPDATE — see `quotas.ts`. An in-memory counter here
     * would be per-replica, and a per-replica quota is not a quota.
     */
    define('POST', '/internal/usage', async (ctx, deps) => {
      await authenticateService(ctx, deps, INTROSPECT_SCOPE)
      const body = await readJson(ctx.req)
      const key = await findApiKey(deps.sql, requireString(body, 'keyId'))
      if (!key) throw new NotFoundError('no such api key')

      const quotas = await quotasFor(deps.sql, key.environmentId, API_REQUESTS)
      const decision = await consumeAll(deps.sql, quotas, 1)
      const status = typeof body['status'] === 'number' ? body['status'] : decision.allowed ? 200 : 429

      await recordUsage(deps.sql, {
        projectId: key.projectId,
        environmentId: key.environmentId,
        apiKeyId: key.id,
        route: (optionalString(body, 'route') ?? 'unknown').slice(0, 200),
        method: (optionalString(body, 'method') ?? 'GET').slice(0, 10),
        status,
      })

      if (!decision.allowed && decision.exceeded) {
        const exceeded = decision.exceeded
        deps.metrics.increment('devplatform_quota_refusals_total', { period: exceeded.period })
        const quota = quotas.find((candidate) => candidate.period === exceeded.period)
        if (quota) {
          await withOutbox(deps.sql, deps.producer, async (_tx, emit) => {
            emitQuotaExceeded(emit, quota, exceeded)
          })
        }
        return {
          status: 200,
          body: { allowed: false, period: exceeded.period, used: exceeded.used, limit: exceeded.limit },
        }
      }
      return { status: 200, body: { allowed: true, outcomes: decision.outcomes } }
    }),

    /* ---------------------------------------------------------------- the inbox */

    /**
     * The internal inbox. Signature verified over the RAW BYTES before anything is parsed.
     *
     * Exempt from the idempotency wrapper because the inbox IS its idempotency: `withInbox`
     * deduplicates on the source event id and shares one transaction with the handler, so a handler
     * that fails leaves no row and the redelivery is processed rather than swallowed.
     */
    define('POST', '/v1/events', async (ctx, deps) => {
      const raw = await readRaw(ctx.req)
      const signature = verifyInbound(raw, headerOf(ctx.req, SIGNATURE_HEADER), deps.ingestSecrets)
      if (!signature.ok) {
        deps.metrics.increment('devplatform_events_rejected_total', { reason: 'bad_signature' })
        ctx.log.warn('an inbound event failed its signature check', { reason: signature.reason })
        return errorReply(401, 'bad_signature', 'the event signature did not verify', ctx.requestId)
      }

      let envelope: Record<string, unknown>
      try {
        const parsed: unknown = JSON.parse(raw.toString('utf8'))
        if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
          throw new BadRequestError('an event envelope must be a JSON object')
        }
        envelope = parsed as Record<string, unknown>
      } catch {
        deps.metrics.increment('devplatform_events_rejected_total', { reason: 'malformed' })
        throw new BadRequestError('the event body is not valid JSON')
      }

      const topic = typeof envelope['topic'] === 'string' ? envelope['topic'] : ''
      const eventId = typeof envelope['id'] === 'string' ? envelope['id'] : ''
      if (!UUID.test(eventId)) {
        deps.metrics.increment('devplatform_events_rejected_total', { reason: 'malformed' })
        throw new BadRequestError('an event envelope must carry a uuid id')
      }
      if (topic !== ORG_DELETED_TOPIC && topic !== USER_DELETED_TOPIC) {
        // Accepted and ignored, with a 202. A 4xx would make the producer's relay retry an event it
        // is correct to send and we are correct not to act on, for ever.
        deps.metrics.increment('devplatform_events_rejected_total', { reason: 'not_subscribed' })
        return { status: 202, body: { status: 'ignored', topic } }
      }

      const payload =
        typeof envelope['payload'] === 'object' && envelope['payload'] !== null
          ? (envelope['payload'] as Record<string, unknown>)
          : {}
      const identityOrgId = typeof payload['organisationId'] === 'string' ? payload['organisationId'] : null
      if (topic === ORG_DELETED_TOPIC && !identityOrgId) {
        throw new BadRequestError('the event payload must name an organisationId')
      }

      const done = deps.lifecycle.track()
      try {
        const outcome = await withInbox(deps.sql, topic, eventId, async (tx) => {
          if (topic === USER_DELETED_TOPIC) {
            // A deleted user is not a deleted organisation. Their keys were issued TO the
            // organisation and remain the organisation's — revoking them here would take a
            // company's production integration down because an employee closed their account.
            return { revoked: 0, suspended: false }
          }
          const org = await findOrgByIdentityId(tx, identityOrgId!)
          if (!org) return { revoked: 0, suspended: false }
          await setOrgStatus(tx, org.id, 'suspended')
          const revoked = await revokeOrgKeys(tx, org.id, 'system:identity', 'organisation deleted')
          for (const key of revoked) emitKeyRevoked((event) => void emitInTx(tx, deps.producer, event), key, 'system:identity')
          return { revoked: revoked.length, suspended: true }
        })
        if (outcome.status === 'processed' && outcome.value.revoked > 0) {
          deps.metrics.increment(
            'devplatform_keys_revoked_total',
            { source: 'event' },
            outcome.value.revoked,
          )
          ctx.log.info('organisation suspended and its keys revoked', {
            topic,
            revoked: outcome.value.revoked,
          })
        }
        return {
          status: 202,
          body: {
            status: outcome.status,
            ...(outcome.status === 'processed' ? { ...outcome.value } : {}),
          },
        }
      } finally {
        done()
      }
    }),
  ]
}

/* ------------------------------------------------------------------ helpers */

/**
 * Write an outbox row on a transaction the caller already holds.
 *
 * Used by the inbox handler, which is inside `withInbox`'s transaction rather than `withOutbox`'s
 * and therefore has an `Emit` to satisfy but no collector behind it. The insert is awaited by the
 * enclosing transaction, so it commits or rolls back with the suspension it announces.
 */
function emitInTx(tx: Tx, producer: string, event: Parameters<Emit>[0]): Promise<void> {
  return tx`
    insert into outbox (topic, key, producer, version, actor, correlation_id, payload)
    values (${event.topic}, ${event.key}, ${producer}, ${event.version ?? 1},
            ${event.actor ?? null}, ${event.correlationId ?? null},
            ${tx.json(event.payload as Record<string, never>)})
  `.then(() => undefined)
}

/**
 * The idempotency wrapper. Every mutating route either uses it or is named in
 * `routeidempotency.test.ts` with the reason it is safe without one.
 *
 * The work runs inside `withIdempotency`'s transaction AND inside an outbox collection, so the
 * artefact, its idempotency claim and its event are one commit. Three separate transactions here
 * would give three ways to end up with two of the three.
 */
async function withIdempotentRoute(
  ctx: RequestContext,
  deps: ServerDeps,
  route: string,
  principal: string,
  fingerprintSubject: Record<string, unknown>,
  run: (tx: Tx, emit: Emit) => Promise<{ response: Record<string, unknown>; artefactId: string | null }>,
): Promise<Reply> {
  const key = headerOf(ctx.req, IDEMPOTENCY_HEADER)
  if (!key || !SAFE_IDEMPOTENCY_KEY.test(key)) {
    throw new BadRequestError(
      'an Idempotency-Key header of 8 to 200 characters is required on every mutating request',
    )
  }
  const outcome = await withIdempotency<Record<string, unknown>>(deps.sql, {
    principal,
    route,
    clientKey: key,
    requestHash: requestFingerprint(fingerprintSubject),
    run: async (tx) => {
      const pending: Parameters<Emit>[0][] = []
      const result = await run(tx, (event) => {
        pending.push(event)
      })
      for (const event of pending) await emitInTx(tx, deps.producer, event)
      return result
    },
  })
  return {
    status: outcome.replayed ? 200 : 201,
    // Said on the wire, so a client can tell "I created this" from "this already existed". A client
    // that cannot tell writes its own duplicate detection, badly.
    body: { ...outcome.result, replayed: outcome.replayed },
  }
}

function requireEnvironment(body: Record<string, unknown>): KeyEnvironment {
  const value = body['environment']
  if (typeof value !== 'string' || !isKeyEnvironment(value)) {
    throw new BadRequestError("environment must be 'live' or 'test'")
  }
  return value
}

/**
 * A path segment that is about to be compared against a `uuid` column.
 *
 * Postgres answers `22P02 invalid input syntax for type uuid` for a segment that is not one, which
 * arrives here as an unhandled failure and leaves as a 500 — a malformed URL reported as a server
 * fault. The two operator routes added with this change use it.
 *
 * **The routes that predate it do not, and that is a defect, reported rather than changed.**
 * `GET /v1/projects/not-a-uuid` is a 500 today (`authoriseProject` → `findProject`), as are the
 * key, endpoint and client reads. Changing the status code of the shipped routes is a different
 * decision from the four this change is about, and `micro-devportal-web` pins citations into every
 * one of them.
 *
 * THE COUNT IS NOT WRITTEN DOWN HERE, deliberately. It said "eleven"; a re-count found nineteen
 * routes carrying an `:id`, and a third reading reported twenty-five. A number in a comment that
 * three readers disagree about is worse than no number, because work gets scoped against it. Count
 * it when you need it, and the command is the honest form of the claim:
 *
 *     grep -oE "'/v1/[^']*:id[^']*'" src/server.ts | sort -u | wc -l
 */
function requireUuid(value: string, what: string): string {
  if (!UUID.test(value)) throw new BadRequestError(`${what} must be a uuid`)
  return value
}

function requireString(body: Record<string, unknown>, field: string): string {
  const value = body[field]
  if (typeof value !== 'string' || value.trim() === '') {
    throw new BadRequestError(`${field} is required`)
  }
  return value
}

function optionalString(body: Record<string, unknown>, field: string): string | undefined {
  const value = body[field]
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

function optionalDate(body: Record<string, unknown>, field: string): Date | null {
  const value = body[field]
  if (typeof value !== 'string' || value.trim() === '') return null
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) throw new BadRequestError(`${field} must be an ISO 8601 timestamp`)
  return parsed
}

function requireStringArray(body: Record<string, unknown>, field: string): readonly string[] {
  const value = body[field]
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw new BadRequestError(`${field} must be an array of strings`)
  }
  return value as string[]
}

function clampLimit(raw: string | null, fallback: number, max: number): number {
  const n = raw === null ? fallback : Number(raw)
  if (!Number.isInteger(n) || n < 1) return fallback
  return Math.min(n, max)
}

async function readRaw(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Refused, not truncated. A truncated body is a different body, and its signature would not
    // verify anyway — but the check is here so an oversized POST cannot buffer unboundedly first.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('the request body is too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks)
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const raw = await readRaw(req)
  if (raw.length === 0) return {}
  let parsed: unknown
  try {
    parsed = JSON.parse(raw.toString('utf8'))
  } catch {
    throw new BadRequestError('the request body is not valid JSON')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new BadRequestError('the request body must be a JSON object')
  }
  return parsed as Record<string, unknown>
}

function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const hasBody = reply.text !== undefined || reply.body !== undefined
  const payload = reply.text ?? (hasBody ? `${JSON.stringify(reply.body ?? {})}\n` : '')
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // A response from this service may contain a credential exactly once, and an intermediary that
    // cached it would serve it to the next caller.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}

/** Refresh the gauges once per scrape. Bounded queries only. */
export function scrapeRefresh(deps: { readonly sql: Db; readonly metrics: Metrics }): () => Promise<void> {
  return async () => {
    deps.metrics.set('devplatform_up', 1)
  }
}
