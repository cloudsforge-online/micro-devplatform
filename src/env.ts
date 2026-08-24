/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repository declares the variables it needs; the deploy
 * provides exactly those" — is a property of this file. Every variable this service reads is named
 * here and nowhere else.
 *
 * Two behaviours are copied from the siblings, deliberately:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic, and a placeholder that boots is a placeholder that reaches production.
 *      `.env.example` ships `CHANGE_ME`, and `CHANGE_ME` does not boot.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT THIS SERVICE DELIBERATELY HAS NO VARIABLE FOR.**
 *
 * There is no `DEVPLATFORM_ADMIN_TOKEN`, no break-glass credential and no reveal switch. Lantern
 * has one because its `/metrics` must stay readable when identity is down; the equivalent here
 * would be a static string that can read or issue credentials, which is the shape of the two
 * omnipotent service tokens SD-05 exists to retire.
 *
 * There is no `PUBLIC_API_BASE_URL` and no path-prefix variable either, and that absence is a
 * finding rather than an oversight: `deploy/gateway/dynamic/policy.yml` mounts no public API at
 * all (it carries CORS, security headers and the `/internal` refusal, and nothing else), so any
 * value configured here would be a URL this service invented. See the README.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { hostname } from 'node:os'
import { assertGeneratedSecret, assertGeneratedSecretList } from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a
 * migration advisory lock.
 */
export const SERVICE = 'devplatform'

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * The estate's shared event-bus HMAC key, held to a SHAPE rather than to a deny-list.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE LOCAL `requiredSecret` AND ITS `PLACEHOLDERS` SET USED TO LIVE HERE, AND THEY ARE GONE
 * RATHER THAN KEPT IN FRONT OF THIS.**
 *
 * They refused a fixed list of exact strings plus anything under 24 characters. The value that sat
 * on 54 lines of a PUBLIC compose file — `estate-only-outbox-secret-00000000000000` — was on no
 * list and was 40 characters, so it passed here and in every other service in the estate
 * (micro-org #142). A check that could not fail read as the absence of a problem, which is worse
 * than no check at all.
 *
 * A deny-list of exact strings cannot work: the next placeholder somebody writes is, by definition,
 * not on it. `assertGeneratedSecret` asserts what a placeholder cannot have — the base64 or hex
 * alphabet (no hyphens; every placeholder this estate wrote had one), 32 decoded BYTES rather than
 * 24 keystrokes, and a measured Shannon entropy floor. Every string the old set held is refused by
 * that, so nothing is lost by deleting it, and keeping it would leave a weaker rule for the next
 * variable to reach for.
 *
 * `required` rather than a length check first, deliberately: the weaker checks are a strict subset
 * of the stronger ones, and running them first would answer a 40-character placeholder with "must
 * be at least 24 characters" — true, useless, and pointing the operator at the wrong property.
 *
 * There is no NODE_ENV exemption and no escape hatch, so CI generates a real value per run rather
 * than being let through. It throws `SecretError` rather than `EnvError`, which is deliberate: the
 * class says a value failed the SHAPE check rather than this file's own parsing, and `fatalConfig`
 * below reads `err.message` off `unknown`, so the boot line is identical either way.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
function requiredSigningSecret(source: Source, name: string): string {
  const value = required(source, name)
  assertGeneratedSecret(name, value)
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/**
 * The secrets the inbound event route accepts, newest first.
 *
 * A LIST, not a value, because rotation without an overlap window means every producer must
 * change secret in the same instant as this service does, and that instant does not exist during
 * a rolling deploy. The same shape as `activity`'s `ACTIVITY_INGEST_SECRETS`.
 *
 * **Every entry faces exactly the bar a single secret faces — `assertGeneratedSecretList` is
 * `assertGeneratedSecret` per entry, and there is no weaker rule for the outgoing key.** In a
 * rotation overlap window the outgoing key is the one an attacker already holds if it leaked, and
 * "just for the drain" is exactly how a placeholder survives the rotation meant to remove it.
 *
 * The local placeholder and length loop that used to sit here went with `requiredSecret`, for the
 * reason recorded above it. What is kept is what the shape check does not know about: the
 * empty-list refusal, whose message names this service's own variable, and the duplicate refusal
 * below.
 */
export function parseSecretList(raw: string, name: string): readonly string[] {
  const entries = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  if (entries.length === 0) throw new EnvError(`${name} is required — at least one secret`)
  assertGeneratedSecretList(name, entries)
  if (new Set(entries).size !== entries.length) {
    // A duplicated secret in the list makes the "which key verified this" answer ambiguous, and
    // that answer is what tells an operator whether a rotation has finished.
    throw new EnvError(`${name} lists the same secret twice`)
  }
  return Object.freeze(entries)
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second here fails the build rather than review.
   */
  readonly databaseUrl: string
  /**
   * The TESTNET database, when this deployment serves both networks. Empty means single-network —
   * `networkSql` then holds one handle and REFUSES a testnet request rather than answering it out
   * of mainnet rows (micro-deploy `docs/network-consolidation.md` §2.2).
   */
  readonly databaseUrlTestnet: string
  /**
   * The network to assume when a request carries no `CF-Network`, or empty to refuse. Set for
   * `pnpm dev`, which has no gateway. Never in production, where guessing makes a routing fault a
   * silent cross-network write.
   */
  readonly singleNetwork: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  readonly instanceId: string

  /**
   * Secrets accepted on `POST /v1/events`, the internal inbox.
   *
   * That route consumes `identity.organisation.deleted` and `identity.user.deleted`, which
   * suspend a developer organisation and revoke its keys. Unsigned, it is a
   * revoke-anybody's-credentials endpoint reachable by anything on the app network.
   */
  readonly ingestSecrets: readonly string[]

  /** Signs this service's OWN outbox deliveries to internal subscribers. */
  readonly outboxSigningSecret: string

  /**
   * The default per-environment request quota applied to a new project, per period.
   *
   * A default rather than a hard ceiling: `quotas` rows are per environment and an operator raises
   * one without a deploy. Zero is not expressible — `quotas_max_positive` refuses it — because a
   * quota of zero is a project that cannot make a request, which is a suspension, and a
   * suspension is a status not a limit.
   */
  readonly defaultQuotaPerMinute: number
  readonly defaultQuotaPerMonth: number

  /** How long a rotated webhook secret keeps verifying. */
  readonly webhookRotationOverlapMinutes: number
  /** Deadline on one webhook POST. A slow subscriber must not hold the delivery lease open. */
  readonly webhookDeadlineMs: number
  /** Attempts before a delivery is abandoned and left for an operator to see. */
  readonly webhookMaxAttempts: number

  /** Raw usage events are pruned once rolled up. The rollups are what survive. */
  readonly usageEventRetentionDays: number
  readonly usageRollupRetentionDays: number
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const usageEventRetentionDays = integer(source, 'DEVPLATFORM_USAGE_EVENT_RETENTION_DAYS', 35, 1, 400)
  const usageRollupRetentionDays = integer(source, 'DEVPLATFORM_USAGE_ROLLUP_RETENTION_DAYS', 400, 1, 3_650)
  if (usageRollupRetentionDays < usageEventRetentionDays) {
    // A rollup that expires before the events it summarises is a summary thrown away while its
    // inputs survive — the inversion of what the rollup is for. It also breaks the one commitment
    // 11-data-and-contract-strategy.md makes to developers: usage-gated removal notifies every
    // project that called an endpoint in the last 90 days, and that question is answered here.
    throw new EnvError(
      `DEVPLATFORM_USAGE_ROLLUP_RETENTION_DAYS (${usageRollupRetentionDays}) must be at least ` +
        `DEVPLATFORM_USAGE_EVENT_RETENTION_DAYS (${usageEventRetentionDays}) — a rollup outlives its events`,
    )
  }

  return {
    port: integer(source, 'PORT', 4000, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'DEVPLATFORM_DATABASE_URL'),
    databaseUrlTestnet: optional(source, 'DEVPLATFORM_DATABASE_URL_TESTNET', ''),
    singleNetwork: optional(source, 'CF_NETWORK_SINGLE', ''),
    databasePoolMax: integer(source, 'DEVPLATFORM_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),

    ingestSecrets: parseSecretList(required(source, 'DEVPLATFORM_INGEST_SECRETS'), 'DEVPLATFORM_INGEST_SECRETS'),
    outboxSigningSecret: requiredSigningSecret(source, 'OUTBOX_SIGNING_SECRET'),

    defaultQuotaPerMinute: integer(source, 'DEVPLATFORM_DEFAULT_QUOTA_PER_MINUTE', 600, 1, 10_000_000),
    defaultQuotaPerMonth: integer(source, 'DEVPLATFORM_DEFAULT_QUOTA_PER_MONTH', 1_000_000, 1, 10_000_000_000),

    webhookRotationOverlapMinutes: integer(source, 'DEVPLATFORM_WEBHOOK_ROTATION_OVERLAP_MINUTES', 1_440, 1, 43_200),
    webhookDeadlineMs: integer(source, 'DEVPLATFORM_WEBHOOK_DEADLINE_MS', 5_000, 100, 60_000),
    webhookMaxAttempts: integer(source, 'DEVPLATFORM_WEBHOOK_MAX_ATTEMPTS', 8, 1, 50),

    usageEventRetentionDays,
    usageRollupRetentionDays,
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand, built from a literal rather than routed through the
 * telemetry package: nothing that can itself fail may sit between a configuration error and the
 * report of it.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
