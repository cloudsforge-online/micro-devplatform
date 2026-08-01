/**
 * Run a mutating operation at most once per key.
 *
 * **The shape is the ledger's** (`ledger/src/idempotency.ts`), by way of `market/src/idempotency.ts`.
 * It is inherited rather than reinvented, because the four properties below are the whole of the
 * correctness and each is easy to lose while writing something that looks equivalent:
 *
 *   1. **The claim INSERT and the work share ONE transaction.** The stored response can therefore
 *      never disagree with what actually committed. A design that claims the key in its own
 *      transaction and then does the work has a window in which the key exists and the key
 *      issuance does not — and a retry arriving in that window is answered "already created" for
 *      a credential that was never minted, so the developer holds a key string that authenticates
 *      nothing and has no way to tell that from a bug in their code.
 *   2. **A concurrent duplicate blocks rather than races.** The second INSERT waits on the first
 *      transaction's uncommitted row; when that commits, the duplicate reads the stored response
 *      and replays it. A double-clicked "Create key" can therefore never mint two credentials.
 *   3. **A reused key with a different body is refused, not replayed.** Returning the first
 *      request's answer to a second, different request is worse than an error: the caller believes
 *      the thing it asked for happened. Here that would mean believing a key exists with scopes it
 *      does not have.
 *   4. **A claim with no response yet is "in flight", not "done".** If the original transaction
 *      rolled back between the insert and this read, nothing committed, so the honest answer is
 *      "retry" rather than a guess.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT MAY NOT BE FINGERPRINTED, AND THE DEFECT THAT PROVES IT.**
 *
 * `correlationId` is a trace identifier and it is SUPPOSED to change on every attempt — that is
 * what makes a retry distinguishable from the original in a trace. The ledger fingerprinted the
 * whole request body, `correlationId` included, so a caller doing exactly the right thing — a
 * fresh request id per attempt — was told its idempotency key had been reused with a different
 * payload. Every honest retry would have 409'd in production, and the caller could not tell that
 * apart from a genuine key collision. `micro-wallet` had to carry a correlation id that was stable
 * per operation rather than per attempt to work around it.
 *
 * The regression is pinned by `idempotency.test.ts` in this repository in both directions: a fresh
 * correlation id replays, a genuinely different scope set still 409s. `PER_ATTEMPT_FIELDS` is
 * asserted by name in CI, because the defect is an omission and an omission has no behaviour.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A RESPONSE STORED HERE MUST NEVER CONTAIN A SECRET.** The stored response is a `jsonb` column
 * that outlives the request, and the whole point of this service is that a key's secret exists for
 * one response and then nowhere. So `POST /v1/projects/:id/keys` stores the key's METADATA and the
 * server re-attaches the secret to the first response only; a replay answers with the metadata and
 * `secretKey: null`. `apikeys.ts` does that, and `server.test.ts` proves a replay carries no
 * secret.
 */

import { createHash } from 'node:crypto'
import type { Db, Tx } from './outbox.ts'

/** The claim exists but its transaction has not committed a response yet. The caller retries. */
export class IdempotencyInFlightError extends Error {
  constructor() {
    super('a request with this idempotency key is still in flight; retry shortly')
    this.name = 'IdempotencyInFlightError'
  }
}

/** The same key was presented with a different body. 409, always. */
export class IdempotencyKeyReuseError extends Error {
  constructor() {
    super('this idempotency key was already used with a different request body')
    this.name = 'IdempotencyKeyReuseError'
  }
}

/** Fields that legitimately differ between attempts at the *same* operation. See the header. */
export const PER_ATTEMPT_FIELDS = new Set(['correlationId', 'idempotencyKey', 'requestId'])

/**
 * A stable fingerprint of a request body, so a reused key with a changed payload is caught.
 *
 * Keys are sorted at every depth before hashing. `JSON.stringify` preserves insertion order, so
 * two semantically identical bodies that serialised their fields in a different order would
 * fingerprint differently and a legitimate retry would be rejected as reuse. Sorting removes a
 * class of false 409 that is maddening to diagnose from the caller's side.
 *
 * Arrays are NOT sorted: `['market:read','market:write']` and its reverse are the same scope set,
 * but an array is ordered in general and a fingerprint that reordered one would be wrong for some
 * other field. `validateScopes` normalises the scope list at the boundary instead, which is where
 * the domain knowledge lives.
 */
export function requestFingerprint(value: unknown): string {
  const subject =
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value as Record<string, unknown>).filter(
            ([key]) => !PER_ATTEMPT_FIELDS.has(key),
          ),
        )
      : value
  return createHash('sha256').update(canonicalise(subject)).digest('hex')
}

function canonicalise(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'bigint') return `"${value.toString()}"`
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalise(v)}`).join(',')}}`
}

/**
 * The stored key, namespaced by the calling principal and the route.
 *
 * The route is in the key because the same client key presented to `POST /v1/projects` and to
 * `POST /v1/projects/:id/keys` describes two different operations, and a caller reusing its
 * request id across both is doing something reasonable.
 *
 * The PRINCIPAL is in it because idempotency keys are chosen by callers, and two developers
 * independently choosing `create-2026-08-01` must not collide — one would replay the other's
 * response, which here means being handed another organisation's key metadata.
 */
export function namespacedKey(principal: string, route: string, clientKey: string): string {
  return `${principal}:${route}:${clientKey}`
}

export interface IdempotentOutcome<T> {
  readonly result: T
  readonly replayed: boolean
}

export interface IdempotencyInput<T> {
  readonly principal: string
  readonly route: string
  readonly clientKey: string
  readonly requestHash: string
  /**
   * The work. Returns the response to store and, when the work created one, the artefact id — so
   * the claim row points at the key, project or endpoint it produced and an operator can join a
   * caller's key to what it minted.
   */
  readonly run: (tx: Tx, storedKey: string) => Promise<{ response: T; artefactId: string | null }>
}

export async function withIdempotency<T>(
  sql: Db,
  input: IdempotencyInput<T>,
): Promise<IdempotentOutcome<T>> {
  const key = namespacedKey(input.principal, input.route, input.clientKey)

  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ key: string }[]>`
      insert into idempotency_keys (key, route, request_hash)
      values (${key}, ${input.route}, ${input.requestHash})
      on conflict (key) do nothing
      returning key
    `

    if (claimed.length === 0) {
      // Someone else holds the key. By the time this read runs, their transaction has either
      // committed (so the response is here) or rolled back (so the row is gone).
      const rows = await tx<{ request_hash: string; response: unknown }[]>`
        select request_hash, response from idempotency_keys where key = ${key}
      `
      const existing = rows[0]
      if (!existing) throw new IdempotencyInFlightError()
      if (existing.request_hash !== input.requestHash) throw new IdempotencyKeyReuseError()
      if (existing.response === null || existing.response === undefined) {
        throw new IdempotencyInFlightError()
      }
      return { value: { result: existing.response as T, replayed: true } }
    }

    const { response, artefactId } = await input.run(tx, key)
    await tx`
      update idempotency_keys
         set response = ${tx.json(response as Record<string, never>)}, artefact_id = ${artefactId}
       where key = ${key}
    `
    return { value: { result: response, replayed: false } }
  })

  return outcome.value
}
