/**
 * The API key: its format, its hashing, and its verification.
 *
 * This is the file the rest of the service exists to protect. Everything else here — projects,
 * quotas, webhooks, the directory — is bookkeeping around the one thing devplatform actually
 * issues: a bearer credential that a third party presents to the CloudsForge public API.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FORMAT: PREFIX · ENVIRONMENT · LOOKUP ID · SECRET.**
 *
 *     cfk_live_7k4m2qb9xzr3tvn8_h5w2c...          (four underscore-separated parts)
 *     ─┬─ ─┬── ────────┬─────── ───┬───
 *      │   │           │           └── 32 random bytes, base32. NEVER stored. Hashed with scrypt.
 *      │   │           └── 10 random bytes, base32. Stored in the clear, UNIQUE, indexed.
 *      │   └── `live` or `test`. Which environment the key acts in.
 *      └── The fixed prefix. Three characters that make a leaked key greppable.
 *
 * Each part earns its place:
 *
 *   `cfk`         A fixed, distinctive token so a leaked key is FINDABLE. Secret scanners, log
 *                 pipelines and `git grep` all work on a literal prefix and on nothing else. A
 *                 key that is 60 characters of base64 with no marker is a key nobody can search
 *                 the estate for after an incident.
 *
 *   `live`/`test` Visible to a human at a glance. A test key pasted into a production config and
 *                 a production key pasted into a test fixture are the same class of mistake, and
 *                 the only cheap defence against both is that the string says which it is.
 *
 *   lookup id     **A key must be identifiable without being usable.** This is the property the
 *                 whole format is arranged around, and it buys two distinct things:
 *
 *                   1. A key can be revoked from a log line. Logs record `cfk_live_7k4m2qb9xzr3tvn8`
 *                      — prefix, environment, lookup, and nothing after it — so an operator who
 *                      finds a key in a paste bin or a support ticket can revoke exactly that key
 *                      without ever holding the secret and without asking the developer which one
 *                      it was.
 *                   2. Verification is ONE indexed lookup. Without a lookup id, checking a
 *                      presented key means running the KDF against every row until one matches —
 *                      which is `O(rows)` scrypt invocations per request, i.e. a service that
 *                      gets slower the more customers it has and falls over at the first
 *                      credential-stuffing attempt.
 *
 *   secret        32 bytes from `randomBytes`. Returned exactly once, at creation, and then gone:
 *                 there is no column that could hold it and no route that could return it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE HASH IS SCRYPT, NOT SHA-256, AND THE PARAMETERS ARE RECORDED IN THE ROW.**
 *
 * An API key table is a password table. It holds one high-value secret per row, an attacker who
 * reaches it holds the whole set, and the only thing standing between a dump and a working
 * credential is how expensive one guess is. SHA-256 makes a guess free.
 *
 * The estate already made this decision and already found the defect in the naive version.
 * `identity/src/passwords.ts` records it: Nimbus called `scrypt` at library defaults and
 * stored two hex strings, so nothing in the row said what cost produced them — and a work factor
 * that cannot be raised without a forced reset for every user is a work factor that never gets
 * raised. `verifyPassword` there reads its parameters FROM the row rather than from a constant.
 * This file does the same, with the same `scrypt$N=…,r=…,p=…,keyLen=…` encoding, so a key issued
 * today still verifies after the constant moves and is re-hashed on its next successful use.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A REVOKED KEY AND AN UNKNOWN KEY MUST BE INDISTINGUISHABLE, INCLUDING IN TIMING.**
 *
 * The obvious implementation returns early on a lookup miss and on a revoked row, and runs scrypt
 * only for a live key. That turns response latency into an oracle: a caller holding a stolen key
 * learns from a ~0.1 ms answer that the lookup id does not exist and from a ~60 ms answer that it
 * does — which is enough to enumerate live lookup ids, and enough to tell "this key was revoked"
 * (so the account is real and someone is watching) from "this key never existed".
 *
 * So `verifyPresentedKey` runs the KDF on **every** path, including the miss, against a decoy
 * hash generated at module load. The refusal reason is carried in the return value for the
 * server's own logs and is never rendered into a response: every failure answers 401 with one
 * message. `keys.test.ts` proves the KDF ran on all three paths by counting invocations through
 * an injectable seam — a counter rather than a stopwatch, because a wall-clock assertion on a
 * loaded CI runner is a flaky test, and a flaky security test gets deleted.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from 'node:crypto'
import { promisify } from 'node:util'

/**
 * `promisify` picks the first overload — the one WITHOUT options — so the cost parameters would be
 * silently dropped and every hash would land at library defaults. That is the exact defect
 * `identity/src/passwords.ts` documents. The signature is restated so the compiler enforces
 * that the options object is passed.
 */
const scryptAsync = promisify(scrypt) as (
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
) => Promise<Buffer>

/* ------------------------------------------------------------------ the alphabet */

/**
 * Lowercase RFC 4648 base32 without padding.
 *
 * Chosen over base64url because base64url's alphabet contains `_`, and `_` is the field separator
 * in the key format. A separator that can occur inside a field is a parser that cannot be trusted
 * to split correctly, and a key format whose parse is ambiguous is a lookup that can be steered.
 *
 * Base32 also survives being read aloud, written on a whiteboard and double-clicked as one word,
 * which is what a support conversation about a leaked key actually involves.
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

export function base32Encode(bytes: Uint8Array): string {
  let out = ''
  let buffer = 0
  let bits = 0
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte
    bits += 8
    while (bits >= 5) {
      bits -= 5
      out += ALPHABET[(buffer >> bits) & 31]
    }
  }
  // The trailing partial group is left-aligned and zero-padded, matching RFC 4648's encoding of a
  // final quantum. No `=` padding: it carries no information here and would put a character
  // outside the alphabet into a value that is compared as a string.
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31]
  return out
}

/* ------------------------------------------------------------------ the format */

export const KEY_PREFIX = 'cfk'

/** Which environment a key acts in. Part of the key STRING, not only of the row. */
export type KeyEnvironment = 'live' | 'test'

export const KEY_ENVIRONMENTS: readonly KeyEnvironment[] = Object.freeze(['live', 'test'])

export function isKeyEnvironment(value: string): value is KeyEnvironment {
  return value === 'live' || value === 'test'
}

/** 10 bytes → 16 base32 characters. Enough that a collision is not a thing that happens. */
const LOOKUP_BYTES = 10
/** 32 bytes → 52 base32 characters. 256 bits; the KDF is the cost, this is the entropy. */
const SECRET_BYTES = 32

export const LOOKUP_LENGTH = 16
export const SECRET_LENGTH = 52

/**
 * The shape a presented key must have before anything is looked up.
 *
 * Anchored, exact lengths, alphabet-restricted. A malformed string is rejected here rather than
 * reaching the database, which means the only values that ever become a query parameter are
 * 16 characters of `[a-z2-7]`.
 */
const KEY_PATTERN = new RegExp(
  `^${KEY_PREFIX}_(live|test)_([a-z2-7]{${LOOKUP_LENGTH}})_([a-z2-7]{${SECRET_LENGTH}})$`,
)

export interface ParsedKey {
  readonly environment: KeyEnvironment
  readonly lookupId: string
  readonly secret: string
}

/**
 * Split a presented key. Returns null for anything that is not exactly the format.
 *
 * Deliberately total and side-effect free: it touches no database, allocates nothing unbounded,
 * and cannot throw. It is the first thing every authenticated request runs, on a string an
 * attacker chose.
 */
export function parseKey(presented: string): ParsedKey | null {
  const match = KEY_PATTERN.exec(presented.trim())
  if (!match) return null
  const [, environment, lookupId, secret] = match
  if (environment === undefined || lookupId === undefined || secret === undefined) return null
  if (!isKeyEnvironment(environment)) return null
  return { environment, lookupId, secret }
}

/**
 * What may be written to a log, shown in a list, or put in an error.
 *
 * Everything up to and including the lookup id, and nothing after it. This is the string an
 * operator revokes by, and it is safe precisely because the secret is not in it.
 */
export function keyDisplay(environment: KeyEnvironment, lookupId: string): string {
  return `${KEY_PREFIX}_${environment}_${lookupId}`
}

/**
 * Redact a key found in arbitrary text — a log line, a support ticket, an error message.
 *
 * Keeps the identifiable half and destroys the usable half, which is the whole reason the format
 * is split. Exported so that anything in this service that might log a caller-supplied string can
 * pass it through first.
 */
export function redactKeys(text: string): string {
  return text.replace(
    new RegExp(`${KEY_PREFIX}_(live|test)_([a-z2-7]{${LOOKUP_LENGTH}})_[a-z2-7]{${SECRET_LENGTH}}`, 'g'),
    `${KEY_PREFIX}_$1_$2_[redacted]`,
  )
}

/* ------------------------------------------------------------------ hashing */

export interface ScryptParams {
  readonly N: number
  readonly r: number
  readonly p: number
  readonly keyLen: number
}

/**
 * What this build hashes at.
 *
 * N=16384 matches `identity/src/passwords.ts` — the same cost the estate already uses for
 * passwords, which is the right comparison because this table is a password table. Raising it is
 * a one-line change here and nothing else: every existing row keeps verifying under its own
 * recorded parameters and is re-hashed on its next successful use.
 *
 * `maxmem` must be raised alongside N by hand — Node's ceiling is 32 MiB and scrypt needs roughly
 * `128 * N * r`, which N=16384 sits just inside and N=32768 does not. Getting that wrong presents
 * as every verification throwing, so it is derived below rather than remembered.
 */
export const CURRENT_PARAMS: ScryptParams = { N: 16_384, r: 8, p: 1, keyLen: 64 }

const SALT_LEN = 16

/** `scrypt$N=16384,r=8,p=1,keyLen=64`. Self-describing, parseable, stable to sort on. */
export function encodeAlgo(params: ScryptParams): string {
  return `scrypt$N=${params.N},r=${params.r},p=${params.p},keyLen=${params.keyLen}`
}

export const CURRENT_ALGO = encodeAlgo(CURRENT_PARAMS)

/**
 * Parse a recorded algorithm back into parameters.
 *
 * Returns null rather than throwing, and the caller treats null as "this credential cannot be
 * verified" — a 401, not a 500. A row carrying an algorithm this build does not understand was
 * written by a NEWER build during a rolling deploy, and the correct behaviour for the older
 * replica is to refuse and let the retry land on a newer one. Guessing at current parameters
 * would produce a wrong answer confidently.
 */
export function parseAlgo(algo: string): ScryptParams | null {
  const match = /^scrypt\$N=(\d+),r=(\d+),p=(\d+),keyLen=(\d+)$/.exec(algo.trim())
  if (!match) return null
  const params = {
    N: Number(match[1]),
    r: Number(match[2]),
    p: Number(match[3]),
    keyLen: Number(match[4]),
  }
  if (!Number.isInteger(params.N) || params.N < 2 || (params.N & (params.N - 1)) !== 0) return null
  if (!Number.isInteger(params.r) || params.r < 1 || params.r > 64) return null
  if (!Number.isInteger(params.p) || params.p < 1 || params.p > 64) return null
  if (!Number.isInteger(params.keyLen) || params.keyLen < 16 || params.keyLen > 256) return null
  return params
}

function maxmemFor(params: ScryptParams): number {
  // 128 * N * r is scrypt's working-set size; the factor of two is headroom Node's own check
  // requires. Derived, because a hard-coded ceiling and a raised N is a service where every
  // verification throws.
  return Math.max(32 * 1024 * 1024, 256 * params.N * params.r)
}

/**
 * The KDF, behind a seam.
 *
 * A function type rather than a direct call so a test can COUNT invocations. That count is how
 * `keys.test.ts` proves the miss path and the revoked path each ran the KDF — a property that is
 * otherwise only observable with a stopwatch, and a stopwatch assertion on a shared CI runner is
 * a test that fails for reasons unrelated to the code.
 */
export type Kdf = (secret: string, salt: Buffer, params: ScryptParams) => Promise<Buffer>

export const scryptKdf: Kdf = (secret, salt, params) =>
  scryptAsync(secret, salt, params.keyLen, {
    N: params.N,
    r: params.r,
    p: params.p,
    maxmem: maxmemFor(params),
  })

export interface StoredHash {
  readonly algo: string
  /** Hex. Random per key, so two identical secrets do not produce identical rows. */
  readonly salt: string
  readonly hash: string
}

export async function hashSecret(
  secret: string,
  params: ScryptParams = CURRENT_PARAMS,
  kdf: Kdf = scryptKdf,
): Promise<StoredHash> {
  const salt = randomBytes(SALT_LEN)
  const derived = await kdf(secret, salt, params)
  return { algo: encodeAlgo(params), salt: salt.toString('hex'), hash: derived.toString('hex') }
}

/**
 * Constant-time comparison of a presented secret against a stored hash.
 *
 * `timingSafeEqual` throws on a length mismatch, so lengths are compared first. A digest length
 * is public knowledge — it is implied by the recorded `keyLen` — so leaking it leaks nothing.
 */
export async function verifyAgainst(
  secret: string,
  stored: StoredHash,
  kdf: Kdf = scryptKdf,
): Promise<boolean> {
  const params = parseAlgo(stored.algo)
  if (!params) return false
  let expected: Buffer
  let derived: Buffer
  try {
    expected = Buffer.from(stored.hash, 'hex')
    derived = await kdf(secret, Buffer.from(stored.salt, 'hex'), params)
  } catch {
    return false
  }
  if (expected.length !== derived.length) return false
  return timingSafeEqual(expected, derived)
}

/* ------------------------------------------------------------------ issuance */

export interface IssuedKey {
  /** The full key string. Returned to the caller ONCE and never persisted in any form. */
  readonly secretKey: string
  readonly environment: KeyEnvironment
  readonly lookupId: string
  readonly display: string
  readonly stored: StoredHash
}

/**
 * Mint a key.
 *
 * The returned `secretKey` is the only copy that will ever exist. `stored` is what goes in the
 * row, and it is a one-way function of the secret — there is no inverse and no column that could
 * hold one. `apikeys.ts` writes `stored`; nothing writes `secretKey`.
 */
export async function issueKey(
  environment: KeyEnvironment,
  params: ScryptParams = CURRENT_PARAMS,
  kdf: Kdf = scryptKdf,
): Promise<IssuedKey> {
  const lookupId = base32Encode(randomBytes(LOOKUP_BYTES)).slice(0, LOOKUP_LENGTH)
  const secret = base32Encode(randomBytes(SECRET_BYTES)).slice(0, SECRET_LENGTH)
  const stored = await hashSecret(secret, params, kdf)
  return {
    secretKey: `${KEY_PREFIX}_${environment}_${lookupId}_${secret}`,
    environment,
    lookupId,
    display: keyDisplay(environment, lookupId),
    stored,
  }
}

/* ------------------------------------------------------------------ verification */

/**
 * A decoy, generated once at module load from bytes nobody has.
 *
 * Verifying a presented secret against this is a full-cost scrypt run that always fails. It is
 * what makes the lookup-miss path cost the same as the hit path. Built lazily and cached, because
 * building it is itself a scrypt run and doing it per request would double the cost of every
 * failed authentication — which is the request an attacker controls the rate of.
 */
let decoyPromise: Promise<StoredHash> | undefined

function decoy(params: ScryptParams, kdf: Kdf): Promise<StoredHash> {
  decoyPromise ??= hashSecret(base32Encode(randomBytes(SECRET_BYTES)), params, kdf)
  return decoyPromise
}

/** Exported for tests, which need each case to start from a known state. */
export function resetDecoy(): void {
  decoyPromise = undefined
}

export type KeyRefusal = 'malformed' | 'unknown' | 'revoked' | 'expired' | 'wrong_environment' | 'bad_secret'

export interface VerifiableKey {
  readonly algo: string
  readonly salt: string
  readonly hash: string
  readonly environment: KeyEnvironment
  readonly revokedAt: Date | null
  readonly expiresAt: Date | null
}

export type KeyVerification =
  | { readonly ok: true; readonly lookupId: string; readonly needsRehash: boolean }
  | { readonly ok: false; readonly reason: KeyRefusal; readonly lookupId: string | null }

/**
 * Verify a presented key against whatever the store says about its lookup id.
 *
 * `load` is a function rather than a row so that this can run the decoy KDF when the load returns
 * nothing — the load and the constant-cost path have to be in the same function, or a caller will
 * eventually write `if (!row) return 401` above it and undo the whole property.
 *
 * **Every path below runs the KDF exactly once.** Malformed is the sole exception, and it is a
 * deliberate one: a string that fails the anchored regex was never a key, carries no lookup id,
 * and reveals nothing about which keys exist. Spending 60 ms of CPU on it would only hand an
 * unauthenticated caller a cheap way to exhaust the process.
 */
export async function verifyPresentedKey(
  presented: string,
  load: (lookupId: string) => Promise<VerifiableKey | null>,
  options: { readonly now?: Date; readonly kdf?: Kdf; readonly params?: ScryptParams } = {},
): Promise<KeyVerification> {
  const kdf = options.kdf ?? scryptKdf
  const params = options.params ?? CURRENT_PARAMS
  const now = options.now ?? new Date()

  const parsed = parseKey(presented)
  if (!parsed) return { ok: false, reason: 'malformed', lookupId: null }

  const row = await load(parsed.lookupId)
  if (!row) {
    // The decoy run. Same KDF, same parameters, same wall-clock cost, guaranteed failure.
    await verifyAgainst(parsed.secret, await decoy(params, kdf), kdf)
    return { ok: false, reason: 'unknown', lookupId: parsed.lookupId }
  }

  // The secret is checked BEFORE the state is consulted, so that a revoked key and a live key with
  // the wrong secret and an unknown lookup id all cost one KDF run. Checking state first would
  // reintroduce the oracle by another door: a revoked key would answer without hashing.
  const matches = await verifyAgainst(parsed.secret, row, kdf)
  if (!matches) return { ok: false, reason: 'bad_secret', lookupId: parsed.lookupId }
  if (row.revokedAt !== null) return { ok: false, reason: 'revoked', lookupId: parsed.lookupId }
  if (row.expiresAt !== null && row.expiresAt.getTime() <= now.getTime()) {
    return { ok: false, reason: 'expired', lookupId: parsed.lookupId }
  }
  if (row.environment !== parsed.environment) {
    // The environment is in the string AND in the row. They disagree only if a key string was
    // hand-assembled, which is worth refusing loudly rather than resolving in either direction.
    return { ok: false, reason: 'wrong_environment', lookupId: parsed.lookupId }
  }

  // A key hashed under a lower work factor is re-hashed at the current one the moment the
  // plaintext is in hand — which is this instant and no other. Without this, raising
  // CURRENT_PARAMS would protect only keys issued afterwards.
  return { ok: true, lookupId: parsed.lookupId, needsRehash: row.algo !== encodeAlgo(params) }
}
