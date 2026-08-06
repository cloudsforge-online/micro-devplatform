/**
 * OAuth clients: registration, secret verification, revocation.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHAT THIS FILE DELIBERATELY DOES NOT CONTAIN: A TOKEN ENDPOINT.**
 *
 * `@cloudsforge/sdk`'s `clientCredentials` (`sdk/packages/sdk/src/credentials.ts`) takes its
 * `tokenUrl` from the caller, with no default, and says why: devplatform did not exist and a
 * default would be a URL the SDK invented. The obvious thing to do here is to invent it —
 * `POST /v1/oauth/token`, mint a JWT, done.
 *
 * That would be wrong, and it is worth writing down why rather than leaving the gap looking like an
 * omission. Minting an access token means signing it with the key the estate's JWKS publishes, and
 * that key is identity's. `runtime/packages/auth`'s `Verifier` checks `issuer` and fetches
 * `IDENTITY_JWKS_URL` (`index.ts`), so a token signed by devplatform verifies nowhere. The
 * alternatives are both worse than the gap:
 *
 *   1. **Devplatform gets a signing key of its own** and every service in the estate gains a second
 *      trusted issuer. That is two omnipotent issuers where there was one, which is the shape SD-05
 *      exists to retire.
 *   2. **Devplatform holds identity's private key.** No.
 *
 * The correct seam is the third option: **devplatform owns the client registry and answers whether
 * a presented `client_id`/`client_secret` pair is valid and what it may ask for; identity owns the
 * token endpoint and calls that.** `verifyClientSecret` below is that answer, and it is reachable
 * at `POST /internal/oauth/verify` — internal, because `deploy/gateway/dynamic/policy.yml` refuses
 * `/internal` from outside at a priority nothing can outrank.
 *
 * Building identity's half is a change to another repository and is reported, not made. Until it
 * exists, `clientCredentials` has no `tokenUrl` default — which is exactly the state the SDK
 * already documents, so nothing regresses.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The secret itself is hashed exactly as an API key's is, with the same recorded parameters and the
 * same constant-cost verification, and for the same reason: a client secret dumped from this table
 * must not be a working credential.
 */

import { randomBytes } from 'node:crypto'
import type { Db, Tx } from './outbox.ts'
import { NotFoundError, ValidationError } from './orgs.ts'
import { validateScopes, type Scope } from './scopes.ts'
import {
  CURRENT_PARAMS,
  base32Encode,
  hashSecret,
  verifyAgainst,
  type Kdf,
  type ScryptParams,
  type StoredHash,
} from './keys.ts'

export const CLIENT_ID_PREFIX = 'cfc'
export const CLIENT_SECRET_PREFIX = 'cfcs'

export interface OAuthClient {
  readonly id: string
  readonly projectId: string
  readonly clientId: string
  readonly name: string
  readonly redirectUris: readonly string[]
  readonly scopes: readonly string[]
  readonly createdAt: Date
  readonly revokedAt: Date | null
}

interface ClientRow {
  readonly id: string
  readonly project_id: string
  readonly client_id: string
  readonly name: string
  readonly redirect_uris: readonly string[]
  readonly scopes: readonly string[]
  readonly created_at: Date
  readonly revoked_at: Date | null
}

function toClient(row: ClientRow): OAuthClient {
  return {
    id: row.id,
    projectId: row.project_id,
    clientId: row.client_id,
    name: row.name,
    redirectUris: row.redirect_uris,
    scopes: row.scopes,
    createdAt: row.created_at,
    revokedAt: row.revoked_at,
  }
}

/**
 * Validate a redirect URI.
 *
 * Absolute https, or an http loopback for local development, and no wildcard — the schema's
 * `oauth_clients_redirects_absolute` says the same thing in a CHECK. A wildcard or relative
 * redirect is an open redirect that hands an authorisation code to whoever asked for it, and it is
 * the single most exploited misconfiguration in OAuth deployments.
 *
 * A fragment is refused too: RFC 6749 §3.1.2 forbids one, and a redirect URI with a fragment breaks
 * the implicit-grant response mode in a way that is invisible until a customer reports it.
 */
export function assertRedirectUri(raw: string): string {
  let url: URL
  try {
    url = new URL(raw.trim())
  } catch {
    throw new ValidationError('a redirect uri must be an absolute URL')
  }
  if (url.hash !== '') throw new ValidationError('a redirect uri must not contain a fragment')
  if (raw.includes('*')) throw new ValidationError('a redirect uri must not contain a wildcard')
  const host = url.hostname.toLowerCase()
  const loopback = host === 'localhost' || host === '127.0.0.1'
  if (url.protocol === 'https:') return url.toString()
  if (url.protocol === 'http:' && loopback) return url.toString()
  throw new ValidationError('a redirect uri must use https, or http on localhost for development')
}

export interface RegisterClientInput {
  readonly projectId: string
  readonly name: string
  readonly redirectUris: readonly string[]
  readonly scopes: readonly string[]
}

export interface RegisteredClient {
  readonly client: OAuthClient
  /** Shown once. There is no column it could be read back from. */
  readonly clientSecret: string
}

export async function registerClient(
  tx: Tx,
  input: RegisterClientInput,
  options: { readonly params?: ScryptParams; readonly kdf?: Kdf } = {},
): Promise<RegisteredClient> {
  const name = input.name.trim()
  if (name.length < 1 || name.length > 200) {
    throw new ValidationError('a client name must be 1 to 200 characters')
  }
  const scopes: readonly Scope[] = validateScopes(input.scopes)
  const redirectUris = [...new Set(input.redirectUris.map(assertRedirectUri))]

  const projects = await tx<{ id: string }[]>`select id from projects where id = ${input.projectId}`
  if (!projects[0]) throw new NotFoundError('no such project')

  const clientId = `${CLIENT_ID_PREFIX}_${base32Encode(randomBytes(12)).slice(0, 19)}`
  const secret = `${CLIENT_SECRET_PREFIX}_${base32Encode(randomBytes(32)).slice(0, 52)}`
  const stored = await hashSecret(secret, options.params ?? CURRENT_PARAMS, options.kdf)

  const rows = await tx<ClientRow[]>`
    insert into oauth_clients (project_id, client_id, name, secret_algo, secret_salt, secret_hash,
                               redirect_uris, scopes)
    values (${input.projectId}, ${clientId}, ${name}, ${stored.algo}, ${stored.salt}, ${stored.hash},
            ${tx.array(redirectUris)}, ${tx.array(scopes as string[])})
    returning id, project_id, client_id, name, redirect_uris, scopes, created_at, revoked_at
  `
  const row = rows[0]
  if (!row) throw new Error('oauth client insert returned no row')
  return { client: toClient(row), clientSecret: secret }
}

export async function listClients(sql: Tx | Db, projectId: string): Promise<readonly OAuthClient[]> {
  const rows = await sql<ClientRow[]>`
    select id, project_id, client_id, name, redirect_uris, scopes, created_at, revoked_at
      from oauth_clients where project_id = ${projectId} order by created_at desc
  `
  return rows.map(toClient)
}

export async function revokeClient(sql: Tx | Db, id: string): Promise<OAuthClient> {
  const rows = await sql<ClientRow[]>`
    update oauth_clients set revoked_at = coalesce(revoked_at, now()) where id = ${id}
    returning id, project_id, client_id, name, redirect_uris, scopes, created_at, revoked_at
  `
  const row = rows[0]
  if (!row) throw new NotFoundError('no such oauth client')
  return toClient(row)
}

export type ClientVerification =
  | { readonly ok: true; readonly client: OAuthClient }
  | { readonly ok: false; readonly reason: 'unknown' | 'revoked' | 'bad_secret' }

/**
 * Verify a presented `client_id`/`client_secret` pair.
 *
 * Constant cost on every path, for the same reason `verifyPresentedKey` is: an unknown client id
 * that answers in microseconds while a real one takes 60 ms is an enumeration oracle over the
 * customer list. The decoy is generated per call from the same parameters rather than cached,
 * because a token endpoint is called orders of magnitude less often than an API route and the
 * simpler code is worth more here than the saved milliseconds.
 *
 * The refusal reason is for this service's logs. The caller — identity's token endpoint — answers
 * RFC 6749's `invalid_client` for all three.
 */
export async function verifyClientSecret(
  sql: Db | Tx,
  clientId: string,
  presentedSecret: string,
  options: { readonly params?: ScryptParams; readonly kdf?: Kdf } = {},
): Promise<ClientVerification> {
  const params = options.params ?? CURRENT_PARAMS
  const rows = await sql<
    (ClientRow & { secret_algo: string; secret_salt: string; secret_hash: string })[]
  >`
    select id, project_id, client_id, name, redirect_uris, scopes, created_at, revoked_at,
           secret_algo, secret_salt, secret_hash
      from oauth_clients where client_id = ${clientId}
  `
  const row = rows[0]

  if (!row) {
    const decoy = await hashSecret(base32Encode(randomBytes(32)), params, options.kdf)
    await verifyAgainst(presentedSecret, decoy, options.kdf)
    return { ok: false, reason: 'unknown' }
  }

  const stored: StoredHash = { algo: row.secret_algo, salt: row.secret_salt, hash: row.secret_hash }
  const matches = await verifyAgainst(presentedSecret, stored, options.kdf)
  // Secret before state, exactly as in keys.ts: checking `revoked_at` first would answer without
  // hashing and reintroduce the oracle by another door.
  if (!matches) return { ok: false, reason: 'bad_secret' }
  if (row.revoked_at !== null) return { ok: false, reason: 'revoked' }
  return { ok: true, client: toClient(row) }
}
