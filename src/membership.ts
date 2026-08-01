/**
 * Who may administer a developer organisation.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IDENTITY IS ASKED. NOTHING IS MIRRORED.**
 *
 * `07-dependency-map.md:143` makes `devplatform → identity` a HARD dependency for "developer
 * organisation and membership", and `orgs.ts` holds no membership rows at all. This is the file
 * that pays for that decision: every request that acts on an organisation asks identity whether the
 * caller belongs to it.
 *
 * The alternative — a mirrored `memberships` table fed by `identity.membership.changed` — is what
 * most services would do, and it is wrong here for one reason. `11-data-and-contract-strategy.md:349`
 * prices the staleness this estate accepts for mirrored identity data at 60 seconds. Sixty seconds
 * is fine for rendering a list of organisations. It is not fine for deciding who may MINT A
 * CREDENTIAL: the minute after someone is removed from a company is precisely the minute they would
 * use to issue themselves a key that outlives their access.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE CALLER'S OWN TOKEN IS FORWARDED. THIS SERVICE HOLDS NO OMNIPOTENT CREDENTIAL.**
 *
 * `identity`'s `GET /organisations/:id/memberships` (`identity/src/server.ts:1219`) authenticates
 * the caller as a USER and answers 404 to a non-member. So devplatform forwards the developer's own
 * bearer token and reads the answer. It therefore needs no service token that can read anybody's
 * membership — which is the shape of the two omnipotent tokens SD-05 exists to retire, and the
 * reason `env.ts` has no `DEVPLATFORM_ADMIN_TOKEN`.
 *
 * A consequence worth stating: identity answering 404 means "you are not a member OR there is no
 * such organisation", and this file preserves that ambiguity rather than resolving it. Resolving it
 * would turn devplatform into an oracle for the existence of organisations that identity
 * deliberately hides.
 *
 * **AN OUTAGE IS 503, NEVER 403.** If identity cannot be reached we do not KNOW whether the caller
 * is a member, and answering "no" would lock every developer out of their own platform for the
 * duration of somebody else's incident. This is the same rule `runtime/packages/auth` states for
 * token verification (`index.ts:10-16`) and it is got backwards at least as often.
 */

import { HttpClient, HttpError } from '@cloudsforge/http'

/** Identity's vocabulary, restated. See the note in the README on the uncut contracts package. */
export const ORG_ROLES = Object.freeze(['owner', 'admin', 'member', 'billing', 'read'] as const)
export type OrgRole = (typeof ORG_ROLES)[number]

/**
 * Roles that may change what a project IS — issue and revoke credentials, register clients, edit
 * the directory listing.
 *
 * `member` is deliberately not here. A member of a company is not automatically someone who may
 * mint a production API key for it; on a developer platform that is an administrative act, and the
 * blast radius of getting it wrong is every customer of that company's integration.
 */
export const ADMIN_ROLES: readonly OrgRole[] = Object.freeze(['owner', 'admin'])

/** Roles that may READ a project: its keys' metadata, its usage, its quotas. */
export const READ_ROLES: readonly OrgRole[] = Object.freeze(['owner', 'admin', 'member', 'billing', 'read'])

export function isOrgRole(value: string): value is OrgRole {
  return (ORG_ROLES as readonly string[]).includes(value)
}

/** Identity could not be reached. The caller answers 503. Never 403. */
export class MembershipUnavailableError extends Error {
  constructor(message: string) {
    super(`membership could not be established: ${message}`)
    this.name = 'MembershipUnavailableError'
  }
}

export interface MembershipClient {
  /**
   * The caller's role in an identity organisation, or null when they have none.
   *
   * `userToken` is the developer's own bearer token, forwarded verbatim.
   */
  roleFor(userToken: string, identityOrgId: string, userId: string): Promise<OrgRole | null>
}

interface MembershipsResponse {
  readonly memberships?: ReadonlyArray<{ userId?: unknown; role?: unknown }>
}

export interface IdentityClientOptions {
  readonly baseUrl: string
  readonly deadlineMs?: number
  readonly fetch?: typeof globalThis.fetch
}

/**
 * The real client.
 *
 * A short deadline, because this call is on the path of every console request and identity being
 * slow must not become devplatform being slow. Two retries, which is safe: the request is a GET.
 */
export function identityMembership(options: IdentityClientOptions): MembershipClient {
  const client = new HttpClient({
    baseUrl: options.baseUrl,
    name: 'identity',
    defaultDeadlineMs: options.deadlineMs ?? 3_000,
    defaultRetries: 2,
    ...(options.fetch ? { fetch: options.fetch } : {}),
  })

  return {
    async roleFor(userToken, identityOrgId, userId) {
      try {
        const body = await client.get<MembershipsResponse>(
          `/organisations/${encodeURIComponent(identityOrgId)}/memberships`,
          { headers: { authorization: `Bearer ${userToken}` } },
        )
        const memberships = body.memberships ?? []
        for (const membership of memberships) {
          if (membership.userId !== userId) continue
          const role = membership.role
          return typeof role === 'string' && isOrgRole(role) ? role : null
        }
        return null
      } catch (err) {
        // 404 is identity's deliberate answer for "not a member, or no such organisation". It is a
        // decision, not a fault, and it means the caller has no role. 401/403 likewise.
        if (err instanceof HttpError && (err.status === 404 || err.status === 401 || err.status === 403)) {
          return null
        }
        // Anything else — a timeout, a 500, DNS — means we could not decide.
        throw new MembershipUnavailableError(err instanceof Error ? err.message : String(err))
      }
    },
  }
}

/** True when the role, if any, is one of the set. A null role grants nothing. */
export function permits(role: OrgRole | null, allowed: readonly OrgRole[]): boolean {
  return role !== null && allowed.includes(role)
}
