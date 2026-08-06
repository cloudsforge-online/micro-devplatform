/**
 * The public scope vocabulary, and the one function that decides whether a key may do a thing.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THREE RULES, AND EACH ONE IS A REFUSAL.**
 *
 *   1. **A key with no scopes grants nothing.** Not "grants everything it has an org role for",
 *      not "grants read". `grantsScope([], anything)` is false, and creating a key with an empty
 *      scope set is allowed precisely so that it is provable: a credential can exist and be
 *      completely inert.
 *
 *   2. **A wildcard grants nothing, and cannot be issued.** `*`, `wallet:*` and `:*` are all
 *      refused at creation as unknown scopes, and all three return false from `grantsScope` even
 *      if one somehow reached a row. Both directions, because "it can never be written" and "it
 *      would do nothing if it were" protect against different failures.
 *
 *   3. **Exact match only.** No prefix implication, no `write` covering `read`, no ordering.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY EXACT MATCH, AND A DIVERGENCE IN THE ESTATE THAT HAD TO BE RESOLVED ONE WAY.**
 *
 * There are two scope matchers in this estate and they do not agree:
 *
 *   - `contracts/packages/auth/src/index.ts` — `grantsScope` is `granted.includes(required)`.
 *     Exact match. Its comment at :201-208 is explicit: "There is no `custody:*`, no
 *     `ledger:write` covering `ledger:post`, and no implication ordering between scopes.
 *     Hierarchy is how a shared token comes back."
 *   - `runtime/packages/auth/src/index.ts` — `hasScope` honours ONE wildcard level, so
 *     `ledger:*` does grant `ledger:post` (`index.test.ts`). A bare `*` grants nothing
 *, which is the part both agree on.
 *
 * So an internal service token carrying `ledger:*` is treated as omnipotent-within-ledger by the
 * runtime middleware and as meaningless by the contracts helper, depending on which one a given
 * service happens to call. That is reported, not fixed — both files are outside this repository.
 *
 * This service takes the **contracts** rule, exactly, and for the reason that file gives: these
 * are credentials issued to third parties, indefinitely lived, and the one thing a developer
 * platform must never ship is a credential nobody can enumerate the authority of. If an
 * integration needs two capabilities it is granted two scopes and the key says so.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS VOCABULARY IS NOT `contracts-auth`'s.**
 *
 * `contracts/packages/auth/src/index.ts` is the closed set of **service** scopes: the
 * authority one CloudsForge service holds over another, `custody:sign:treasury` and the like.
 * Handing any of those to a third party would be a category error — `ledger:post` writes journal
 * entries, and nothing outside this estate may do that.
 *
 * The public vocabulary is a different, smaller set, and it is the one a developer sees. It
 * belongs in `@cloudsforge/contracts-devplatform`, which
 * `11-data-and-contract-strategy.md` names as the owner of the "scope vocabulary" — and which
 * `18-build-status.md` records as one of the four contract packages that have not been cut.
 * Until it is, this is the vocabulary, here, and moving it is a package extraction rather than a
 * redesign.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

export interface ScopeSpec {
  /** The service that would enforce it. Only that service should ever check for this scope. */
  readonly service: string
  /** Read or write. Surfaced in the console so a developer can see what they are handing out. */
  readonly kind: 'read' | 'write'
  readonly description: string
}

/**
 * Every scope a devplatform key may carry.
 *
 * Named by SERVICE and ACTION, never by URL path. That is deliberate and is the direct
 * consequence of there being no gateway route map: see README §"The gateway has no route map".
 * A scope named `POST /v1/listings` would be invalidated the day the gateway decides where the
 * public API is mounted; `market:write` is a fact about authority and survives any layout.
 */
export const SCOPES = Object.freeze({
  'wallet:read': Object.freeze({
    service: 'wallet',
    kind: 'read',
    description: 'Read wallets, deposit addresses and withdrawal state for the acting subject.',
  }),
  'ledger:read': Object.freeze({
    service: 'ledger',
    kind: 'read',
    description: 'Read balances and journal entries for the acting subject.',
  }),
  'pricing:read': Object.freeze({
    service: 'pricing',
    kind: 'read',
    description: 'Read quotes and administered rates.',
  }),
  'indexer:read': Object.freeze({
    service: 'indexer',
    kind: 'read',
    description: 'Read blocks, transactions and address activity.',
  }),
  'activity:read': Object.freeze({
    service: 'activity',
    kind: 'read',
    description: 'Read the activity feed for the acting subject.',
  }),
  'market:read': Object.freeze({
    service: 'market',
    kind: 'read',
    description: 'Read listings, offers, auctions and collections.',
  }),
  'market:write': Object.freeze({
    service: 'market',
    kind: 'write',
    description: 'Create and manage listings, offers and bids.',
  }),
  'worlds:read': Object.freeze({
    service: 'worlds',
    kind: 'read',
    description: 'Read titles, profiles, inventory and achievements.',
  }),
  'worlds:write': Object.freeze({
    service: 'worlds',
    kind: 'write',
    description: 'Write inventory and achievement state for the acting subject.',
  }),
  'mint:read': Object.freeze({
    service: 'mint',
    kind: 'read',
    description: 'Read token orders, deployments and the token registry.',
  }),
  'mint:write': Object.freeze({
    service: 'mint',
    kind: 'write',
    description: 'Create token orders and drive a deployment.',
  }),
  'devplatform:read': Object.freeze({
    service: 'devplatform',
    kind: 'read',
    description: 'Read this project: its keys (never their secrets), webhooks, usage and quotas.',
  }),
  'devplatform:write': Object.freeze({
    service: 'devplatform',
    kind: 'write',
    description: 'Manage this project: issue and revoke keys, manage webhook endpoints.',
  }),
} as const satisfies Readonly<Record<string, ScopeSpec>>)

export type Scope = keyof typeof SCOPES

export const SCOPE_NAMES: readonly Scope[] = Object.freeze(Object.keys(SCOPES) as Scope[])

export function isScope(value: string): value is Scope {
  return Object.hasOwn(SCOPES, value)
}

export function scopeSpec(scope: Scope): ScopeSpec {
  return SCOPES[scope]
}

/**
 * Exact match. See the header for why there is no wildcard and no hierarchy.
 *
 * The `granted` parameter is `readonly string[]` rather than `readonly Scope[]` on purpose: a row
 * read back from the database is untyped text, and the whole point is that an unrecognised or
 * wildcard entry sitting in that array grants nothing rather than throwing or being interpreted.
 */
export function grantsScope(granted: readonly string[], required: Scope): boolean {
  return granted.includes(required)
}

export function grantsAllScopes(granted: readonly string[], required: readonly Scope[]): boolean {
  // `every` over an empty requirement is true, which is correct: a route that requires no scope
  // requires no scope. Routes that must never be reachable by a key demand one explicitly.
  return required.every((scope) => grantsScope(granted, scope))
}

/** Drops anything not in the registry. A key carrying an unknown scope carries nothing by it. */
export function knownScopes(granted: readonly string[]): readonly Scope[] {
  return granted.filter(isScope)
}

export class UnknownScopeError extends Error {
  readonly unknown: readonly string[]
  constructor(unknown: readonly string[]) {
    super(
      `not scopes this platform issues: ${unknown.join(', ')}. ` +
        'There is no wildcard: name every scope the key needs.',
    )
    this.name = 'UnknownScopeError'
    this.unknown = unknown
  }
}

/**
 * Validate a requested scope set at issuance, and normalise it.
 *
 * Refuses rather than filters. A caller that asked for `market:write` and `wallet:*` and got back
 * a key with only `market:write` would believe it holds an authority it does not, and would
 * discover otherwise at the worst possible moment. Duplicates collapse and order is stabilised so
 * that two identical requests produce identical rows — which is what makes an idempotency
 * fingerprint over the scope list meaningful.
 */
export function validateScopes(requested: readonly string[]): readonly Scope[] {
  const trimmed = requested.map((scope) => scope.trim()).filter((scope) => scope.length > 0)
  const unknown = trimmed.filter((scope) => !isScope(scope))
  if (unknown.length > 0) throw new UnknownScopeError([...new Set(unknown)])
  return Object.freeze([...new Set(trimmed as Scope[])].sort())
}
