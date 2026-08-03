# micro-devplatform

[![ci](https://github.com/cloudsforge-online/micro-devplatform/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-devplatform/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

The developer platform. Developer organisations, projects, environments, **API keys**, service
accounts, OAuth clients, webhook endpoints and secrets, usage, quotas, and the application
directory.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

It is the service that issues the credential a third party presents to the CloudsForge public API.
Everything else here is bookkeeping around that one thing.

```
POST /v1/projects/:id/keys   →   cfk_live_7k4m2qb9xzr3tvn8_h5w2c…
                                 shown once, stored under scrypt, never recoverable
```

---

## 1. The key format

```
cfk_live_7k4m2qb9xzr3tvn8_h5w2c…          four underscore-separated parts
─┬─ ─┬── ────────┬─────── ───┬───
 │   │           │           └── 32 random bytes, base32. NEVER stored. Hashed with scrypt.
 │   │           └── 10 random bytes, base32. Stored in the clear, UNIQUE, indexed.
 │   └── `live` or `test`. Which environment the key acts in.
 └── The fixed prefix. Three characters that make a leaked key greppable.
```

Each part earns its place.

**`cfk`** — a fixed, distinctive token so a leaked key is **findable**. Secret scanners, log
pipelines and `git grep` all work on a literal prefix and on nothing else. A key that is sixty
characters of base64 with no marker is a key nobody can search the estate for after an incident.

**`live` / `test`** — visible to a human at a glance. A test key pasted into a production config and
a production key pasted into a test fixture are the same class of mistake, and the only cheap
defence against both is that the string says which it is.

**The lookup id** — *a key must be identifiable without being usable.* This is the property the
whole format is arranged around, and it buys two distinct things:

1. **A key can be revoked from a log line.** Logs record `cfk_live_7k4m2qb9xzr3tvn8` — prefix,
   environment, lookup, and nothing after it. An operator who finds a key in a paste bin or a support
   ticket revokes exactly that key without ever holding the secret and without asking the developer
   which one it was. `redactKeys()` turns any text containing a full key into that form.
2. **Verification is one indexed lookup.** Without a lookup id, checking a presented key means
   running the KDF against every row until one matches — `O(rows)` scrypt invocations per request,
   a service that gets slower the more customers it has and falls over at the first
   credential-stuffing attempt.

**The secret** — 32 bytes from `randomBytes`, base32. Returned exactly once, at creation, and then
gone. There is no column that could hold it and no route that could return it.

Base32 rather than base64url because base64url's alphabet contains `_`, and `_` is the field
separator. A separator that can occur inside a field is a parser that can be steered.

### The hash is scrypt, and the parameters are recorded in the row

An API key table **is** a password table. It holds one high-value secret per row, an attacker who
reaches it holds the whole set, and the only thing between a dump and a working credential is how
expensive one guess is. SHA-256 makes a guess free.

The estate already made this decision and already found the defect in the naive version.
`identity/src/passwords.ts:1-19` records it: Nimbus called `scrypt` at library defaults and stored
two hex strings, so nothing in the row said what cost produced them — and a work factor that cannot
be raised without a forced reset for every user is a work factor that never gets raised. This
service uses the same `scrypt$N=…,r=…,p=…,keyLen=…` encoding at the same `N=16384`
(`identity/src/passwords.ts:57`), reads the parameters **from the row**, and re-hashes a key at the
current cost on its next successful use — the one moment the plaintext is in hand.

Two layers keep it honest:

| Layer | What refuses what |
| --- | --- |
| `keys.ts` | `promisify(scrypt)` is re-typed so the options object cannot be silently dropped — the exact defect `identity/src/passwords.ts:24-28` documents. |
| `api_keys_slow_kdf_only` | A CHECK constraint. A row recording `sha256` — or anything else fast — is refused by **the database**. The day someone reaches for `createHash` because it is one line shorter, this is what stops it. |

### A revoked key is indistinguishable from an unknown one, including in timing

The obvious implementation returns early on a lookup miss and on a revoked row, and runs scrypt only
for a live key. That turns response latency into an oracle: a caller holding a stolen key learns from
a ~0.1 ms answer that the lookup id does not exist and from a ~60 ms answer that it does — enough to
enumerate live lookup ids, and enough to tell "this key was revoked, so the account is real and
someone is watching" from "this key never existed".

So `verifyPresentedKey` runs the KDF on **every** path, including the miss, against a decoy hash
generated at module load. The organisation-suspension check runs *after* the hash, for the same
reason. Every refusal answers 401 with one message; the reason goes to the log and to
`devplatform_key_refusals_total{reason}` and never to the wire.

Proved by counting KDF invocations through an injectable seam, not by a stopwatch — a wall-clock
assertion on a shared CI runner is a flaky test, and a flaky security test gets deleted. See
`keys.test.ts` and `apikeys.test.ts`, and `server.test.ts` for the byte-for-byte comparison of the
two 401s over the wire.

### A key with no scope grants nothing; a wildcard grants nothing

`scopes.ts` takes the **contracts** rule (`contracts/packages/auth/src/index.ts:209` — exact match),
not the runtime one. Both directions are enforced and both are tested:

- `validateScopes` **refuses** a wildcard at issuance rather than filtering it. A caller told
  "created" for a key missing an authority it asked for would find out at the worst possible moment.
- `grantsScope` returns false for `*`, `market:*`, `:*` and five other forms even if one somehow
  reached a row.
- `api_keys_scopes_no_wildcard` refuses one at the database, however it arrived.

An **empty** scope array is legal and completely inert — which is what makes the property provable
rather than merely asserted: a credential can exist and authorise nothing. It can still call
`GET /v1/keys/self`.

---

## 2. The whoami: `GET /v1/keys/self`

[18-build-status](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/18-build-status.md) §3.3d(4) records the finding:

> **A machine credential has no whoami.** `identity/src/server.ts:540` refuses a service token on
> `GET /auth/me`, so a devplatform API key will have no way to ask what it is.

The finding is correct. Its remedy is **not** in identity, for a reason the finding could not have
known before this service existed.

**An API key is not a JWT.** `identity`'s `/auth/me` authenticates by verifying a signed token and
reading its claims (`identity/src/server.ts:513-532`, narrowed to a user at `:534-542`). A
`cfk_live_…` string has no signature, no claims and no issuer. Identity holds neither the `api_keys`
row nor the scrypt hash that would let it decide anything about one, and giving it either would mean
either replicating the credential store into a second service or handing identity a read path into
this one. Relaxing line 540 would admit a *service token* — a third kind of credential entirely — to
`/auth/me`; that is a separate question, and one this service does not own.

So: **the service that issued the credential introspects it.**

```
GET /v1/keys/self
Authorization: Bearer cfk_live_7k4m2qb9xzr3tvn8_h5w2c…

{ "display": "cfk_live_7k4m2qb9xzr3tvn8", "name": "integration",
  "environment": "live", "projectId": "…", "orgId": "…",
  "scopes": ["market:read", "wallet:read"], "createdAt": "…", "expiresAt": null }
```

Three decisions inside it:

- **It requires no scope.** A credential that cannot ask what it is cannot be diagnosed, and gating
  it behind `devplatform:read` would mean the keys most likely to be misconfigured — the ones with no
  scopes at all — are exactly the ones that cannot find out.
- **It answers the scope list exactly.** The most common integration failure is "why is this 403?",
  and the answer is a list the developer can compare against the route's requirement.
- **It never returns anything derived from the secret.** No hash, no salt, no algorithm.

For the estate rather than for the developer, the same answer is at
`POST /internal/keys/verify` — the route a gateway or a service calls to turn a presented key into a
principal. `/internal` is refused from outside by `deploy/gateway/dynamic/policy.yml` at a priority
nothing can outrank, **and** the route requires a service token carrying `devplatform:introspect`.
Two controls, because the first is a deployment fact and the second is a code fact, and neither alone
survives a gateway misconfiguration. A bad credential there is a `200 {"ok": false}` with no reason:
the caller's own credential was fine, and conflating the two makes a caller retry its service token.

**What identity would need, if it ever did serve this.** Recorded so the option is not lost: a
`POST /internal/credentials/introspect` on devplatform is already that interface. Identity would call
it and re-shape the answer into `/auth/me`'s schema. That is a change to identity, in another
repository, and is reported rather than made.

---

## 3. How this service builds to the public API

Since §3.3d was written, two artefacts appeared that this service was built against rather than
around.

**`deploy/gateway/dynamic/public-api.yml`** mounts the public surface at `api.<apex>/v1/<resource>`,
uniformly, and strips `/v1` for the four services that do not serve it themselves.

**`sdk/openapi.json`** describes the 65 verified public routes across 52 paths, generated from the
SDK's route table, and already declares the security scheme this service fills in:

```json
"apiKey": { "type": "http", "scheme": "bearer",
            "description": "A developer platform API key, presented as a bearer token." }
```

46 of its operations accept it. So the wire format was already decided: **the key is the bearer
token**, exactly as `sdk/packages/sdk/src/credentials.ts:62`'s `apiKey()` sends it, and exactly as
every route in the estate already reads it (`bearerFrom(headerOf(req, 'authorization'))`). Nothing
about the format had to be negotiated; it had to be *compatible*, and it is.

### Path versioning: `/v1` natively

**Chosen: this service serves `/v1/…` itself.** That puts it in the wallet / market / mint / worlds
half — forwarded unchanged, no rewrite middleware — rather than the pricing / activity / foresight /
identity half, which needs `cf-api-strip-version`. A strip rule is a second place the public path is
decided, and a second place drifts. Since this service is new, there is no shipped internal caller to
break, so there is no reason to take the option that costs a middleware.

### Resource names, chosen against the existing 52 paths

`public-api.yml` routes by **resource**, not by service, and says why: which service owns a resource
is an implementation detail, and publishing it turns an internal refactor into a breaking public
change. That is only safe because the verified public routes have no method+path collision across
services — *checked, not assumed*. Adding one here would break that property for everyone, so the
names below were picked against `sdk/openapi.json` rather than guessed:

| Mounted | Note |
| --- | --- |
| `/v1/organisations` | free |
| `/v1/projects` | free |
| `/v1/keys` | free — `/v1/keys/self` is the whoami |
| `/v1/webhook-endpoints` | free |
| `/v1/oauth-clients` | free |
| `/v1/apps` | free — the public directory |
| `/v1/scopes` | free — the scope vocabulary, unauthenticated |

Deliberately **not** used: `/v1/tokens` (mint's, `sdk/openapi.json`), `/v1/auth` (identity's).
`quotas` and `usage` are nested under `/v1/projects/:id/…` rather than mounted at the root, because
neither is meaningful without a project.

The gateway router this service needs, when it is added — this repository does not write it, because
`deploy/` is another repository:

```yaml
cf-api-devplatform:
  rule: "Host(`{{ env \"CF_API_HOST\" }}`) && (PathPrefix(`/v1/organisations`) || PathPrefix(`/v1/projects`) || PathPrefix(`/v1/keys`) || PathPrefix(`/v1/webhook-endpoints`) || PathPrefix(`/v1/oauth-clients`) || PathPrefix(`/v1/apps`) || PathPrefix(`/v1/scopes`))"
  priority: 1000
  entryPoints: [websecure]
  middlewares: [cf-api-headers]     # no strip: this service serves /v1 natively
  service: cf-api-devplatform
```

---

## 4. The rest of the security core

### Secrets are shown once

Three routes return a secret, each attaching a value minted **in that request** and never stored:

| Route | Returns |
| --- | --- |
| `POST /v1/projects/:id/keys` | `secretKey` — the full `cfk_…` string |
| `POST /v1/projects/:id/webhook-endpoints`, `POST /v1/webhook-endpoints/:id/rotate-secret` | `secret` — a `whsec_…` signing secret |
| `POST /v1/projects/:id/oauth-clients` | `clientSecret` — a `cfcs_…` secret |

A **replay** of any of them answers with the metadata and `null`. The stored idempotency response is
a `jsonb` column that outlives the request, so it carries no secret — which is precisely what makes
a replay safe.

`micro-custody` deleted its admin-reveal endpoint rather than guard it (SD-08). There is no
equivalent here and nothing to guard: for an API key and an OAuth client the plaintext does not exist
after the response is written.

This is enforced by two independent tests, because they fail on different mistakes:

- `server.test.ts` walks **all 18 read routes** and greps every response body for each of the four
  minted secrets. Catches a leak through an unexpected field.
- `routeidempotency.test.ts` enumerates the four **source positions** where a secret may be attached
  at all, and asserts each is assigned from a mint rather than from a query. Catches a route added
  tomorrow.

### The one honest exception: a webhook secret is stored recoverably

HMAC is a keyed function of the payload, and signing a delivery requires the key material itself. A
hash of the secret cannot sign anything. There is no arrangement in which this service both signs
deliveries and does not hold the secret, and pretending otherwise would be worse than the exception.

`webhook_secrets.secret` is therefore plaintext, and says so in the schema. The compensating controls
are the ones actually available: it is shown once and no route reads it back; it authenticates *us to
the subscriber* rather than granting access to anything; and it is **rotatable without an outage**,
which is the control that matters most. Rotation writes a new row and stamps `retires_at` on the old
one, so both verify during the overlap window (`DEVPLATFORM_WEBHOOK_ROTATION_OVERLAP_MINUTES`, default
24 h) and a customer can deploy and roll back. A single-value rotation would require the subscriber
to change configuration in the same instant this service does, and that instant does not exist.

### A signature is verified over the raw bytes, before anything is parsed

`verifyInbound(rawBody: Buffer, …)` takes bytes, which makes "parse first, verify second"
*unwriteable* rather than merely discouraged. A handler that parsed first has already run an
unauthenticated document through a parser and already made decisions on input nobody authenticated.

`webhooks.test.ts` proves the distinction bites: a body that re-serialises to different bytes (key
order, unicode escaping, number formatting) verifies against the original bytes and fails against the
round trip. A handler verifying `JSON.stringify(JSON.parse(body))` would reject its own honest
deliveries.

The scheme is `t=<seconds>,v1=<hex>` from `@cloudsforge/contracts-events` — the timestamp is *inside*
the signed material, so a captured delivery cannot be replayed outside the tolerance window.
Comparison is `timingSafeEqual` after a length check.

`POST /v1/events`, the internal inbox, is checked the same way against `DEVPLATFORM_INGEST_SECRETS`.
Unsigned it would be a revoke-anybody's-integration endpoint reachable by anything that can open a
socket to the app network.

### Quotas are counted in the database

An in-memory counter is per-replica, and a per-replica quota is not a quota — a customer on a
600/minute plan gets 600 × N. It is also wrong on a single replica, because a deploy resets it: "600
per minute, or per deploy, whichever comes first".

The counter is a `quota_windows` row and the increment is one guarded statement:

```sql
update quota_windows set used_units = used_units + n
 where quota_id = … and window_start = … and used_units + n <= max_units
returning used_units
```

Postgres holds a row lock for the UPDATE, so a second transaction re-evaluates its `where` against
the first's *committed* value. No row returned means the limit was reached, by this caller or by the
one that beat it, and the two are the same answer. `quota_windows_within_limit` is the belt to that
UPDATE's braces.

Proved with concurrency, twice: 40 concurrent `consumeQuota` calls against a limit of 10 allow
exactly 10, and 25 concurrent `POST /internal/usage` calls against a limit of 5 allow exactly 5. The
test pool is opened wide (`max: 24`) on purpose — with one connection the requests would serialise in
the *client* and the test would pass without the database guard doing anything. Checked against the
tempting implementation: a read-then-write increment allows 22 of 40, differently every run.

`max_units` is copied into the window row, so raising a quota applies to the **next** window rather
than retroactively to the one in progress. That also makes "what was the limit when this request was
refused?" answerable after the fact.

#### A quota the quota'd party can raise is not a quota

`PUT /v1/projects/:id/quotas` (`src/server.ts:1011`) used to require only `project:write`, and
`setQuota` accepted any whole number ≥ 1 with **no upper bound** — `quotas_max_positive` guarded the
bottom and nothing guarded the top. So the owner of a project could set their own rate limit to
whatever they liked, and so could any **API key** in it carrying `devplatform:write`: a machine
credential raising the limit that binds it. `micro-devportal-web` declined to call this route at all
for that reason, which is why the developer console still has no quota editor.

**The direction is the authority.** Lowering is a customer's own safety feature — a developer capping
their test environment so a runaway loop cannot burn the month's allowance is doing the platform's
work for it, and making that need an operator means nobody ever does it. Raising is the abuse.

| Request | Who | Where |
| --- | --- | --- |
| lower, or write the same value again | `project:write` | `src/server.ts:1039-1052` |
| raise | operator | `src/server.ts:1046-1051` |
| create a row where none exists | operator | `src/server.ts:1040-1045` |
| any value above the ceiling | **nobody** | `src/quotas.ts:149-156`, `src/migrations.ts:524-526` |

Equal is permitted deliberately: PUT is idempotent by natural key, and a retry that answered 403
would make that route's exemption in `routeidempotency.test.ts` a lie.

**Creating a quota is an operator act, and that is not an oversight.** An environment with *no* row
is unlimited — `quotasFor` returns nothing and `consumeAll` over an empty list allows everything
(`src/quotas.ts:319-327` and `src/quotas.ts:310-315`). Treating absence as infinity and calling any finite value a reduction
would hand the whole defect back through the periods that have no row.

**The ceiling is in the schema**, `quotas_max_within_ceiling` (`src/migrations.ts:524-526`), and it is
there rather than in the handler for the reason this estate always gives: a CHECK holds against a
caller with a database connection — a backfill, a psql session, a write path written next year — and
a handler does not. The same numbers are in `MAX_UNITS_CEILING` (`src/quotas.ts:71-76`) so a caller
gets a 400 naming the ceiling instead of a 500 carrying `23514`, and `migrations.test.ts` reads
`pg_get_constraintdef` and asserts the two agree, which is the only thing that stops them drifting.

They are not a judgement about what a plan should be. Each is the largest value this service's own
configuration already permits to be *seeded* into these rows — `env.ts:210` bounds
`DEVPLATFORM_DEFAULT_QUOTA_PER_MINUTE` at 10,000,000 and `env.ts:211` bounds
`DEVPLATFORM_DEFAULT_QUOTA_PER_MONTH` at 10,000,000,000 — so a legal configuration can never be
refused by the constraint guarding the rows it seeds. The minute ceiling is the lower of the two on
purpose: one ceiling for every period would have to be the month's, and a per-minute allowance of ten
billion is not a limit anybody chose.

**Nothing is silently migrated, and no stored quota is above it.** Adding the constraint *validates
every existing row*: a database holding one fails migration 9 with `23514`, and the deploy stops. That
is the intended behaviour rather than a hazard — a migration that quietly clamped somebody's limit
would destroy the only record of what it had been, and the repair is a deliberate `UPDATE` decided
by a person before the deploy.

Checked rather than assumed. Migration 9 was run against three databases already at version 8 and
carrying rows:

| Version-8 database | Result |
| --- | --- |
| default quotas (600/minute, 1,000,000/month) and a delisted listing | applied |
| a `minute` quota of 99,999,999,999 | refused: `quotas_max_within_ceiling … is violated by some row` |
| a listing whose slug is `pending` | refused: `applications_slug_not_reserved … is violated by some row` |

No production database is in either failing state, because **this service has never been deployed**:
it is routed in `deploy/gateway/dynamic/public-api.yml:177` and appears in no file under
`deploy/compose/`, so the only `quotas` rows that have ever existed are the ones CI creates and
drops. Every value any code path could have written is inside the ceiling anyway — `env.ts:210-211`
bound the seeded defaults and `PUT /v1/projects/:id/quotas` was the only other writer.

**An operator here is not an administrator of the customer's organisation.** `isOperator`
(`src/server.ts:553-557`) admits a service token carrying the exact scope `devplatform:admin`, or a
user token carrying the platform role `admin` — `market/src/server.ts:1335-1341`'s `requireOperator`,
adopted rather than reinvented. The membership check is *skipped* for them rather than added to,
because an operator asked to be a member of every organisation they act on ends up holding a
credential that is a member of all of them, which is the shape SD-05 exists to retire. An **API key
is never an operator**: `devplatform:admin` is deliberately absent from `src/scopes.ts`, so
`validateScopes` refuses it at issuance and no row can hold it.

### The application directory has an operator, and it now has a route

`setApplicationStatus` (`src/applications.ts:238`) was written on the first day, imported by the
server, and **called by no handler at all**. An application could be submitted and could never be
approved, so the directory could never be populated. `server.test.ts` proved the directory worked by
writing `update applications set status = 'listed'` by hand — a test that writes the row itself
cannot notice that nothing else can — and `applications.ts` had no test file of its own until now.

`PUT /v1/projects/:id/application/status` (`src/server.ts:1344`) is that handler, and it is an
operator's. Not `project:write` at any strength: a directory a developer can publish to unilaterally
is a directory that eventually hosts a phishing page wearing this platform's chrome, and the consent
screen a user reads before granting an OAuth client authority is rendered from exactly this row.

**The transitions are enumerated and the move is claimed, not assigned.** `OPERATOR_TRANSITIONS`
(`src/applications.ts:80-87`) names the legal sources for each target and the UPDATE claims with
`where status = any(...)` (`src/applications.ts:255`), so two operators deciding one submission
produce one winner and one 409 rather than two successes and a last-write-wins — including `listed`
silently overwriting a `rejected` somebody had just decided. The unguarded version also made
`draft → listed` reachable, which publishes copy nobody reviewed.

**`rejected` is a status of its own** (migration 9), not a reuse of `delisted`. "We looked and said
no" and "you were live and we took you down" are different facts about a developer, support answers
them differently, and one is a resubmission while the other is an appeal. `submitForReview` accepts
`rejected` as a source (`src/applications.ts:211`) so a rejected listing can be revised and asked
about again — one operator's "no" is not permanent.

The queue an operator works from is `GET /v1/apps/pending` (`src/server.ts:1283`), oldest first,
because newest-first ordering on a queue nobody empties starves the developer who has waited longest.
It is matched **before** `GET /v1/apps/:slug` (`src/server.ts:1291`), and what makes that safe is not
the ordering: `applications_slug_not_reserved` (`src/migrations.ts:548-549`) refuses `pending` as a
slug, so there is no listing this route can shadow even if somebody reorders the file.

### A disabled webhook endpoint can be turned back on

`POST /v1/webhook-endpoints/:id/disable` passed `true` unconditionally and there was no inverse, so
disabling was permanent. The only way back was to `DELETE` the endpoint and create a new one — which
mints a new signing secret, drops the delivery history, and requires the subscriber to redeploy. An
endpoint is disabled *during* an incident, which is the worst hour in which to tell a customer to
rotate a secret.

`POST /v1/webhook-endpoints/:id/enable` (`src/server.ts:1178`) is the inverse. Two verbs rather than
a `{ disabled: boolean }` body on one, because the two are not equally consequential and a boolean
makes them look it: a client that inverted the flag would silently do the opposite of what its
operator intended. Deliveries are **not** replayed on the way back — `enqueueDeliveries` selects
`where e.disabled_at is null` (`src/webhooks.ts:380`), so nothing was queued while it was off. That
is said out loud because the opposite is the reasonable assumption.

### A console can ask which organisation it is in, without writing anything

`findOrgByIdentityId` (`src/orgs.ts:162`) was reachable only from the event inbox, so the only way to
answer "which developer organisation am I in?" was to re-`POST /v1/organisations` and read what came
back — idempotent, therefore harmless, and still a mutation issued to ask a question.

`GET /v1/organisations?identityOrgId=…` (`src/server.ts:784`) is the read. It cannot enumerate: the
lookup key is the **identity** organisation id, which the caller must already hold, and authority is
asked of identity with the caller's own token before the row is read at all — so a non-member gets
the same 404 for "you are not a member" and "there is no such organisation" that identity itself
gives, and that ambiguity is preserved rather than resolved. A **member** of an organisation that has
never been enrolled gets `200 { "organisations": [] }`, which is an enrolment button rather than a
dead end, and leaks nothing identity has not already confirmed.

### No money

`usage_events` counts **calls**. There is no amount, price, currency or balance column anywhere in
this schema, and `migrations.test.ts` greps the DDL for six of those words. Metered usage that costs
money is a `micro-billing` entitlement or a `micro-ledger` entry; a column named for an amount here
would be the first row of a second ledger.

### Membership is asked, never mirrored

`developer_orgs` holds an **enrolment** keyed by identity's organisation id and no membership rows at
all. Every request that acts on an organisation asks identity — forwarding the **developer's own
bearer token** to `GET /organisations/:id/memberships` (`identity/src/server.ts:1219`), so this
service holds no credential that can read anybody's membership.

A mirrored membership table would be stale at exactly the moment someone is removed from a company,
and [11-data-and-contract-strategy](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/11-data-and-contract-strategy.md):349 prices
the staleness this estate accepts for identity data at 60 seconds. Sixty seconds is fine for
rendering a list. It is not fine for deciding who may **mint a credential**.

**Identity being unreachable is a 503, never a 403.** If we cannot reach identity we do not *know*
whether the caller is a member, and answering "no" would lock every developer out of their own
platform for the duration of somebody else's incident. Note the asymmetry that makes this affordable:
`/internal/keys/verify` needs identity for nothing at all, so identity is a **soft** readiness probe
and a degraded devplatform still authenticates keys for the whole estate.

`member` may read; only `owner` and `admin` may write. A member of a company is not automatically
someone who may mint a production API key for it.

### No `setInterval`

Four leased jobs, each claimed `FOR UPDATE SKIP LOCKED` under a lease keyed on the resource it
contends on. `jobs.test.ts` runs two `JobRunner`s with **different owners** against one due job and
asserts exactly one execution — a test that cannot even be written against a module-local boolean,
because the boolean is invisible to the second process by construction.

| Job | Unleased, it would… |
| --- | --- |
| `outbox.relay` | deliver every event to every internal subscriber twice — including `devplatform.key.revoked`, the event that invalidates a cached key at the edge |
| `webhook.deliver` | POST every event to a customer's endpoint twice |
| `usage.rollup` | race two upserts on one primary key and pay for two aggregate scans |
| `retention` | run the heaviest DELETE in the service twice |

Webhook deliveries are additionally claimed `for update skip locked` at the **row** level, because
one worker is allowed to run deliveries concurrently with itself — the contended resource there is a
delivery row, not the queue.

### Idempotency, checked by enumeration

Every mutating route either wraps `withIdempotentRoute` or appears in `routeidempotency.test.ts`'s
`EXEMPT` map with the **mechanism** that makes it safe — a natural key, an `on conflict do nothing`,
a state transition claimed on a column, or `DELETE`. A route added without either fails the build.

That test is `market/src/routeidempotency.test.ts`, adopted deliberately. Market shipped two routes
with no wrapper and no natural key, and a double-clicked button opened two disputes on one order.
The stakes here are higher: `POST /v1/projects/:id/keys` unwrapped mints **two** credentials on a
retry, and the second is one the developer never saw and therefore never revokes — a live key with no
owner. `EXEMPT` is checked for staleness in both directions, and each reason must name a mechanism.

The fingerprint excludes `correlationId`, `requestId` and `idempotencyKey`. The ledger fingerprinted
the whole body, so a caller doing exactly the right thing — a fresh trace id per attempt — was told
its key had been reused with a different payload, and every honest retry would have 409'd. Pinned in
both directions: a fresh correlation id replays, a different scope set still 409s.

---

## 5. The routes

Read out of `src/server.ts`, not inferred from a client. Every line below was opened.

**Who** is the mechanism the handler uses, and it is a property of the code rather than a label:

| Who | What the handler calls |
| --- | --- |
| **none** | nothing. No credential is read at all. |
| `key` | `authenticateKeyOnly` (`:572`) — an API key ONLY. A user JWT is a 403 (`:574`). |
| `user+admin` | `authenticateUser` (`:565`) plus `permits(role, ADMIN_ROLES)` against identity (`:753`). |
| `org:read` / `org:write` | `authoriseOrg` (`:645`) — a user token only, whose role in the identity organisation is asked of identity per request. |
| `project:read` / `project:write` | `authoriseProject` (`:603`) — a user token OR an API key. A key may act only within its own project, because the project id is read from the ROW and never from the request (`:630-635`). |
| **operator** | `isOperator` (`:553`) — a service token carrying `devplatform:admin`, or a user token with the platform role `admin`. **No organisation membership.** |
| `service` | `authenticateService` (`:579`) — a service token carrying an exact scope. `/internal` only. |
| `hmac` | a signature over the raw bytes, checked before `JSON.parse` (`:1473`). |

### Public and customer surface

| Method | Path | Who | `Idempotency-Key` | Line |
| --- | --- | --- | --- | --- |
| `GET` | `/livez` | none | — | `:685` |
| `GET` | `/readyz` | none | — | `:687` |
| `GET` | `/metrics` | none | — | `:692` |
| `GET` | `/v1/scopes` | none | — | `:712` |
| `GET` | `/v1/keys/self` | `key` | — | `:732` |
| `POST` | `/v1/organisations` | `user+admin` | — | `:745` |
| `GET` | `/v1/organisations` | user, member of the named identity org | — | `:784` |
| `GET` | `/v1/organisations/:id` | `org:read` | — | `:799` |
| `GET` | `/v1/organisations/:id/projects` | `org:read` | — | `:807` |
| `POST` | `/v1/projects` | `org:write` | **required** | `:815` |
| `GET` | `/v1/projects/:id` | `project:read` | — | `:838` |
| `POST` | `/v1/projects/:id/service-accounts` | `project:write` | — | `:850` |
| `GET` | `/v1/projects/:id/service-accounts` | `project:read` | — | `:861` |
| `POST` | `/v1/projects/:id/keys` | `project:write` | **required** | `:880` |
| `GET` | `/v1/projects/:id/keys` | `project:read` | — | `:934` |
| `GET` | `/v1/keys/:id` | `project:read` | — | `:941` |
| `DELETE` | `/v1/keys/:id` | `project:write` | — | `:956` |
| `PUT` | `/v1/projects/:id/quotas` | `project:write` to **lower**; **operator** to raise or create | — | `:1011` |
| `GET` | `/v1/projects/:id/quotas` | `project:read` | — | `:1063` |
| `GET` | `/v1/projects/:id/usage` | `project:read` | — | `:1073` |
| `POST` | `/v1/projects/:id/webhook-endpoints` | `project:write` | **required** | `:1083` |
| `GET` | `/v1/projects/:id/webhook-endpoints` | `project:read` | — | `:1114` |
| `POST` | `/v1/webhook-endpoints/:id/rotate-secret` | `project:write` | **required** | `:1123` |
| `POST` | `/v1/webhook-endpoints/:id/disable` | `project:write` | — | `:1154` |
| `POST` | `/v1/webhook-endpoints/:id/enable` | `project:write` | — | `:1178` |
| `DELETE` | `/v1/webhook-endpoints/:id` | `project:write` | — | `:1188` |
| `GET` | `/v1/webhook-endpoints/:id/deliveries` | `project:read` | — | `:1197` |
| `POST` | `/v1/projects/:id/oauth-clients` | `project:write` | **required** | `:1207` |
| `GET` | `/v1/projects/:id/oauth-clients` | `project:read` | — | `:1244` |
| `DELETE` | `/v1/oauth-clients/:id` | `project:write` | — | `:1249` |
| `GET` | `/v1/apps` | none | — | `:1263` |
| `GET` | `/v1/apps/:slug` | none | — | `:1291` |
| `PUT` | `/v1/projects/:id/application` | `project:write` | — | `:1298` |
| `GET` | `/v1/projects/:id/application` | `project:read` | — | `:1312` |
| `POST` | `/v1/projects/:id/application/submit` | `project:write` | — | `:1320` |

### Operator only

Ordinary `/v1` paths guarded in code, which is the estate's shape (`market/src/server.ts:1335-1341`)
and what keeps them inside the prefixes the gateway already routes
(`deploy/gateway/dynamic/public-api.yml:177`) rather than needing a rule this repository cannot write.

| Method | Path | Line |
| --- | --- | --- |
| `GET` | `/v1/apps/pending` — the review queue, oldest first | `:1283` |
| `PUT` | `/v1/projects/:id/application/status` — list, reject or delist | `:1344` |
| `PUT` | `/v1/projects/:id/quotas` — when the request raises or creates | `:1020` |

### Internal

Refused from outside by `deploy/gateway/dynamic/policy.yml` at a priority nothing can outrank, **and**
requiring a service token carrying `devplatform:introspect` — two controls, because the first is a
deployment fact and the second is a code fact.

| Method | Path | Who | Line |
| --- | --- | --- | --- |
| `POST` | `/internal/keys/verify` | `service` | `:1372` |
| `POST` | `/internal/oauth/verify` | `service` | `:1392` |
| `POST` | `/internal/usage` | `service` | `:1426` |
| `POST` | `/v1/events` | `hmac` | `:1471` |

**Six routes make no `authenticate()` call of any kind** — `/livez`, `/readyz`, `/metrics`,
`GET /v1/scopes`, `GET /v1/apps` and `GET /v1/apps/:slug`. A client that sends a bearer to one of
those is not refused; it is ignored, which is the harder thing to diagnose. `POST /v1/events` is the
seventh that reads no `Authorization` header, but it is not public: it is HMAC-checked instead.

### The constraints that carry meaning

Each is in the schema rather than in a handler, and this is why.

| Constraint | Refuses | Why here |
| --- | --- | --- |
| `api_keys_slow_kdf_only` | a credential row whose recorded algorithm is not a scrypt encoding | the day someone reaches for `createHash` because it is one line shorter, review is not what stops it (`src/migrations.ts:204`) |
| `api_keys_scopes_no_wildcard` | a key carrying `*` | the schema outlives any particular write path, and the day someone adds a bulk import is the day `scopes.ts` is bypassed (`src/migrations.ts:210`) |
| `api_keys_revoked_has_time` | a revocation with no time | a row claiming to be revoked without saying when cannot be reasoned about during an incident, which is the only time anyone reads it (`src/migrations.ts:214`) |
| `quota_windows_within_limit` | an overage that got past the guarded UPDATE | the UPDATE is the mechanism; this is the belt, and it refuses the row rather than allowing a silent overage (`src/migrations.ts:365`) |
| `quotas_max_within_ceiling` | a `minute` quota above 10,000,000, anything else above 10,000,000,000 | a quota's upper bound must hold against a caller with a database connection — a backfill, a psql session, a write path written next year — and the handler that had it did not (`src/migrations.ts:524-526`) |
| `applications_listed_has_time` | a listed row with no `listed_at`, or the reverse | "when did this become visible?" is the first question asked after a bad listing, and a state that cannot be dated cannot be audited (`src/migrations.ts:427`) |
| `applications_slug_not_reserved` | a listing whose slug is `pending` | `GET /v1/apps/pending` is matched before `GET /v1/apps/:slug`, so that listing would be unreachable at its own public address. A route ordering that has to be remembered is one that will be reordered (`src/migrations.ts:548-549`) |
| `oauth_clients_redirects_absolute` | a wildcard or relative redirect URI | an open redirect hands an authorisation code to whoever asked for it (`src/migrations.ts:253-257`) |
| `webhook_endpoints_url_https` | a plaintext delivery target | the signature proves origin; it does not provide confidentiality (`src/migrations.ts:282`) |

`migrations.test.ts` writes the row each one exists to refuse and asserts the refusal. A CHECK that
is never exercised is a comment with a table around it.

---

## 6. Running it

```bash
pnpm install
cp .env.example .env          # every secret is CHANGE_ME, and CHANGE_ME does not boot
pnpm migrate                  # a SEPARATE one-shot process, never called from index.ts
pnpm start
```

```bash
pnpm typecheck
DEVPLATFORM_TEST_DATABASE_URL='postgres://…/devplatform_test' pnpm test
pnpm check                    # both
```

The suite is `node:test` against a **real Postgres** — deferred constraints, `SKIP LOCKED` leases and
row-lock races are the things most worth proving and not one of them exists in a fake. The DSN's name
must contain `test`: `resetDevplatform` truncates every table this service owns, and `api_keys` is not
recoverable from anything, because the secret half was never stored.

`--test-concurrency=1` is required, not a preference: every database test file truncates between
cases, a `TRUNCATE` takes an `AccessExclusiveLock`, and node:test runs *files* in parallel by default.

**302 tests, 0 skipped.**

### Configuration

Every variable is declared in `.env.example` and read in exactly one place, `src/env.ts`.
`env.test.ts` asserts the two agree in **both** directions — a variable declared but unread fails the
suite just as loudly as one read but undeclared.

There is deliberately no `DEVPLATFORM_ADMIN_TOKEN`, no break-glass credential and no reveal switch;
their absence is asserted by name. The equivalent would be a static string that can read or issue
credentials, which is the shape of the omnipotent service tokens SD-05 exists to retire.

---

## 7. Things found in siblings, reported and not fixed

Each is in another repository and out of this one's scope.

1. **Two scope matchers in the estate disagree.** `contracts/packages/auth/src/index.ts:209` is exact
   match; `runtime/packages/auth/src/index.ts:178` honours one wildcard level, so `ledger:*` grants
   `ledger:post` (`index.test.ts:155`). An internal service token carrying `ledger:*` is therefore
   omnipotent-within-ledger or meaningless depending on which helper the service happens to call.
   This repository takes the contracts rule, and `/internal/keys/verify` checks its required scope
   with `includes` rather than `hasScope` for exactly this reason — a wildcard must not reach a route
   that reads credentials. `server.test.ts` proves `devplatform:*` is refused there.

2. **`devplatform.*` is not a registered topic.**
   `contracts/packages/events/src/index.ts:222` freezes `TOPICS` and `:351` closes `TopicName`;
   `devplatform` is a legal `ProducerService` (`:194`) but has no topic of its own. So
   `devplatform.key.revoked` — which
   [11-data-and-contract-strategy](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/11-data-and-contract-strategy.md):363 names by
   string as the mechanism that propagates a revocation past the gateway's 30-second validation cache
   — cannot be constructed through `makeEvent`. The five topics are local constants in `outbox.ts`,
   validated with `isValidTopicName` (the shape check, which they pass) rather than
   `isRegisteredTopic` (which they cannot until the package adds them).

3. **`@cloudsforge/contracts-devplatform` has not been cut.** 18 §3.5(4) lists it among the four
   uncut packages, and [11](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/11-data-and-contract-strategy.md):54 names it as the
   owner of the scope vocabulary. Until it exists the vocabulary is `src/scopes.ts`, and moving it is
   a package extraction rather than a redesign.

4. **There is no OAuth token endpoint, deliberately.** `sdk`'s `clientCredentials`
   (`sdk/packages/sdk/src/credentials.ts:109`) takes its `tokenUrl` from the caller with no default.
   This service does not supply one, because minting an access token means signing it with the key
   the estate's JWKS publishes, and that key is identity's — `runtime/packages/auth`'s `Verifier`
   checks `issuer` and fetches `IDENTITY_JWKS_URL` (`index.ts:103-106`), so a token signed here
   verifies nowhere. The alternatives are a second trusted issuer (the shape SD-05 retires) or
   devplatform holding identity's private key. **The seam:** devplatform owns the client registry and
   answers `POST /internal/oauth/verify`; identity owns the token endpoint and calls it. Identity's
   half is another repository.

5. **`src/migrations.ts` did not parse when this work resumed.** Two SQL comments carried unescaped
   backticks inside a template literal (`` `*` `` at :208 and `` `verifyDelivery` `` at :292), which
   closed the string early — migration 4 escapes its own, these two did not. Escaped rather than
   rewritten. Recorded here because it is a change to inherited code in this repository, not a
   sibling's defect.

---

## 8. Found in this repository, and what was done about each

The four defects `micro-devportal-web` reported were real, and one was worse than stated. §4 covers
each in full; this is the ledger, with what else turned up while fixing them.

### Fixed

| Finding | Where it was | What it is now |
| --- | --- | --- |
| A customer could raise their own quota to any value | `PUT /v1/projects/:id/quotas` required only `project:write`, `setQuota` had no ceiling | lowering is `project:write`, raising and creating are an operator's, and the top is a CHECK (§4) |
| **Worse than reported:** an API KEY carrying `devplatform:write` could do it too | the same route — `authoriseProject` admits a key acting in its own project | `devplatform:admin` is absent from `src/scopes.ts`, so `validateScopes` refuses it at issuance and no key can ever hold it |
| Nothing could approve a submitted application | `setApplicationStatus` was imported at `src/server.ts` and called by no handler | `PUT /v1/projects/:id/application/status` (`:1344`), plus the queue at `GET /v1/apps/pending` (`:1283`) that makes it addressable |
| A rejection could not be told from a delisting | four statuses; a refused application had nowhere to go but `delisted` | `rejected` is its own status (migration 9), and `submitForReview` accepts it as a source so one "no" is not permanent |
| No route resolved a developer organisation | `findOrgByIdentityId` was reachable only from the event inbox | `GET /v1/organisations?identityOrgId=…` (`:784`) |
| A disabled webhook endpoint could not be re-enabled | `:1154` passed `true` unconditionally, no inverse | `POST /v1/webhook-endpoints/:id/enable` (`:1178`) |
| `applications.ts` had **no test file** | the only case touching the directory wrote `update applications set status = 'listed'` by hand | `src/applications.test.ts`, 18 cases |
| A guard in `routeidempotency.test.ts` could not fail | it sliced `server.ts` from `function buildRoutes` to `indexOf('/* ----')`, which finds the *first* such banner ~15 kB **earlier** — a backwards slice is `''`, so it searched nothing and passed for any input | ends at the banner that closes the route list, and asserts the extractor found a route block at all |

### Reported, not fixed

1. **A malformed path parameter is a 500, not a 400.** Eleven routes pass `ctx.params['id']`
   straight to a `uuid` column, so `GET /v1/projects/not-a-uuid` (`src/server.ts:838` →
   `authoriseProject` → `findProject`) surfaces Postgres `22P02` as `500 internal`. The same holds
   for `GET /v1/keys/:id` (`:941`), `DELETE /v1/keys/:id` (`:956`), the four
   `/v1/webhook-endpoints/:id` routes and `DELETE /v1/oauth-clients/:id` (`:1249`). A malformed URL
   reported as a server fault also puts a 5xx on the dashboard for something no server did wrong.
   `requireUuid` (`src/server.ts:1638`) exists and the two routes added here use it; changing the
   status code of eleven shipped routes is a different decision, and `micro-devportal-web` pins
   citations into every one of them.

2. **`src/outbox.ts:29` names a file that does not exist.** "`topics.ts` carries the list a future
   `contracts-devplatform` should adopt verbatim" — there is no `src/topics.ts` in this repository.
   The list it describes is `TOPICS` at `src/outbox.ts:52-58`. A pointer to a file nobody wrote is
   the kind of claim rule 1 of the README template exists to stop.

3. **An environment with no quota row is unlimited, and nothing says so on the wire.**
   `quotasFor` returns an empty list and `consumeAll` over it allows everything
   (`src/quotas.ts:310-315`). `POST /v1/projects` seeds `minute` and `month` on both environments,
   so a project created through the API is covered — but `hour` and `day` never have rows, and any
   project created by another path has none at all. `GET /v1/projects/:id/quotas` reports the rows
   that exist rather than the periods that are unmetered, so "no limit" and "no row" look identical
   to a console. Left alone because inventing rows would change what a project costs; recorded so
   the next reader does not have to rediscover it.

4. **`GET /v1/projects/:id/quotas` is `project:read`, and quota rows are per environment.** A
   `billing`-role member can therefore read a project's limits, which is right, but there is no
   route that answers "what is the ceiling?" other than the `ceiling` field this change adds to the
   `PUT` response. A console rendering a slider has to make one write to learn the range.

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
