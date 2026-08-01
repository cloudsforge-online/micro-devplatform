# micro-devplatform

The developer platform. Developer organisations, projects, environments, **API keys**, service
accounts, OAuth clients, webhook endpoints and secrets, usage, quotas, and the application
directory.

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

[18-build-status](../docs/ecosystem/18-build-status.md) §3.3d(4) records the finding:

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

- `server.test.ts` walks **all 16 read routes** and greps every response body for each of the four
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
and [11-data-and-contract-strategy](../docs/ecosystem/11-data-and-contract-strategy.md):349 prices
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

## 5. Running it

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

**256 tests, 0 skipped.**

### Configuration

Every variable is declared in `.env.example` and read in exactly one place, `src/env.ts`.
`env.test.ts` asserts the two agree in **both** directions — a variable declared but unread fails the
suite just as loudly as one read but undeclared.

There is deliberately no `DEVPLATFORM_ADMIN_TOKEN`, no break-glass credential and no reveal switch;
their absence is asserted by name. The equivalent would be a static string that can read or issue
credentials, which is the shape of the omnipotent service tokens SD-05 exists to retire.

---

## 6. Things found in siblings, reported and not fixed

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
   [11-data-and-contract-strategy](../docs/ecosystem/11-data-and-contract-strategy.md):363 names by
   string as the mechanism that propagates a revocation past the gateway's 30-second validation cache
   — cannot be constructed through `makeEvent`. The five topics are local constants in `outbox.ts`,
   validated with `isValidTopicName` (the shape check, which they pass) rather than
   `isRegisteredTopic` (which they cannot until the package adds them).

3. **`@cloudsforge/contracts-devplatform` has not been cut.** 18 §3.5(4) lists it among the four
   uncut packages, and [11](../docs/ecosystem/11-data-and-contract-strategy.md):54 names it as the
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
   backticks inside a template literal (`` `*` `` at :193 and `` `verifyDelivery` `` at :277), which
   closed the string early — migration 4 escapes its own, these two did not. Escaped rather than
   rewritten. Recorded here because it is a change to inherited code in this repository, not a
   sibling's defect.
