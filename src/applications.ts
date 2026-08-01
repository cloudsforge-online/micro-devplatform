/**
 * The application directory.
 *
 * A project may publish one listing. The listing is what a user sees on the consent screen when
 * that project's OAuth client asks for authority — which is why it is here and not in a marketing
 * CMS: the name and the icon a user is asked to trust must come from the same record the credential
 * came from, or the consent screen is showing a claim nobody verified.
 *
 * **A LISTING IS NOT PUBLIC UNTIL SOMEBODY SAID SO.** The transition to `listed` is the only one
 * that changes what an anonymous caller can see, so it is the only one that is not self-service:
 * `submitForReview` is the developer's action and `setApplicationStatus` is the operator's. A
 * directory a developer can publish to unilaterally is a directory that eventually hosts a phishing
 * page wearing a platform's chrome.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TRANSITIONS ARE ENUMERATED, AND `setApplicationStatus` CLAIMS ONE RATHER THAN ASSIGNING.**
 *
 * The first version of this function wrote `set status = $1 where project_id = $2` with no guard,
 * which made every state reachable from every other: an operator could list a `draft` that had
 * never been submitted — publishing copy nobody reviewed, which is the exact failure the review
 * step exists to prevent — and two operators racing on one submission would both report success
 * while one silently overwrote the other. `OPERATOR_TRANSITIONS` names the legal sources for each
 * target and the UPDATE claims with `status = any(...)`, so the second attempt matches no row and
 * says so.
 *
 * **`rejected` is a status of its own, not a reuse of `delisted`.** "We looked and said no" and
 * "you were live and we took you down" are different facts about a developer, they are answered
 * differently by support, and one of them is a resubmission while the other is an appeal. Without
 * the distinction a rejected application is indistinguishable from a delisted one — and, worse,
 * a caller could not tell either from an application still waiting.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * `applications_listed_has_time` makes the pair inseparable at the database: a listed row has a
 * `listed_at`, and a row with a `listed_at` is listed. A state that cannot be dated cannot be
 * audited, and "when did this become visible?" is the first question asked after a bad listing.
 */

import type { Db, Tx } from './outbox.ts'
import { ConflictError, NotFoundError, ValidationError, assertName, assertSlug } from './orgs.ts'

export const APPLICATION_STATUSES = Object.freeze([
  'draft',
  'in_review',
  'listed',
  'rejected',
  'delisted',
] as const)
export type ApplicationStatus = (typeof APPLICATION_STATUSES)[number]

export function isApplicationStatus(value: string): value is ApplicationStatus {
  return (APPLICATION_STATUSES as readonly string[]).includes(value)
}

/**
 * The slug an operator route already occupies, so no listing may take it.
 *
 * `/v1/apps/pending` is the review queue and is matched before `/v1/apps/:slug`. A listing called
 * `pending` would therefore be unreachable at its own public address. `applications_slug_not_reserved`
 * (migration 9) refuses it at the database as well — two layers, because this one gives a developer
 * a sentence they can act on and that one survives a write path that never comes through here.
 */
export const RESERVED_SLUGS: readonly string[] = Object.freeze(['pending'])

/**
 * The statuses an operator may move an application FROM, for each status they may move it TO.
 *
 * Read as: to reach the key, the row must currently be one of the values.
 *
 *   `listed`    from `in_review` (the reviewed submission) or `delisted` (putting a listing back).
 *               NOT from `draft`: a draft has never been submitted, and listing one publishes copy
 *               nobody asked to have reviewed. NOT from `rejected`: the developer resubmits, and
 *               the resubmission is what gets reviewed.
 *   `rejected`  from `in_review` only. Rejecting something nobody submitted is not a decision.
 *   `delisted`  from `listed` only. Taking down what is up. A draft is not "down", it is unsent.
 *
 * `draft` and `in_review` are absent as targets on purpose: they are the DEVELOPER's states.
 * `upsertApplication` creates a draft and `submitForReview` moves it to review, and an operator
 * pushing a row back into either would be editing a customer's submission on their behalf.
 */
export const OPERATOR_TRANSITIONS: Readonly<Record<ApplicationStatus, readonly ApplicationStatus[]>> =
  Object.freeze({
    draft: Object.freeze([]),
    in_review: Object.freeze([]),
    listed: Object.freeze(['in_review', 'delisted'] as const),
    rejected: Object.freeze(['in_review'] as const),
    delisted: Object.freeze(['listed'] as const),
  })

/** The statuses an operator route accepts. Derived, so adding a transition cannot leave it behind. */
export const OPERATOR_STATUSES: readonly ApplicationStatus[] = Object.freeze(
  APPLICATION_STATUSES.filter((status) => OPERATOR_TRANSITIONS[status].length > 0),
)

export interface Application {
  readonly id: string
  readonly projectId: string
  readonly slug: string
  readonly name: string
  readonly tagline: string
  readonly description: string
  readonly homepageUrl: string | null
  readonly status: ApplicationStatus
  readonly listedAt: Date | null
  readonly createdAt: Date
}

interface ApplicationRow {
  readonly id: string
  readonly project_id: string
  readonly slug: string
  readonly name: string
  readonly tagline: string
  readonly description: string
  readonly homepage_url: string | null
  readonly status: string
  readonly listed_at: Date | null
  readonly created_at: Date
}

function toApplication(row: ApplicationRow): Application {
  return {
    id: row.id,
    projectId: row.project_id,
    slug: row.slug,
    name: row.name,
    tagline: row.tagline,
    description: row.description,
    homepageUrl: row.homepage_url,
    status: isApplicationStatus(row.status) ? row.status : 'draft',
    listedAt: row.listed_at,
    createdAt: row.created_at,
  }
}

const COLUMNS = 'id, project_id, slug, name, tagline, description, homepage_url, status, listed_at, created_at'

/** https only, matching `applications_homepage_https`. Same argument as a webhook url. */
function assertHomepage(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined || raw.trim() === '') return null
  const value = raw.trim()
  if (!/^https:\/\/[^*\s]+$/.test(value)) {
    throw new ValidationError('a homepage url must be an absolute https URL with no wildcard')
  }
  return value
}

export interface UpsertApplicationInput {
  readonly projectId: string
  readonly slug: string
  readonly name: string
  readonly tagline?: string
  readonly description?: string
  readonly homepageUrl?: string | null
}

/**
 * Create or update a project's listing.
 *
 * An upsert on `project_id` — one listing per project, which `applications_project_uniq` enforces
 * — so this route is idempotent by construction and a retry updates rather than conflicts.
 *
 * **Editing a LISTED application does not un-list it, and does not re-review it.** That is a
 * deliberate, and arguable, choice: re-review on every copy change would mean a typo fix takes a
 * human, and the practical consequence of that is developers who never fix typos. The status
 * transition is the reviewed event; the copy is not.
 */
export async function upsertApplication(sql: Tx | Db, input: UpsertApplicationInput): Promise<Application> {
  const slug = assertSlug(input.slug, 'slug')
  if (RESERVED_SLUGS.includes(slug)) {
    throw new ValidationError(
      `'${slug}' is reserved: an operator route is served at that address, so a listing there ` +
        'could never be fetched by its own slug',
    )
  }
  const name = assertName(input.name, 'name')
  const homepage = assertHomepage(input.homepageUrl)
  const tagline = (input.tagline ?? '').trim().slice(0, 300)
  const description = (input.description ?? '').trim().slice(0, 10_000)

  const projects = await sql<{ id: string }[]>`select id from projects where id = ${input.projectId}`
  if (!projects[0]) throw new NotFoundError('no such project')

  const rows = await sql<ApplicationRow[]>`
    insert into applications (project_id, slug, name, tagline, description, homepage_url)
    values (${input.projectId}, ${slug}, ${name}, ${tagline}, ${description}, ${homepage})
    on conflict (project_id) do update
      set slug = excluded.slug,
          name = excluded.name,
          tagline = excluded.tagline,
          description = excluded.description,
          homepage_url = excluded.homepage_url,
          updated_at = now()
    returning ${sql.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (!row) throw new ValidationError(`the slug '${slug}' is already taken by another application`)
  return toApplication(row)
}

/**
 * The developer's action. Into `in_review`, and nothing else.
 *
 * `rejected` is a legal source: a rejection is a decision about a submission, not a sentence on the
 * project, and the developer's remedy is to fix what was wrong and ask again. A rejected listing
 * that could never be resubmitted would make one operator's "no" permanent, which is not what
 * anyone rejecting a listing means.
 */
export async function submitForReview(sql: Tx | Db, projectId: string): Promise<Application> {
  const rows = await sql<ApplicationRow[]>`
    update applications set status = 'in_review', updated_at = now()
     where project_id = ${projectId} and status in ('draft','delisted','rejected')
    returning ${sql.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (row) return toApplication(row)
  const existing = await findApplicationByProject(sql, projectId)
  if (!existing) throw new NotFoundError('this project has no application listing')
  // Already in review or already listed. Not an error — a retried submission is the first one.
  return existing
}

/**
 * The operator's action. The transition that completes the lifecycle.
 *
 * **The move is CLAIMED, not assigned.** `where status = any(...)` names the legal sources from
 * `OPERATOR_TRANSITIONS`, so two operators deciding one submission produce one winner and one
 * `ConflictError` rather than two successes and a last-write-wins. An unguarded assignment also
 * made `draft → listed` reachable, which publishes copy nobody reviewed.
 *
 * A no-row result is disambiguated by a second read, because "this project has no listing" and
 * "this listing is not in a state that can become `listed`" are different answers and a caller
 * that received one for the other would retry the wrong thing.
 *
 * `listed_at` is set in the same statement as the status, which is what
 * `applications_listed_has_time` requires. Setting it from a second statement would leave a window
 * in which the CHECK is violated, and the CHECK would refuse the first one.
 */
export async function setApplicationStatus(
  sql: Tx | Db,
  projectId: string,
  status: ApplicationStatus,
): Promise<Application> {
  const from = OPERATOR_TRANSITIONS[status]
  if (from.length === 0) {
    throw new ValidationError(
      `an operator may not set an application to '${status}': ` +
        `the statuses an operator decides are ${OPERATOR_STATUSES.join(', ')}`,
    )
  }
  const rows = await sql<ApplicationRow[]>`
    update applications
       set status = ${status},
           listed_at = ${status === 'listed' ? sql`coalesce(listed_at, now())` : sql`null`},
           updated_at = now()
     where project_id = ${projectId} and status = any(${sql.array([...from])})
    returning ${sql.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (row) return toApplication(row)

  const existing = await findApplicationByProject(sql, projectId)
  if (!existing) throw new NotFoundError('this project has no application listing')
  throw new ConflictError(
    `an application in '${existing.status}' cannot become '${status}'; ` +
      `only ${from.join(' or ')} can`,
  )
}

/**
 * The review queue: everything waiting on an operator, oldest first.
 *
 * Oldest first rather than newest, because this is a WORK queue and the thing that must not happen
 * is a submission that is never reached. Newest-first ordering on a queue nobody empties starves
 * exactly the developer who has been waiting longest.
 *
 * Operator-only at the route (`GET /v1/apps/pending`). It returns unlisted rows — drafts a
 * developer has submitted but nobody has approved — and serving those publicly would be the
 * directory leak `listDirectory` is arranged to prevent.
 */
export async function listForReview(
  sql: Tx | Db,
  options: { readonly limit?: number } = {},
): Promise<readonly Application[]> {
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 500)
  const rows = await sql<ApplicationRow[]>`
    select ${sql.unsafe(COLUMNS)} from applications
     where status = 'in_review' order by updated_at asc limit ${limit}
  `
  return rows.map(toApplication)
}

export async function findApplicationByProject(
  sql: Tx | Db,
  projectId: string,
): Promise<Application | null> {
  const rows = await sql<ApplicationRow[]>`
    select ${sql.unsafe(COLUMNS)} from applications where project_id = ${projectId}
  `
  const row = rows[0]
  return row ? toApplication(row) : null
}

export async function findListedApplication(sql: Tx | Db, slug: string): Promise<Application | null> {
  const rows = await sql<ApplicationRow[]>`
    select ${sql.unsafe(COLUMNS)} from applications where slug = ${slug} and status = 'listed'
  `
  const row = rows[0]
  return row ? toApplication(row) : null
}

/**
 * The public directory.
 *
 * `status = 'listed'` is in the query rather than applied by the caller. A filter the caller has to
 * remember is a filter that will one day be forgotten, and the consequence here is a draft listing
 * — including one written by someone probing what the directory will render — served to the public.
 */
export async function listDirectory(
  sql: Tx | Db,
  options: { readonly limit?: number } = {},
): Promise<readonly Application[]> {
  const limit = Math.min(Math.max(options.limit ?? 100, 1), 500)
  const rows = await sql<ApplicationRow[]>`
    select ${sql.unsafe(COLUMNS)} from applications
     where status = 'listed' order by listed_at desc limit ${limit}
  `
  return rows.map(toApplication)
}
