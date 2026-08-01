/**
 * The application directory.
 *
 * A project may publish one listing. The listing is what a user sees on the consent screen when
 * that project's OAuth client asks for authority — which is why it is here and not in a marketing
 * CMS: the name and the icon a user is asked to trust must come from the same record the credential
 * came from, or the consent screen is showing a claim nobody verified.
 *
 * **A LISTING IS NOT PUBLIC UNTIL SOMEBODY SAID SO.** `draft → in_review → listed`, and `delisted`
 * from anywhere. The transition to `listed` is the only one that changes what an anonymous caller
 * can see, so it is the only one that is not self-service: `submitForReview` is the developer's
 * action and `setStatus` is the operator's. A directory a developer can publish to unilaterally is
 * a directory that eventually hosts a phishing page wearing a platform's chrome.
 *
 * `applications_listed_has_time` makes the pair inseparable at the database: a listed row has a
 * `listed_at`, and a row with a `listed_at` is listed. A state that cannot be dated cannot be
 * audited, and "when did this become visible?" is the first question asked after a bad listing.
 */

import type { Db, Tx } from './outbox.ts'
import { NotFoundError, ValidationError, assertName, assertSlug } from './orgs.ts'

export const APPLICATION_STATUSES = Object.freeze(['draft', 'in_review', 'listed', 'delisted'] as const)
export type ApplicationStatus = (typeof APPLICATION_STATUSES)[number]

export function isApplicationStatus(value: string): value is ApplicationStatus {
  return (APPLICATION_STATUSES as readonly string[]).includes(value)
}

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

/** The developer's action. `draft → in_review` and nothing else. */
export async function submitForReview(sql: Tx | Db, projectId: string): Promise<Application> {
  const rows = await sql<ApplicationRow[]>`
    update applications set status = 'in_review', updated_at = now()
     where project_id = ${projectId} and status in ('draft','delisted')
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
 * The operator's action.
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
  const rows = await sql<ApplicationRow[]>`
    update applications
       set status = ${status},
           listed_at = ${status === 'listed' ? sql`coalesce(listed_at, now())` : sql`null`},
           updated_at = now()
     where project_id = ${projectId}
    returning ${sql.unsafe(COLUMNS)}
  `
  const row = rows[0]
  if (!row) throw new NotFoundError('this project has no application listing')
  return toApplication(row)
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
