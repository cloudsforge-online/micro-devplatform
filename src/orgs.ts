/**
 * Developer organisations, projects and environments.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **IDENTITY OWNS ORGANISATIONS. THIS SERVICE OWNS THEIR ENROLMENT.**
 *
 * `07-dependency-map.md` makes `devplatform → identity` a **hard** dependency for
 * "Developer organisation and membership", and `02-target-architecture.md` states the
 * division in one sentence: "Identity issues *the token*; devplatform issues *the credential that
 * requests the token*. Devplatform is a client of identity, exactly like every other product."
 *
 * So `developer_orgs` holds an enrolment keyed by `identity_org_id` — the plan, the status, the
 * slug a developer sees — and holds **no membership rows at all**. Membership is asked of identity
 * on the request that needs it. A mirrored membership table is a membership that can be stale at
 * exactly the moment somebody is removed from an organisation, which is the moment it matters, and
 * `11-data-and-contract-strategy.md` prices the staleness this estate accepts for that data at
 * 60 seconds — acceptable for rendering a list, not for deciding who may mint a credential.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A PROJECT IS CREATED WITH BOTH ENVIRONMENTS, IN ONE TRANSACTION.** `live` and `test` are rows,
 * not an enum: keys, quotas, webhook endpoints and usage all hang off an environment, and a
 * foreign key to a row is the only version of "this key belongs to this environment" the database
 * can enforce. Creating them with the project means there is no window in which a project exists
 * with nowhere to put a key.
 */

import type { Actor } from '@cloudsforge/contracts-events'
import type { Db, Emit, Tx } from './outbox.ts'
import { TOPICS } from './outbox.ts'
import type { KeyEnvironment } from './keys.ts'
import { KEY_ENVIRONMENTS } from './keys.ts'

export class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

export class ConflictError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConflictError'
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ValidationError'
  }
}

const SLUG = /^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$/

/**
 * Slugs are validated here AND constrained in the schema.
 *
 * Two layers because a slug reaches a URL, and the day someone adds a bulk import or an admin
 * backfill is the day the application layer is bypassed. The application refuses with a message a
 * developer can act on; the database refuses with 23514 whatever the write path.
 */
export function assertSlug(value: string, field: string): string {
  const slug = value.trim().toLowerCase()
  if (!SLUG.test(slug)) {
    throw new ValidationError(
      `${field} must be 3 to 64 characters of lowercase letters, digits and hyphens, ` +
        'starting and ending with a letter or digit',
    )
  }
  return slug
}

export function assertName(value: string, field: string): string {
  const name = value.trim()
  if (name.length < 1 || name.length > 200) {
    throw new ValidationError(`${field} must be 1 to 200 characters`)
  }
  return name
}

/* ------------------------------------------------------------------ developer orgs */

export interface DeveloperOrg {
  readonly id: string
  readonly identityOrgId: string
  readonly name: string
  readonly slug: string
  readonly status: 'active' | 'suspended'
  readonly createdAt: Date
}

interface OrgRow {
  readonly id: string
  readonly identity_org_id: string
  readonly name: string
  readonly slug: string
  readonly status: string
  readonly created_at: Date
}

function toOrg(row: OrgRow): DeveloperOrg {
  return {
    id: row.id,
    identityOrgId: row.identity_org_id,
    name: row.name,
    slug: row.slug,
    status: row.status === 'suspended' ? 'suspended' : 'active',
    createdAt: row.created_at,
  }
}

export interface EnrolOrgInput {
  readonly identityOrgId: string
  readonly name: string
  readonly slug: string
}

/**
 * Enrol an identity organisation in the developer platform.
 *
 * Idempotent on `identity_org_id` by construction: `on conflict do nothing` followed by a read.
 * That is what makes the route safe without a wrapper — the natural key is the organisation, and
 * a second enrolment of the same organisation is the first one.
 */
export async function enrolOrg(sql: Tx | Db, input: EnrolOrgInput): Promise<DeveloperOrg> {
  const slug = assertSlug(input.slug, 'slug')
  const name = assertName(input.name, 'name')
  const identityOrgId = input.identityOrgId.trim()
  if (identityOrgId.length === 0) throw new ValidationError('identityOrgId is required')

  const inserted = await sql<OrgRow[]>`
    insert into developer_orgs (identity_org_id, name, slug)
    values (${identityOrgId}, ${name}, ${slug})
    on conflict (identity_org_id) do nothing
    returning id, identity_org_id, name, slug, status, created_at
  `
  const row = inserted[0]
  if (row) return toOrg(row)

  const existing = await sql<OrgRow[]>`
    select id, identity_org_id, name, slug, status, created_at
      from developer_orgs where identity_org_id = ${identityOrgId}
  `
  const found = existing[0]
  if (!found) {
    // The insert conflicted on something that is not `identity_org_id` — the only other unique
    // constraint on this table is the slug. Said plainly, because "conflict" with no subject is
    // the least useful error a developer console can render.
    throw new ConflictError(`the slug '${slug}' is already taken by another organisation`)
  }
  return toOrg(found)
}

export async function findOrg(sql: Tx | Db, id: string): Promise<DeveloperOrg | null> {
  const rows = await sql<OrgRow[]>`
    select id, identity_org_id, name, slug, status, created_at from developer_orgs where id = ${id}
  `
  const row = rows[0]
  return row ? toOrg(row) : null
}

export async function findOrgByIdentityId(sql: Tx | Db, identityOrgId: string): Promise<DeveloperOrg | null> {
  const rows = await sql<OrgRow[]>`
    select id, identity_org_id, name, slug, status, created_at
      from developer_orgs where identity_org_id = ${identityOrgId}
  `
  const row = rows[0]
  return row ? toOrg(row) : null
}

/**
 * Suspend an organisation.
 *
 * Suspension is a status, not a deletion, and it is not a revocation of every key either: the keys
 * survive so that reinstatement is one state change rather than a re-issue of every credential the
 * organisation ever handed to a customer. Authentication consults the status (`apikeys.ts`), so a
 * suspended organisation's keys stop working immediately without any row being destroyed.
 */
export async function setOrgStatus(
  sql: Tx | Db,
  id: string,
  status: 'active' | 'suspended',
): Promise<DeveloperOrg> {
  const rows = await sql<OrgRow[]>`
    update developer_orgs set status = ${status}, updated_at = now()
     where id = ${id}
    returning id, identity_org_id, name, slug, status, created_at
  `
  const row = rows[0]
  if (!row) throw new NotFoundError('no such developer organisation')
  return toOrg(row)
}

/* ------------------------------------------------------------------ projects */

export interface Environment {
  readonly id: string
  readonly projectId: string
  readonly name: KeyEnvironment
}

export interface Project {
  readonly id: string
  readonly orgId: string
  readonly name: string
  readonly slug: string
  readonly status: 'active' | 'archived'
  readonly createdAt: Date
  readonly environments: readonly Environment[]
}

interface ProjectRow {
  readonly id: string
  readonly org_id: string
  readonly name: string
  readonly slug: string
  readonly status: string
  readonly created_at: Date
}

interface EnvironmentRow {
  readonly id: string
  readonly project_id: string
  readonly name: string
}

function toEnvironment(row: EnvironmentRow): Environment {
  return { id: row.id, projectId: row.project_id, name: row.name === 'live' ? 'live' : 'test' }
}

export interface CreateProjectInput {
  readonly orgId: string
  readonly name: string
  readonly slug: string
}

/**
 * Create a project and both of its environments.
 *
 * Takes a transaction rather than a pool on purpose. The project, its two environments and its
 * default quotas are one fact — a project with no `test` environment is a project a developer
 * cannot try anything in — and the caller wraps them with the outbox row that announces it.
 */
export async function createProject(tx: Tx, input: CreateProjectInput): Promise<Project> {
  const slug = assertSlug(input.slug, 'slug')
  const name = assertName(input.name, 'name')

  const orgs = await tx<{ id: string }[]>`select id from developer_orgs where id = ${input.orgId}`
  if (!orgs[0]) throw new NotFoundError('no such developer organisation')

  const inserted = await tx<ProjectRow[]>`
    insert into projects (org_id, name, slug)
    values (${input.orgId}, ${name}, ${slug})
    on conflict (org_id, slug) do nothing
    returning id, org_id, name, slug, status, created_at
  `
  const row = inserted[0]
  if (!row) throw new ConflictError(`this organisation already has a project with the slug '${slug}'`)

  const environments: Environment[] = []
  for (const environment of KEY_ENVIRONMENTS) {
    const envRows = await tx<EnvironmentRow[]>`
      insert into environments (project_id, name) values (${row.id}, ${environment})
      returning id, project_id, name
    `
    const envRow = envRows[0]
    // Cannot happen — the insert has no `on conflict` and would have thrown — but the type says it
    // can, and `noUncheckedIndexedAccess` is right to. A silent `continue` here would produce a
    // project with one environment and no error, which is the failure this whole function avoids.
    if (!envRow) throw new Error('environment insert returned no row')
    environments.push(toEnvironment(envRow))
  }

  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    slug: row.slug,
    status: 'active',
    createdAt: row.created_at,
    environments,
  }
}

export async function findProject(sql: Tx | Db, id: string): Promise<Project | null> {
  const rows = await sql<ProjectRow[]>`
    select id, org_id, name, slug, status, created_at from projects where id = ${id}
  `
  const row = rows[0]
  if (!row) return null
  const envRows = await sql<EnvironmentRow[]>`
    select id, project_id, name from environments where project_id = ${id} order by name
  `
  return {
    id: row.id,
    orgId: row.org_id,
    name: row.name,
    slug: row.slug,
    status: row.status === 'archived' ? 'archived' : 'active',
    createdAt: row.created_at,
    environments: envRows.map(toEnvironment),
  }
}

export async function listProjects(sql: Tx | Db, orgId: string): Promise<readonly Project[]> {
  const rows = await sql<ProjectRow[]>`
    select id, org_id, name, slug, status, created_at
      from projects where org_id = ${orgId} order by created_at desc
  `
  const out: Project[] = []
  for (const row of rows) {
    const project = await findProject(sql, row.id)
    if (project) out.push(project)
  }
  return out
}

export async function findEnvironment(
  sql: Tx | Db,
  projectId: string,
  name: KeyEnvironment,
): Promise<Environment | null> {
  const rows = await sql<EnvironmentRow[]>`
    select id, project_id, name from environments where project_id = ${projectId} and name = ${name}
  `
  const row = rows[0]
  return row ? toEnvironment(row) : null
}

/** Announce a project. The caller holds the transaction; this is the event that goes with it. */
export function emitProjectCreated(emit: Emit, project: Project, actor: Actor): void {
  emit({
    topic: TOPICS.projectCreated,
    key: project.id,
    actor,
    payload: {
      projectId: project.id,
      orgId: project.orgId,
      slug: project.slug,
      environments: project.environments.map((environment) => environment.name),
    },
  })
}
