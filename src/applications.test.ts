/**
 * The application directory, against a real Postgres.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS FILE DID NOT EXIST, AND THAT IS WHY THE LIFECYCLE WAS BROKEN FOR SO LONG.**
 *
 * `applications.ts` shipped with no test of its own. The only case that touched the directory was
 * `server.test.ts`'s "a listing is not public until an operator lists it", and it reached `listed`
 * with a hand-written `update applications set status = 'listed'` — so the suite proved the
 * DIRECTORY worked while `setApplicationStatus`, the function that is supposed to perform that
 * transition, was imported by the server and called by nothing at all. A test that writes the row
 * itself cannot notice that nothing else can.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The properties below are the ones an unguarded `set status = $1` gets wrong, and each is written
 * so the unguarded version fails it:
 *
 *   * a draft cannot be listed — publishing copy nobody reviewed is what the review step prevents;
 *   * two operators deciding one submission produce one winner and one 409, not two successes;
 *   * a rejection is distinguishable from a delisting AND from a submission still waiting;
 *   * a rejected listing can be revised and resubmitted, so one "no" is not permanent.
 */

import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  APPLICATION_STATUSES,
  OPERATOR_STATUSES,
  OPERATOR_TRANSITIONS,
  RESERVED_SLUGS,
  findApplicationByProject,
  findListedApplication,
  isApplicationStatus,
  listDirectory,
  listForReview,
  setApplicationStatus,
  submitForReview,
  upsertApplication,
} from './applications.ts'
import { ConflictError, NotFoundError, ValidationError } from './orgs.ts'
import type { Db } from './outbox.ts'
import { migrateTestDb, openDb, resetDevplatform, seedWorkspace, skip, uniqueSlug } from './testsupport.ts'

/* ------------------------------------------------------------------ the vocabulary */

test('the status vocabulary tells a rejection from a delisting, and from a wait', () => {
  // Four statuses meant a refused application had nowhere to go but `delisted` — the same value as
  // a listing that WAS public and was taken down. Support answers those two differently, and one of
  // them is a resubmission while the other is an appeal.
  assert.ok(isApplicationStatus('rejected'))
  assert.ok(isApplicationStatus('delisted'))
  assert.ok(isApplicationStatus('in_review'))
  assert.ok(!isApplicationStatus('refused'))
  assert.equal(new Set(APPLICATION_STATUSES).size, APPLICATION_STATUSES.length)
})

test('the statuses an operator may set are exactly those with a legal source', () => {
  // Derived rather than written down twice, so adding a transition cannot leave the route behind.
  assert.deepEqual([...OPERATOR_STATUSES].sort(), ['delisted', 'listed', 'rejected'])
  for (const status of OPERATOR_STATUSES) {
    assert.ok(OPERATOR_TRANSITIONS[status].length > 0, `${status} has no source`)
  }
  // `draft` and `in_review` are the DEVELOPER's states. An operator pushing a row into either would
  // be editing a customer's submission on their behalf.
  assert.deepEqual([...OPERATOR_TRANSITIONS.draft], [])
  assert.deepEqual([...OPERATOR_TRANSITIONS.in_review], [])
})

test('every source named in a transition is itself a known status', () => {
  // A typo here would be a transition that can never fire, which looks exactly like a policy.
  for (const [target, sources] of Object.entries(OPERATOR_TRANSITIONS)) {
    for (const source of sources) {
      assert.ok(isApplicationStatus(source), `${target} names an unknown source '${source}'`)
    }
  }
})

/* ------------------------------------------------------------------ against Postgres */

test('applications', { skip }, async (t) => {
  const sql = openDb()
  await migrateTestDb(sql)
  t.after(async () => {
    await sql.end({ timeout: 5 })
  })
  t.beforeEach(() => resetDevplatform(sql))

  const store = sql as unknown as Db

  /** A project with a draft listing on it. The starting point of every case below. */
  async function draft(): Promise<{ projectId: string; slug: string }> {
    const { project } = await seedWorkspace(sql)
    const slug = uniqueSlug('app')
    await upsertApplication(store, { projectId: project.id, slug, name: 'My App' })
    return { projectId: project.id, slug }
  }

  /* ---------------------------------------------------------------- the happy lifecycle */

  await t.test('THE LIFECYCLE COMPLETES: draft, review, listed, and the directory shows it', async () => {
    // The path nothing in this repository could walk before: `setApplicationStatus` was a dead
    // import, so `in_review` was a terminal state and the directory could never be populated.
    const { projectId, slug } = await draft()

    assert.equal((await findApplicationByProject(store, projectId))?.status, 'draft')
    assert.equal(await findListedApplication(store, slug), null, 'a draft is public')

    assert.equal((await submitForReview(store, projectId)).status, 'in_review')
    assert.equal(await findListedApplication(store, slug), null, 'a submission is public')

    const listed = await setApplicationStatus(store, projectId, 'listed')
    assert.equal(listed.status, 'listed')
    assert.ok(listed.listedAt, 'a listed row carries no listed_at — applications_listed_has_time')

    assert.equal((await findListedApplication(store, slug))?.slug, slug)
    assert.ok((await listDirectory(store)).some((application) => application.slug === slug))
  })

  await t.test('a listing can be taken down and put back, and keeps its first listed_at', async () => {
    const { projectId, slug } = await draft()
    await submitForReview(store, projectId)
    const first = await setApplicationStatus(store, projectId, 'listed')

    const delisted = await setApplicationStatus(store, projectId, 'delisted')
    assert.equal(delisted.status, 'delisted')
    assert.equal(delisted.listedAt, null, 'a delisted row kept its listed_at')
    assert.equal(await findListedApplication(store, slug), null)

    const relisted = await setApplicationStatus(store, projectId, 'listed')
    assert.equal(relisted.status, 'listed')
    // `coalesce(listed_at, now())` — but the delisting nulled it, so this is a fresh time and the
    // audit answer to "when did this become visible?" is the CURRENT visibility, not the first.
    assert.ok(relisted.listedAt && relisted.listedAt >= first.listedAt!)
  })

  /* ---------------------------------------------------------------- the refusals */

  await t.test('A DRAFT CANNOT BE LISTED — the review step is not optional', async () => {
    // The transition an unguarded `set status = $1` made reachable. Listing a draft publishes copy
    // nobody asked to have reviewed, which is the whole reason the directory has a review step.
    const { projectId, slug } = await draft()
    await assert.rejects(
      () => setApplicationStatus(store, projectId, 'listed'),
      (err: unknown) => err instanceof ConflictError && String(err).includes('draft'),
    )
    assert.equal(await findListedApplication(store, slug), null)
    assert.equal((await findApplicationByProject(store, projectId))?.status, 'draft')
  })

  await t.test('a submission nobody made cannot be rejected either', async () => {
    const { projectId } = await draft()
    await assert.rejects(
      () => setApplicationStatus(store, projectId, 'rejected'),
      ConflictError,
      'a draft was rejected — rejecting something nobody submitted is not a decision',
    )
  })

  await t.test('an operator may not set a status that is the developer\'s to set', async () => {
    const { projectId } = await draft()
    for (const status of ['draft', 'in_review'] as const) {
      await assert.rejects(
        () => setApplicationStatus(store, projectId, status),
        (err: unknown) => err instanceof ValidationError && String(err).includes(status),
        `an operator set an application to ${status}`,
      )
    }
  })

  await t.test('a project with no listing is a not-found, not a conflict', async () => {
    // The two are different answers and a caller that received one for the other would retry the
    // wrong thing: one is "create the listing first", the other is "the state has moved on".
    const { project } = await seedWorkspace(sql)
    await assert.rejects(() => setApplicationStatus(store, project.id, 'listed'), NotFoundError)
  })

  await t.test('TWO OPERATORS DECIDING ONE SUBMISSION PRODUCE ONE WINNER', async () => {
    // The claim is `where status = any(...)`, so the second attempt matches no row. An unguarded
    // assignment gives both callers a success and silently keeps whichever committed last —
    // including "listed" overwriting "rejected", which publishes what somebody just refused.
    const { projectId, slug } = await draft()
    await submitForReview(store, projectId)

    const outcomes = await Promise.allSettled([
      setApplicationStatus(store, projectId, 'listed'),
      setApplicationStatus(store, projectId, 'rejected'),
    ])
    const fulfilled = outcomes.filter((outcome) => outcome.status === 'fulfilled')
    assert.equal(fulfilled.length, 1, 'both operators were told they decided the application')
    for (const outcome of outcomes) {
      if (outcome.status === 'rejected') assert.ok(outcome.reason instanceof ConflictError)
    }

    const settled = await findApplicationByProject(store, projectId)
    assert.ok(settled)
    assert.equal(
      settled.status === 'listed',
      (await findListedApplication(store, slug)) !== null,
      'the directory disagrees with the row about whether this application is public',
    )
  })

  /* ---------------------------------------------------------------- rejection */

  await t.test('A REJECTION IS DISTINGUISHABLE FROM A DELISTING AND FROM A WAIT', async () => {
    const rejected = await draft()
    await submitForReview(store, rejected.projectId)
    assert.equal((await setApplicationStatus(store, rejected.projectId, 'rejected')).status, 'rejected')

    const delisted = await draft()
    await submitForReview(store, delisted.projectId)
    await setApplicationStatus(store, delisted.projectId, 'listed')
    await setApplicationStatus(store, delisted.projectId, 'delisted')

    const waiting = await draft()
    await submitForReview(store, waiting.projectId)

    const statuses = await Promise.all(
      [rejected, delisted, waiting].map(async ({ projectId }) =>
        (await findApplicationByProject(store, projectId))?.status,
      ),
    )
    assert.deepEqual(statuses, ['rejected', 'delisted', 'in_review'])
    assert.equal(new Set(statuses).size, 3, 'two of these three states are indistinguishable')
  })

  await t.test('a rejected listing can be revised and resubmitted; one "no" is not permanent', async () => {
    const { projectId, slug } = await draft()
    await submitForReview(store, projectId)
    await setApplicationStatus(store, projectId, 'rejected')

    // The developer fixes what was wrong. Editing does not change the status — the copy is not the
    // reviewed event — so the resubmission is what asks for the decision again.
    const revised = await upsertApplication(store, {
      projectId,
      slug,
      name: 'My App',
      tagline: 'now with a working homepage',
      homepageUrl: 'https://example.com',
    })
    assert.equal(revised.status, 'rejected')
    assert.equal((await submitForReview(store, projectId)).status, 'in_review')
    assert.equal((await setApplicationStatus(store, projectId, 'listed')).status, 'listed')
  })

  /* ---------------------------------------------------------------- the review queue */

  await t.test('the review queue holds what is waiting, oldest first, and nothing else', async () => {
    // Oldest first because this is a WORK queue: newest-first ordering on a queue nobody empties
    // starves exactly the developer who has been waiting longest.
    const waitingFirst = await draft()
    await submitForReview(store, waitingFirst.projectId)
    const waitingSecond = await draft()
    await submitForReview(store, waitingSecond.projectId)

    const stillDraft = await draft()
    const alreadyListed = await draft()
    await submitForReview(store, alreadyListed.projectId)
    await setApplicationStatus(store, alreadyListed.projectId, 'listed')
    const wasRejected = await draft()
    await submitForReview(store, wasRejected.projectId)
    await setApplicationStatus(store, wasRejected.projectId, 'rejected')

    const queue = await listForReview(store)
    assert.deepEqual(
      queue.map((application) => application.slug),
      [waitingFirst.slug, waitingSecond.slug],
      'the queue is not exactly the submissions waiting on a decision, in the order they arrived',
    )
    for (const absent of [stillDraft, alreadyListed, wasRejected]) {
      assert.ok(!queue.some((application) => application.slug === absent.slug))
    }
  })

  await t.test('the review queue is bounded whatever the caller asks for', async () => {
    const { projectId } = await draft()
    await submitForReview(store, projectId)
    assert.equal((await listForReview(store, { limit: 0 })).length, 1, 'a limit of 0 emptied the queue')
    assert.equal((await listForReview(store, { limit: 10_000 })).length, 1)
  })

  /* ---------------------------------------------------------------- the reserved slug */

  await t.test('a listing may not take a slug an operator route already serves', async () => {
    // `/v1/apps/pending` is matched before `/v1/apps/:slug`, so a listing called `pending` could
    // never be fetched at its own public address. `applications_slug_not_reserved` refuses it at
    // the database too — this layer is the sentence a developer can act on.
    const { project } = await seedWorkspace(sql)
    for (const slug of RESERVED_SLUGS) {
      await assert.rejects(
        () => upsertApplication(store, { projectId: project.id, slug, name: 'My App' }),
        (err: unknown) => err instanceof ValidationError && String(err).includes('reserved'),
        `'${slug}' was accepted as a slug`,
      )
    }
    // And a slug that merely contains one is fine, so this is a reservation rather than a filter.
    await upsertApplication(store, { projectId: project.id, slug: 'pending-review', name: 'My App' })
  })

  await t.test('an upsert refuses a homepage that is not absolute https', async () => {
    const { project } = await seedWorkspace(sql)
    for (const homepageUrl of ['http://example.com', 'https://*.example.com', '/relative']) {
      await assert.rejects(
        () =>
          upsertApplication(store, {
            projectId: project.id,
            slug: uniqueSlug('app'),
            name: 'My App',
            homepageUrl,
          }),
        ValidationError,
        `${homepageUrl} was accepted`,
      )
    }
  })

  await t.test('the directory serves only listed rows, whatever the caller asks for', async () => {
    // The filter is inside the query rather than applied by the caller: a filter somebody has to
    // remember is one that will one day be forgotten, and the consequence is a draft — including
    // one written by somebody probing what the directory will render — served to the public.
    for (const status of ['draft', 'in_review', 'rejected'] as const) {
      const { projectId } = await draft()
      if (status !== 'draft') await submitForReview(store, projectId)
      if (status === 'rejected') await setApplicationStatus(store, projectId, 'rejected')
    }
    assert.deepEqual(await listDirectory(store), [])
  })
})
