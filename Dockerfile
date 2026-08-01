# syntax=docker/dockerfile:1.7
#
# Build context is this repository, plus two named contexts for the unpublished first-party
# packages:
#
#   docker build -t devplatform \
#     --build-context runtimepkgs=../runtime \
#     --build-context contractspkgs=../contracts .
#
# The extra contexts are temporary. Once the @cloudsforge/* packages are published (AD-02),
# package.json takes registry versions, the COPY lines marked below are deleted, the flags go away,
# and this becomes an ordinary single-context build.
#
# They are named `runtimepkgs` and `contractspkgs` rather than `runtime` and `contracts` because a
# build context and a build stage share one namespace, and the final stage below is called
# `runtime`.
#
# This service takes BOTH, unlike lantern: `src/outbox.ts` imports `@cloudsforge/contracts-events`
# for the delivery signature scheme (`signDelivery`, `verifyDelivery`, `SIGNATURE_HEADER`), so the
# contracts workspace must exist at `../contracts` inside the image for the `link:` to resolve.

# ----------------------------------------------------------------------------------- deps
FROM node:22-slim AS deps
# Pin pnpm in the image. The sibling workspaces are installed before this service's own
# package.json is copied, so corepack has no packageManager field to read at that point and would
# otherwise grab whatever is latest and then refuse to switch to the 11.9.0 the siblings pin.
RUN corepack enable && corepack prepare pnpm@11.9.0 --activate
WORKDIR /app

# Temporary: the link: dependencies resolve to ../runtime and ../contracts relative to this
# directory, so the packages must exist at those paths inside the image for the lockfile to stay
# frozen. `link:` in particular resolves at install time to the sibling's own node_modules.
COPY --from=runtimepkgs package.json pnpm-workspace.yaml pnpm-lock.yaml /runtime/
COPY --from=runtimepkgs packages /runtime/packages
COPY --from=contractspkgs package.json pnpm-workspace.yaml pnpm-lock.yaml /contracts/
COPY --from=contractspkgs packages /contracts/packages

# Install each sibling workspace's OWN dependencies first. `link:` uses the sibling as-is and does
# not manage its dependency tree, so their node_modules must exist independently — both for `tsc` to
# resolve the source it typechecks (jose, @opentelemetry/api) and for `node --import tsx` to load
# @cloudsforge/* at run time. Without this the image builds a set of @cloudsforge symlinks that
# point at source which cannot resolve its own imports.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store,sharing=locked \
    pnpm --dir /runtime install --frozen-lockfile --config.store-dir=/pnpm-store
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store,sharing=locked \
    pnpm --dir /contracts install --frozen-lockfile --config.store-dir=/pnpm-store

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
# `--frozen-lockfile` is the point of the step: a build that silently resolves a different
# dependency tree from the one CI tested is a build whose provenance means nothing.
RUN --mount=type=cache,id=pnpm-store,target=/pnpm-store,sharing=locked \
    pnpm install --frozen-lockfile --config.store-dir=/pnpm-store

# ----------------------------------------------------------------------------------- build
# `tsc --noEmit` rather than an emit: tsx runs the TypeScript sources directly, exactly as every
# service in the estate already does. What this stage buys is that a type error fails the image
# build instead of the first request.
FROM deps AS build
COPY tsconfig.json tsconfig.base.json ./
COPY src ./src
RUN pnpm typecheck

# ----------------------------------------------------------------------------------- runtime
FROM node:22-slim AS runtime
WORKDIR /app

# No corepack, no pnpm, no build toolchain in the final image: fewer things an RCE can reach, and
# nothing at runtime needs them. That argument carries more weight here than anywhere else in the
# estate — this container's database holds every third-party credential on the platform.
#
# /runtime and /contracts come across too: /app/node_modules holds @cloudsforge/* as symlinks into
# them, so without the targets the links dangle and the first `import '@cloudsforge/db'` fails at
# run time.
COPY --from=build /runtime /runtime
COPY --from=build /contracts /contracts
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/tsconfig.json /app/tsconfig.base.json ./
COPY --from=build /app/src ./src

# node:22-slim ships an unprivileged `node` user (uid 1000). Nothing is written to the filesystem at
# runtime, so read-only ownership of the image is sufficient.
USER node

# No secret is baked in, and none may be: every value in src/env.ts is supplied by the deploy at run
# time. There is no ENV line here on purpose — least of all DEVPLATFORM_INGEST_SECRETS or
# OUTBOX_SIGNING_SECRET, which are exactly the things a leaked image layer would hand over.
#
# There is also no DEVPLATFORM_ADMIN_TOKEN to leak, because there is no such variable: this service
# has no break-glass credential and no reveal switch. See src/env.ts.
ENV NODE_ENV=production
EXPOSE 4000

# The health endpoints are for the orchestrator, not for the image: the balancer probes /readyz and
# the restart policy probes /livez. A HEALTHCHECK here would duplicate that in a second place that
# then drifts.

# The migrator is a SEPARATE one-shot process — `node --import tsx src/migrator.ts` — run as an init
# container or a Kubernetes Job before this ever starts. It is deliberately not invoked here: below
# SCHEMA_VERSION the `api_keys_slow_kdf_only` CHECK may not exist, and a service that could create it
# at boot is a service that could start without it — which is a service that would happily write a
# SHA-256 hash into the credential table. `index.ts` asserts the schema version and refuses to serve
# below it.
CMD ["node", "--import", "tsx", "src/index.ts"]
