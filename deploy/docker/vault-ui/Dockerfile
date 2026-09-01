# syntax=docker/dockerfile:1
# vault-ui — Next.js (standalone output). Build context is the repo root, to
# match the CI convention (context: ., file: deploy/docker/<svc>/Dockerfile).

FROM node:22-alpine AS deps
WORKDIR /app
COPY ui/apps/vault-ui/package.json ui/apps/vault-ui/package-lock.json ./
RUN npm ci

FROM node:22-alpine AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
# Next.js resolves next.config rewrite destinations at BUILD time (they are
# frozen into routes-manifest.json), so the backend URLs must be present now —
# runtime Deployment env vars do NOT affect rewrites. Defaults target the
# in-cluster service DNS for a Helm release named "wslvault"; override with
# --build-arg if the release name/namespace differs.
ARG IDENTITY_URL=http://wslvault-identity-service:8082
ARG SECRET_URL=http://wslvault-secret-engine:8081
ARG TRANSIT_URL=http://wslvault-transit-engine:8086
ARG POLICY_URL=http://wslvault-policy-engine:8083
ARG AUDIT_URL=http://wslvault-audit-service:8085
ARG LEASE_URL=http://wslvault-lease-manager:8084
ARG GATEWAY_URL=http://wslvault-region-health:8092
ENV IDENTITY_URL=$IDENTITY_URL \
    SECRET_URL=$SECRET_URL \
    TRANSIT_URL=$TRANSIT_URL \
    POLICY_URL=$POLICY_URL \
    AUDIT_URL=$AUDIT_URL \
    LEASE_URL=$LEASE_URL \
    GATEWAY_URL=$GATEWAY_URL
COPY --from=deps /app/node_modules ./node_modules
COPY ui/apps/vault-ui/ ./
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
# Fallbacks for the footer build stamp (/api/version) when the image runs
# outside the chart (docker-compose, local). The Deployment env wins in-cluster.
ARG GIT_SHA=""
ARG APP_VERSION=dev
ENV APP_GIT_SHA=$GIT_SHA \
    APP_VERSION=$APP_VERSION
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3011 \
    HOSTNAME=0.0.0.0
# `output: 'standalone'` emits a self-contained server bundle + minimal deps.
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
EXPOSE 3011
USER 65534:65534
CMD ["node", "server.js"]
