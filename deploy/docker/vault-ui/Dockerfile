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
COPY --from=deps /app/node_modules ./node_modules
COPY ui/apps/vault-ui/ ./
RUN npm run build

FROM node:22-alpine AS runner
WORKDIR /app
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
