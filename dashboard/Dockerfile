FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS deps
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --ignore-scripts

FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS runtime-deps
WORKDIR /app
COPY package.json package-lock.json .npmrc ./
RUN npm ci --omit=dev --ignore-scripts

FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS builder
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY . .
RUN npx --no-install prisma generate && \
    engine_path="$(find /app/node_modules/@prisma/engines /root/.cache/prisma \
      -type f -name 'schema-engine*' 2>/dev/null | head -n 1)" && \
    test -n "$engine_path" && \
    cp "$engine_path" /app/prisma-schema-engine && \
    chmod 0555 /app/prisma-schema-engine
ENV NODE_OPTIONS="--max-old-space-size=4096"
RUN AUTH_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')" \
    ENCRYPTION_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')" \
    AUTH_URL=http://localhost:3000 \
    AUTH_GITHUB_ID=build-only-client-id \
    AUTH_GITHUB_SECRET="$(node -e 'process.stdout.write(require("crypto").randomBytes(32).toString("hex"))')" \
    npm run build

FROM node:26-alpine@sha256:aadf416b2cdce311a8811ba3f0608a61b77dbf997500e2eafe781b51f6a0b019 AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 --ingroup nodejs nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./prisma.config.ts
COPY --from=builder /app/prisma-schema-engine ./prisma-schema-engine
COPY --from=runtime-deps /app/node_modules ./node_modules

USER nextjs
EXPOSE 3000
ENV HOSTNAME="0.0.0.0"
ENV PRISMA_SCHEMA_ENGINE_BINARY="/app/prisma-schema-engine"
CMD ["sh", "-c", "./node_modules/.bin/prisma migrate deploy && exec node server.js"]
