FROM node:22-alpine AS ui-build

WORKDIR /app/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci --no-audit --no-fund && npm cache clean --force
COPY ui/ ./
RUN npm run build

FROM node:22-alpine

WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    DATA_DIR=/app/data

# Install production dependencies in a cached layer.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

# Copy only runtime files so secrets, tooling, and build sources never enter the image.
COPY --chown=node:node server.js ./
COPY --chown=node:node lib ./lib
COPY --chown=node:node public ./public
COPY --chown=node:node worker ./worker
COPY --from=ui-build --chown=node:node /app/ui/dist ./ui/dist

# Persistent state (auth secret, API-key hashes) lives here and is mounted as a volume.
RUN mkdir -p /app/data && chown -R node:node /app/data

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 3000) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.js"]
