# Multi-stage Docker build for TrustVault
FROM node:22-alpine AS builder

WORKDIR /app

# Copy root manifests and install server dependencies
COPY package*.json tsconfig.json ./
RUN npm install

# Copy client manifests and install client dependencies
COPY client/package*.json client/tsconfig*.json client/vite.config.ts client/tailwind.config.js client/postcss.config.js client/index.html ./client/
RUN npm --prefix client install

# Copy source code
COPY server/ ./server/
COPY client/src/ ./client/src/

# Build client production bundle
RUN npm --prefix client run build

# Runtime Stage
FROM node:22-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4000

COPY package*.json ./
RUN npm install --omit=dev

# Copy compiled client and server files
COPY --from=builder /app/client/dist ./client/dist
COPY server/ ./server/
COPY tsconfig.json ./

# Ensure data and storage directories exist
RUN mkdir -p data storage/files

# Expose port
EXPOSE 4000

# Start server with tsx
CMD ["npx", "tsx", "server/src/server.ts"]
