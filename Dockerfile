# Stage 1: Build the React web UI frontend
FROM node:22-alpine AS web-build
WORKDIR /web
COPY web/package.json ./
# If package-lock.json exists, npm ci is preferred, otherwise npm install
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi
COPY web/ ./
RUN npm run build

# Stage 2: Build the Go gateway binary
FROM golang:1.26.1-alpine AS go-build
RUN apk add --no-cache git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Copy the built web UI assets into the embed path expected by go embed
RUN rm -rf cmd/gateway/web/dist && mkdir -p cmd/gateway/web/dist
COPY --from=web-build /web/dist/ cmd/gateway/web/dist/
# Run build with ldflags for version/commit injection
ARG REF_NAME=dev
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-s -w -X main.version=${REF_NAME} -X main.commit=$(git rev-parse HEAD 2>/dev/null || echo unknown) -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /app/gateway cmd/gateway/*.go

# Stage 3: Final runtime container
FROM ubuntu:noble
RUN apt-get update && apt-get install -y ca-certificates wget && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=go-build /app/gateway .
# Copy the default config template as the config file
COPY config/gateway.yaml.example /app/config/gateway.yaml
EXPOSE 8080 8081
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8081/health || exit 1
ENTRYPOINT ["/app/gateway"]
CMD ["-config", "/app/config/gateway.yaml"]
