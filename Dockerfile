# AgentShield gateway image. Multi-stage: build the dashboard, then a static Go
# binary that embeds it, then copy into a distroless non-root runtime (no shell,
# no package manager, uid 65532).

# 1. Dashboard
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. Binaries
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/bin/gateway ./cmd/gateway \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/bin/gatewayctl ./cmd/gatewayctl \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/bin/bench ./cmd/bench \
 && mkdir -p /out/state /out/results

# 3. Runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/bin /app/bin
COPY --from=build --chown=65532:65532 /out/state /app/state
COPY --from=build --chown=65532:65532 /out/results /app/results
COPY --chown=65532:65532 config/ /app/config/
COPY bench/ /app/bench/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/app/bin/gateway"]
