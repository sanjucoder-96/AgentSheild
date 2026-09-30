# Multi-stage build: compile the dashboard, then the Go binary that embeds it.
# Result is a small static image with no Node.js or Go at runtime.

# 1. Dashboard
FROM node:22-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build

# 2. Gateway binary
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/gateway ./cmd/gateway \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/gatewayctl ./cmd/gatewayctl \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags "-s -w" -o /out/bench ./cmd/bench

# 3. Runtime
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/gateway /out/gatewayctl /out/bench /app/
COPY config/ /app/config/
COPY bench/ /app/bench/
USER nonroot:nonroot
EXPOSE 8080
VOLUME ["/app/state", "/app/results"]
ENTRYPOINT ["/app/gateway"]
