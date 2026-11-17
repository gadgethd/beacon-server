# Copyright 2026 Beacon Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

# golang:1.26.11-alpine3.24; must satisfy go.mod with GOTOOLCHAIN=local.
FROM golang@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o beacon ./cmd/beacon

# alpine:3.24
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
ARG POSTGRES_CLIENT_MAJOR=16
RUN apk add --no-cache ca-certificates tzdata postgresql${POSTGRES_CLIENT_MAJOR}-client
WORKDIR /app
COPY --from=builder /app/beacon .
CMD ["./beacon"]
