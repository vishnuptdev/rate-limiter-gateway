# syntax=docker/dockerfile:1

# ---- build -----------------------------------------------------------------
FROM golang:1.25-alpine AS build
WORKDIR /src
ARG VERSION=dev
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/rateguard ./cmd/rateguard \
 && mkdir -p /out/data

# ---- runtime ---------------------------------------------------------------
# distroless has no shell, no package manager, and runs as the nonroot user.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/rateguard /usr/local/bin/rateguard
# Owned by nonroot so the process can write auth.json, audit.jsonl and config.json.
COPY --from=build --chown=nonroot:nonroot /out/data /data

ENV RLG_DATA_DIR=/data
USER nonroot
EXPOSE 8080 9000
VOLUME /data

ENTRYPOINT ["/usr/local/bin/rateguard"]
