ARG GO_IMAGE=golang:1.25-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# ============================================================
# prod-build: сборка только encgit-server
# Исходники монтируются read-only через BuildKit и не попадают в layer
# ============================================================
FROM ${GO_IMAGE} AS prod-build

RUN apk add --no-cache ca-certificates git

WORKDIR /src

COPY go.mod go.sum LICENSE ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify

RUN --mount=type=bind,source=cmd/encgit-server,target=/src/cmd/encgit-server,ro \
    --mount=type=bind,source=internal,target=/src/internal,ro \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
      -trimpath \
      -tags netgo \
      -ldflags="-s -w -extldflags=-static" \
      -o /out/encgit-server \
      ./cmd/encgit-server

# ============================================================
# devtest: образ для разработчика
# root + shell + toolchain + исходники + зависимости внутри образа
# ============================================================
FROM ${GO_IMAGE} AS devtest

RUN apk add --no-cache \
      bash \
      build-base \
      ca-certificates \
      curl \
      git

WORKDIR /workspace

COPY go.mod go.sum LICENSE ./

# Тут без cache-mount специально:
# зависимости остаются внутри image, чтобы dev мог сразу запускать go test
RUN go mod download && go mod verify

# Для тестов нужны оба cmd и весь internal
COPY cmd/encgit/ ./cmd/encgit/
COPY cmd/encgit-server/ ./cmd/encgit-server/
COPY internal/ ./internal/
COPY docs/FORMAT-SPEC*.md ./docs/

ENV CGO_ENABLED=1

CMD ["/bin/bash"]

# ============================================================
# ci-test: прогон всех тестов на этапе сборки
# ============================================================
FROM devtest AS ci-test

RUN go test -count=1 -v ./...

# ============================================================
# testbin: собрать test binaries по всем пакетам, где есть тесты
# ============================================================
FROM devtest AS testbin

RUN mkdir -p /out/tests && \
    go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... \
    | awk 'NF' \
    | while read -r pkg; do \
        name="$(printf '%s' "$pkg" | sed 's|[^A-Za-z0-9_.-]|_|g')"; \
        go test -c -o "/out/tests/${name}.test" "$pkg"; \
      done

# ============================================================
# prod: минимальный runtime
# ============================================================
FROM ${RUNTIME_IMAGE} AS prod

LABEL org.opencontainers.image.title="encgit-server" \
      org.opencontainers.image.description="Tier-4 HTTP authorizer for encgit" \
      org.opencontainers.image.licenses="Apache-2.0"

USER nonroot:nonroot
WORKDIR /home/nonroot

COPY --from=prod-build --chown=nonroot:nonroot /out/encgit-server /usr/local/bin/encgit-server
COPY --from=prod-build --chown=nonroot:nonroot /src/LICENSE /licenses/LICENSE

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/encgit-server"]
CMD ["--addr", "0.0.0.0:8080", "--db", "/data/encgit.db", "--blobs", "/data/blobs"]