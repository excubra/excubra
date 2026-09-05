# Container image of the EX0 server: one static binary on a distroless base.
# Build from the repository root:  docker build -f deploy/Dockerfile -t excubra .
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.0.0-dev
RUN CGO_ENABLED=0 go build -trimpath -mod=readonly \
      -ldflags "-s -w -X github.com/excubra/excubra/internal/version.Version=${VERSION}" \
      -o /excubra ./cmd/excubra

# distroless/static carries CA roots (needed to POST webhooks to public HTTPS
# endpoints) and nothing else; runs as uid 65532.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /excubra /excubra
VOLUME ["/var/lib/excubra"]
ENV EXCUBRA_DATA_DIR=/var/lib/excubra \
    EXCUBRA_INGEST_LISTEN=:8443
ENTRYPOINT ["/excubra"]
CMD ["server", "run"]
