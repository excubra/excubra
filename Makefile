MODULE  := github.com/excubra/excubra
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
  -X $(MODULE)/internal/version.Version=$(VERSION) \
  -X $(MODULE)/internal/version.Commit=$(COMMIT) \
  -X $(MODULE)/internal/version.Date=$(DATE)
GOFLAGS := -trimpath -mod=readonly

.PHONY: all build release test lint integration fixtures tidy-check clean

all: build

## build: host binary in bin/ (CGO off, like every shipped build)
build:
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o bin/excubra ./cmd/excubra

## release: static Linux binaries for amd64 and arm64 plus SHA256SUMS in dist/
release:
	rm -rf dist && mkdir -p dist
	for arch in amd64 arm64; do \
	  CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build $(GOFLAGS) -ldflags '$(LDFLAGS)' \
	    -o dist/excubra_linux_$$arch ./cmd/excubra || exit 1; \
	done
	cd dist && shasum -a 256 excubra_linux_* > SHA256SUMS

## test: unit tests with the race detector
test:
	go test -race -count=1 ./...

## lint: vet + golangci-lint (config in .golangci.yml)
lint:
	go vet ./...
	golangci-lint run

## integration: end-to-end test through Docker (build tag integration)
integration:
	go test -tags integration -count=1 -v ./test/integration/...

## fixtures: regenerate fixtures/events from the code
fixtures:
	go test -count=1 ./internal/server/webhook -run TestFixtures -update

## tidy-check: go.mod/go.sum must be tidy
tidy-check:
	go mod tidy
	git diff --exit-code -- go.mod go.sum

clean:
	rm -rf bin dist

## oui: regenerate the embedded vendor table from the IEEE registry
oui:
	go run ./tools/oui
