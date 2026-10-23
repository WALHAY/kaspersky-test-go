GO ?= go
GOLANGCI_LINT_VERSION := v2.1.6

.PHONY: build run migrate generate check-generated fmt test integration coverage vet lint check up down test-docker

build:
	$(GO) build -trimpath -o bin/server ./cmd/server

run:
	$(GO) run ./cmd/server

migrate:
	$(GO) run ./cmd/server migrate

generate:
	$(GO) generate ./api

check-generated:
	@set -eu; backup=$$(mktemp); cp api/generated.go "$$backup"; \
	trap 'cp "$$backup" api/generated.go; rm -f "$$backup"' EXIT; \
	$(GO) generate ./api; diff -u "$$backup" api/generated.go

fmt:
	$(GO) fmt ./...

test:
	$(GO) test -race ./...

integration:
	@test -n "$$TEST_DATABASE_URL" || (echo 'Set TEST_DATABASE_URL to a test PostgreSQL URL' >&2; exit 1)
	$(GO) test -race -tags=integration -count=1 ./...

coverage:
	$(GO) test -race -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -func=coverage.out

vet:
	$(GO) vet ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

check: check-generated test vet lint build

up:
	docker compose up --build -d

down:
	docker compose down

test-docker:
	@status=0; docker compose -f compose.test.yaml up --abort-on-container-exit --exit-code-from tests || status=$$?; \
	docker compose -f compose.test.yaml down; exit $$status
