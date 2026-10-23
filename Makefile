GO ?= go
GOLANGCI_LINT_VERSION := v2.15.0

.PHONY: build run generate test integration lint docker clean

build: generate
	$(GO) build -trimpath -o bin/server ./cmd/server

run: generate
	$(GO) run ./cmd/server

generate:
	$(GO) generate ./api

test: generate
	$(GO) test -race ./...

integration: generate
	@test -n "$$TEST_DATABASE_URL" || (echo 'Set TEST_DATABASE_URL to a test PostgreSQL URL' >&2; exit 1)
	$(GO) test -race -tags=integration -count=1 ./...

lint: generate
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

docker: build
	docker compose up --build -d

clean:
	rm -rf bin generated
	rm -f server coverage.out api/generated.go
	find . -type f -name '*.test' -not -path './.git/*' -delete
