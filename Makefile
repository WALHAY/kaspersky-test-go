GO ?= go
GOLANGCI_LINT_VERSION := v2.1.6

.PHONY: build run generate test integration lint clean

build:
	$(GO) build -trimpath -o bin/server ./cmd/server

run:
	$(GO) run ./cmd/server

generate:
	$(GO) generate ./api

test:
	$(GO) test -race ./...

integration:
	@test -n "$$TEST_DATABASE_URL" || (echo 'Set TEST_DATABASE_URL to a test PostgreSQL URL' >&2; exit 1)
	$(GO) test -race -tags=integration -count=1 ./...

lint:
	$(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION) run

clean:
	rm -rf bin
	rm -f server coverage.out api/generated.go
	find . -type f -name '*.test' -not -path './.git/*' -delete
