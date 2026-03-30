.PHONY: build test lint format check quality clean tidy

# Go build settings
GOFLAGS ?= -trimpath
LDFLAGS ?= -s -w

build:
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" ./...

test:
	go test -v -race -count=1 -coverprofile=coverage.out ./...

lint:
	golangci-lint run ./...

format:
	gofumpt -w .
	goimports -w .

tidy:
	go mod tidy

check: format tidy lint test build
	@echo "All checks passed."

# quality は自動化可能な品質チェック。check とは別に実行する。
quality:
	@echo "=== Quality Gate ==="
	@test -f LICENSE || { echo "ERROR: LICENSE missing. Fix: add MIT LICENSE file"; exit 1; }
	@! grep -rn "TODO\|FIXME\|HACK\|console\.log\|println\|print(" cmd/ internal/ pkg/ 2>/dev/null | grep -v "node_modules" || { echo "ERROR: debug output or TODO found. Fix: remove before ship"; exit 1; }
	@! grep -rn "password=\|secret=\|api_key=\|sk-\|ghp_" cmd/ internal/ pkg/ 2>/dev/null | grep -v '\$${' | grep -v "node_modules" || { echo "ERROR: hardcoded secrets. Fix: use env vars with no default"; exit 1; }
	@test ! -f PRD.md || ! grep -q "\[ \]" PRD.md || { echo "ERROR: unchecked acceptance criteria in PRD.md"; exit 1; }
	@echo "OK: automated quality checks passed"
	@echo "Manual checks required: README quickstart, demo GIF, input validation, ADR >=1"

clean:
	go clean -cache -testcache
	rm -f coverage.out
