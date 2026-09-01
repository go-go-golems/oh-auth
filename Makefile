.PHONY: lint lintmax fmt-check gosec govulncheck test build ci-check smoke-final

lint:
	GOWORK=off golangci-lint run -v

lintmax:
	GOWORK=off golangci-lint run -v --max-same-issues=100

fmt-check:
	GOWORK=off golangci-lint fmt --diff

gosec:
	GOWORK=off go install github.com/securego/gosec/v2/cmd/gosec@latest
	gosec -exclude-generated -exclude=G101,G304,G301,G306 -exclude-dir=.history ./...

govulncheck:
	GOWORK=off go install golang.org/x/vuln/cmd/govulncheck@latest
	GOWORK=off govulncheck ./...

test:
	GOWORK=off go test ./...

build:
	GOWORK=off go build ./...

ci-check: fmt-check lint test build

# Deployed validation is intentionally a single release-candidate gate.
# The final orchestrator will be added with the integration smoke phase.
smoke-final:
	@echo "smoke-final is not implemented until the release-candidate integration phase"
	@exit 1
