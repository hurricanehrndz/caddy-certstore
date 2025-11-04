# update go get -tool -modfile=tools.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
.PHONY: lint
lint:
	@pre-commit run --all-files
	@go tool -modfile=tools.mod golangci-lint run
	@go tool -modfile=tools.mod govulncheck ./...

.PHONY: format
format:
	@go tool -modfile=tools.mod golangci-lint fmt

.PHONY: test
test:
	go test -v -race  -covermode=atomic ./...


caddy: build/darwin/caddy
build/darwin/caddy:
	test -f $(@D) || mkdir -p $(@D)
	@go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
	CGO_ENABLED=1 xcaddy build \
		--output $(@) \
		--with github.com/hurricanehrndz/caddy-certstore=.

.PHONY: install-hooks
install-hooks:
	@pre-commit install --install-hooks
