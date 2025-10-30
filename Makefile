# update go get -tool -modfile=tools.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
.PHONY: lint
lint:
	@go tool -modfile=tools.mod golangci-lint run
	@go tool -modfile=tools.mod govulncheck ./...

.PHONY: format
format:
	@go tool -modfile=tools.mod golangci-lint fmt

.PHONY: test
test:
	go test -v ./...
