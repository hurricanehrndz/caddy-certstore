# Agent Guidelines for caddy-certstore

## Build & Test Commands
- **Build**: `go build -v ./...`
- **Test all**: `make test`
- **Test single**: `go test -v -run TestName ./...`
- **Lint**: `make lint`
- **Format**: `make format`

## Code Style
**Imports**: Group standard, external, then Caddy packages (std → default → github.com/caddyserver/caddy). Use `gci` for ordering.
**Formatting**: Use `gofumpt` (stricter gofmt). Run formatters before committing.
**Types**: Always use explicit types; prefer struct initialization with field names. Follow Caddy module patterns.
**Naming**: Follow Go conventions (CamelCase exports, camelCase internal). Use descriptive names (e.g., `CertStoreLoader` not `CSL`).
**Error Handling**: Always check errors; return detailed errors up the call stack. Use `fmt.Errorf` with context.
**Comments**: Document all exported types/functions with proper godoc format. Start with the name being documented.
**JSON Tags**: Use `json:"field_name,omitempty"` for optional config fields (Caddy convention).
**Alignment**: Align the happy path to the left
**Complexity**: Ensure code adheres to following coding principles: KISS, SRP, DRY and prioritize clarity over brevity or clever 
**General**: Use modern features of Go when possible

## Project Context
This is a Caddy v2 module for loading TLS certificates from OS certificate stores (macOS Keychain, Windows CertStore). Implements Caddy's `CertificateLoader` interface. Module ID: `tls.certificates.load_certstore`.
