# caddy-certstore

A Caddy v2 module for loading TLS certificates from OS-native certificate stores (macOS Keychain and Windows Certificate Store).

## Overview

This module implements Caddy's `CertificateLoader` interface, allowing you to use certificates stored in your operating system's native certificate store instead of managing PEM files. This is particularly useful in enterprise environments where certificates are managed centrally through the OS certificate infrastructure.

**Supported Platforms:**
- **macOS**: Loads certificates from Keychain (System and Login keychains)
- **Windows**: Loads certificates from Certificate Store (LocalMachine and CurrentUser stores)

## Installation

```bash
xcaddy build --with github.com/hurricanehrndz/caddy-certstore
```

## Configuration

The module uses the ID `tls.certificates.load_certstore` and can be configured in your Caddyfile or JSON config.

### JSON Configuration

```json
{
  "apps": {
    "tls": {
      "certificates": {
        "load_certstore": {
          "certificates": [
            {
              "name": "example.com",
              "location": "user",
              "tags": ["production"]
            }
          ]
        }
      }
    }
  }
}
```

### Certificate Selector Options

- **`name`**: Common name of the certificate to load (e.g., "example.com")
- **`issuer`**: Issuer name to match certificates against
- **`location`**: Certificate store location
  - macOS: `"system"` or `"user"`, has no real implication on macOS (Keychain)
  - Windows: `"machine"` or `"user"` (Certificate Store)
- **`tags`**: Optional tags for certificate organization

**Note:** Either `name` or `issuer` must be specified for each certificate selector.

## Features

- **Native OS Integration**: Uses platform-specific certificate APIs
- **Automatic Cleanup**: Properly releases certificate store resources
- **Caddy Replacers**: Supports Caddy's placeholder syntax in configuration
- **Tags Support**: Organize and identify certificates with custom tags
- **Flexible Selection**: Find certificates by common name or issuer

## Testing

Comprehensive test suite covering unit tests and platform-specific integration tests. See [TEST_README.md](TEST_README.md) for detailed testing instructions.

**Quick Start:**
```bash
# Run all tests (macOS/Windows)
go test -v ./...

# Run unit tests only (any platform)
SKIP_KEYCHAIN_TESTS=1 go test -v ./...  # macOS
$env:SKIP_CERTSTORE_TESTS=1; go test -v ./...  # Windows
```

## Development

**Requirements:**
- Go 1.25+
- macOS or Windows for integration testing

**Build:**
```bash
go build -v ./...
```

**Lint:**
```bash
make lint
```

**Format:**
```bash
make format
```

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and code is properly formatted before submitting PRs.
