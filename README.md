# caddy-certstore

A Caddy v2 HTTP reverse proxy transport module that enables client certificate
authentication using certificates from OS certificate stores (macOS Keychain
and Windows Certificate Store) for mTLS connections to upstream servers.

## Overview

This module extends Caddy's reverse proxy HTTP transport to support client
certificate authentication using certificates stored in your operating system's
native certificate store. This is particularly useful in enterprise
environments where client certificates are managed centrally through the OS
certificate infrastructure.

**Supported Platforms:**
- **macOS**: Loads certificates from Keychain (System and Login keychains)
- **Windows**: Loads certificates from Certificate Store (LocalMachine and CurrentUser stores)

## Installation

```bash
CGO_ENABLED=1 xcaddy build --with github.com/hurricanehrndz/caddy-certstore
```

## Configuration

The module uses the ID `http.reverse_proxy.transport.certstore` and can be
configured in your Caddyfile or JSON config.

### JSON Configuration

```json
{
  "apps": {
    "http": {
      "servers": {
        "srv0": {
          "routes": [
            {
              "handle": [
                {
                  "handler": "reverse_proxy",
                  "transport": {
                    "protocol": "certstore",
                    "client_certificate": {
                      "name": "client.example.com",
                      "location": "user"
                    }
                  },
                  "upstreams": [
                    {
                      "dial": "upstream.example.com:443"
                    }
                  ]
                }
              ]
            }
          ]
        }
      }
    }
  }
}
```

### Caddyfile Configuration

```caddyfile
example.com {
    reverse_proxy https://upstream.example.com {
        transport certstore {
            client_certificate {
                name client.example.com
                location user
            }
        }
    }
}
```

### Certificate Selector Options

The `client_certificate` object supports the following fields:

- **`name`** (required): Common name or regex pattern of the certificate to load
  - Exact match: `"client.example.com"`
  - Regex pattern: `"client\\..*\\.com"` (automatically detected by presence of regex metacharacters)
- **`location`** (optional): Certificate store location
  - macOS: `"system"` or `"user"` (searches both automatically)
  - Windows: `"machine"` or `"user"` (maps to LocalMachine or CurrentUser)
  - Default: `"system"`

### Regex Pattern Support

The module automatically detects regex patterns by checking for metacharacters
(`*`, `+`, `?`, `^`, `$`, `()`, `[]`, `{}`, `|`, `\`). When detected, the
pattern is compiled and used for matching against certificate common names.

**Examples:**
- `"^client-.*\\.example\\.com$"` - Matches any client certificate under example.com
- `"test\\..*"` - Matches any certificate starting with "test."
- `"*.example.com"` - Wildcard pattern

## Features

- **Native OS Integration**: Uses platform-specific certificate APIs via [tailscale/certstore](https://github.com/tailscale/certstore)
- **mTLS Support**: Enables mutual TLS authentication to upstream servers
- **Automatic Cleanup**: Properly releases certificate store resources
- **Regex Matching**: Flexible certificate selection using regex patterns
- **Structured Logging**: Logs certificate details when loaded (common name, issuer, serial number, location)
- **Zero-Config Keychain**: macOS automatically searches both system and user keychains

## How It Works

1. During Caddy's provision phase, the module:
   - Validates that a certificate name is specified
   - Detects and compiles regex patterns if present
   - Opens the OS certificate store (read-only)
   - Searches for matching certificate identity
   - Loads the certificate and private key
   - Configures the HTTP transport's TLS client config

2. When making requests to upstream servers:
   - Caddy's reverse proxy uses the configured client certificate
   - The certificate and private key are presented during TLS handshake
   - Upstream server validates the client certificate (mTLS)

3. On shutdown:
   - Certificate store resources are properly closed
   - Identity handles are released

## Logging

When a certificate is successfully loaded, the module logs an informational message:

```json
{
  "level": "info",
  "msg": "loaded client certificate from OS certificate store",
  "common_name": "client.example.com",
  "issuer": "Example CA",
  "serial_number": "123456789",
  "location": "user"
}
```

This helps verify which certificate was selected during provisioning.

## Testing

Comprehensive test suite covering unit tests and platform-specific integration
tests. See [TEST_README.md](TEST_README.md) for detailed testing instructions.

**Quick Start:**
```bash
# Run all tests (macOS/Windows)
make test
```

## Development

**Requirements:**
- Go 1.21+
- macOS or Windows for integration testing

**Build:**
```bash
make caddy
```

**Lint:**
```bash
make lint
```

**Format:**
```bash
make format
```

## Use Cases

- **Enterprise mTLS**: Use corporate-managed client certificates stored in OS certificate stores
- **Zero-Touch Configuration**: Certificates provisioned via MDM/Group Policy work automatically
- **Certificate Rotation**: OS-managed certificates can be updated without modifying Caddy config
- **Simplified Management**: No need to manage PEM files or certificate paths in configuration

## Breaking Changes from Previous Versions

If upgrading from a previous version that used `CertificateLoader` interface:

- Module ID changed: `tls.certificates.load_certstore` → `http.reverse_proxy.transport.certstore`
- Configuration structure changed to support reverse proxy transport
- JSON field renamed: `client_certificate_match` → `client_certificate`
- Type renamed: `Matcher` → `CertSelector` (internal, not visible in config)

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please ensure all tests pass and code is properly
formatted before submitting PRs.

## Acknowledgments

- Built on [Caddy v2](https://caddyserver.com/)
- Uses [tailscale/certstore](https://github.com/tailscale/certstore) for OS certificate store access
