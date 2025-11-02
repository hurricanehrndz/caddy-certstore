# Testing Guide for caddy-certstore

This document explains how to run the comprehensive test suite for the caddy-certstore module.

## Test Overview

The test suite is split into three files:

- **`module_test.go`**: Platform-agnostic unit tests that run on any OS
- **`module_darwin_test.go`**: macOS-specific integration tests using Keychain
- **`module_windows_test.go`**: Windows-specific integration tests using Certificate Store

Test types include:

- **Unit Tests**: Test individual functions and components (platform-agnostic)
- **Integration Tests**: Test actual certificate loading from OS certificate stores (Darwin/Windows)
- **HTTP Transport Tests**: Test Caddy's reverse proxy transport provisioning
- **Certificate Selector Tests**: Test certificate matching and loading logic

## Prerequisites

### For All Tests

```bash
go version  # Go 1.21 or later required
```

### For Integration Tests (macOS and Windows)

Integration tests require:

**macOS:**
1. **macOS** operating system (Darwin)
2. **Test certificates** in `testdata/` directory
3. **No root privileges required** - uses login keychain

**Windows:**
1. **Windows** operating system
2. **Test certificates** in `testdata/` directory
3. **PowerShell** (included with Windows)
4. **No administrator privileges required** - uses CurrentUser certificate store

## Running Tests

### Run All Unit Tests (Platform-Agnostic)

```bash
# Run unit tests only (skips integration tests)
# On Unix/macOS:
SKIP_KEYCHAIN_TESTS=1 go test -v ./...

# On Windows (PowerShell):
$env:SKIP_CERTSTORE_TESTS=1; go test -v ./...
```

### Run All Tests Including Integration

**macOS:**
```bash
# Run complete test suite with keychain integration
# No sudo needed - uses login keychain
go test -v ./...
```

**Windows:**
```powershell
# Run complete test suite with certificate store integration
# No administrator privileges needed - uses CurrentUser store
go test -v ./...
```

### Run Specific Tests

```bash
# Run only HTTPTransport provision tests
SKIP_KEYCHAIN_TESTS=1 go test -v -run TestHTTPTransport_Provision

# Run only CertSelector tests
SKIP_KEYCHAIN_TESTS=1 go test -v -run TestCertSelector

# Run only regex pattern tests
go test -v -run TestIsRegexPattern
```

## Test Details

### Unit Tests (module_test.go)

These tests are platform-agnostic and don't require certificate store access:

- `TestIsRegexPattern`: Tests regex pattern detection logic
  - Validates that FQDNs are not treated as regex patterns
  - Validates that regex metacharacters are properly detected
  - Tests various regex patterns (wildcards, anchors, groups, etc.)

### Integration Tests (module_darwin_test.go - macOS)

These tests are macOS-specific and use pre-generated test certificates:

- `TestHTTPTransport_Provision_Darwin`: Tests provisioning of HTTPTransport with client certificates
  - Tests exact certificate name matching
  - Tests regex pattern matching
  - Tests error handling for non-existent certificates
  - Tests provisioning without client cert (should succeed)
  - Tests validation of empty certificate name (should fail)
  
- `TestCertSelector_LoadCertificate_Darwin`: Tests certificate loading logic
  - Tests loading by exact common name
  - Tests loading by regex pattern
  - Tests error handling for non-existent certificates
  
- `TestSerializeCertificateChain_Darwin`: Tests certificate chain serialization with real certificates

### Integration Tests (module_windows_test.go - Windows)

These tests are Windows-specific and mirror the Darwin tests:

- `TestHTTPTransport_Provision_Windows`: Same test coverage as Darwin version for Windows Certificate Store
- `TestCertSelector_LoadCertificate_Windows`: Same test coverage as Darwin version for Windows Certificate Store  
- `TestSerializeCertificateChain_Windows`: Tests certificate chain serialization on Windows

### How Integration Tests Work

**macOS (`module_darwin_test.go`):**

1. **Test Certificate**: Located in `testdata/` (committed to repository):
   - `test-cert.pem` - Self-signed certificate
   - `test-key.pem` - Private key  
   - `test-cert.p12` - PKCS#12/PFX bundle
   - Common Name: `test.caddycertstore.local`
   - Password: `test123`

2. **Keychain Import**: Uses macOS `security` command-line tool to import the certificate into the **login keychain** (no sudo required)

3. **Module Testing**: Tests the actual `HTTPTransport` and `CertSelector` functionality

4. **Cleanup**: Removes test certificates from the keychain after tests complete

**Note**: On macOS, the certstore library provides access to certificates from both system and login keychains automatically.

**Windows (`module_windows_test.go`):**

1. **Test Certificate**: Same files in `testdata/`:
   - `test-cert.p12` serves as PFX file (PFX and P12 are the same format)
   - Password: `test123`

2. **Certificate Store Import**: Uses PowerShell `Import-PfxCertificate` cmdlet to import into **CurrentUser\My** (Personal) store (no administrator privileges required)

3. **Module Testing**: Tests the actual `HTTPTransport` and `CertSelector` functionality

4. **Cleanup**: Removes test certificates from the certificate store after tests complete

**Note**: On Windows, the certstore library can access both CurrentUser and LocalMachine certificate stores.

### Platform-Specific Build Tags

- **`module_darwin_test.go`**: Uses `//go:build darwin` to only compile on macOS
- **`module_windows_test.go`**: Uses `//go:build windows` to only compile on Windows
- **`module_test.go`**: No build tag, runs on all platforms

This ensures that CI/CD pipelines on different platforms only run the tests relevant to that platform.

## Environment Variables

- **`SKIP_KEYCHAIN_TESTS`** (macOS): Set to skip keychain integration tests
  ```bash
  SKIP_KEYCHAIN_TESTS=1 go test -v ./...
  ```

- **`SKIP_CERTSTORE_TESTS`** (Windows): Set to skip certificate store integration tests
  ```powershell
  $env:SKIP_CERTSTORE_TESTS=1; go test -v ./...
  ```

## Test Coverage

Generate a coverage report:

```bash
# Unit tests only
SKIP_KEYCHAIN_TESTS=1 go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# With integration tests (macOS)
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Continuous Integration

For CI environments (GitHub Actions, etc.):

### macOS Runners

```yaml
- name: Run Tests
  run: |
    go mod download
    go test -v ./...
```

### Windows Runners

```yaml
- name: Run Tests
  run: |
    go mod download
    go test -v ./...
```

### Linux Runners (Unit Tests Only)

```yaml
- name: Run Unit Tests
  env:
    SKIP_KEYCHAIN_TESTS: 1
  run: |
    go mod download
    go test -v ./...
```

## What Tests Validate

### HTTPTransport Module
- ✅ Module registration with Caddy
- ✅ Provisioning with valid certificate names
- ✅ Provisioning with regex patterns
- ✅ TLS client config is properly set
- ✅ Certificate and private key are loaded
- ✅ Error handling for non-existent certificates
- ✅ Error handling for empty certificate names
- ✅ Provisioning without client cert (nil check)
- ✅ Cleanup of certificate store resources

### CertSelector
- ✅ Certificate loading by exact common name
- ✅ Certificate loading by regex pattern
- ✅ Proper error messages for failures
- ✅ Certificate Leaf is populated
- ✅ Private key is available
- ✅ Resource cleanup

### Utility Functions
- ✅ Regex pattern detection logic
- ✅ Certificate chain serialization
- ✅ Store location parsing (system/user/machine)

## Common Test Scenarios

### Testing Certificate Name Matching

```bash
# Test exact name matching
go test -v -run TestCertSelector_LoadCertificate_Darwin/load_by_exact_common_name

# Test regex pattern matching  
go test -v -run TestCertSelector_LoadCertificate_Darwin/load_by_regex_pattern
```

### Testing Error Conditions

```bash
# Test non-existent certificate
go test -v -run TestHTTPTransport_Provision_Darwin/provision_with_non-existent_certificate

# Test empty name validation
go test -v -run TestHTTPTransport_Provision_Darwin/provision_with_empty_name
```

## Troubleshooting Tests

### macOS: "Certificate already in keychain"

This is expected behavior. The test checks for existing certificates and reuses them if found.

### macOS: "Failed to import certificate to keychain"

Ensure:
- You have permission to access the login keychain
- The keychain is unlocked
- Test certificates exist in `testdata/`

### Windows: "Failed to import certificate"

Ensure:
- PowerShell execution policy allows running cmdlets
- Test certificates exist in `testdata/`
- You're using CurrentUser store (no admin needed)

## Contributing

When adding new tests:

1. Follow the existing test patterns
2. Use `t.Helper()` for test helper functions
3. Clean up resources in defer statements or cleanup functions
4. Skip integration tests appropriately:
   - macOS: Check `SKIP_KEYCHAIN_TESTS` env var
   - Windows: Check `SKIP_CERTSTORE_TESTS` env var
5. Use platform-specific build tags (`//go:build darwin` or `//go:build windows`)
6. Document any new test requirements or scenarios
7. Ensure tests are idempotent and can run multiple times

## Questions?

For issues or questions about testing, please open an issue on the GitHub repository.
