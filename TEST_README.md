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
- **Provisioner Tests**: Test Caddy's provisioning and replacer functionality
- **Benchmark Tests**: Performance testing for certificate operations

## Prerequisites

### For All Tests

```bash
go version  # Go 1.25 or later required
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
# Run only provisioner tests
SKIP_KEYCHAIN_TESTS=1 go test -v -run TestCertStoreLoader_Provision

# Run only integration tests
go test -v -run TestCertStoreLoader_LoadCertificates_Integration

# Run only unit tests for validation
SKIP_KEYCHAIN_TESTS=1 go test -v -run TestIsValidCertificate
```

### Run Benchmarks

```bash
# Run all benchmarks (skips keychain benchmarks)
SKIP_KEYCHAIN_TESTS=1 go test -bench=. -benchmem

# Run keychain benchmarks
go test -bench=BenchmarkLoadCertificate_Darwin
```

## Test Details

### Unit Tests (module_test.go)

These tests are platform-agnostic and don't require keychain access:

- `TestCertStoreLoader_CaddyModule`: Validates module registration
- `TestCertStoreLoader_Provision`: Tests configuration provisioning and validation
- `TestCertStoreLoader_Cleanup`: Tests resource cleanup
- `TestCertificateSelector_Cleanup`: Tests selector cleanup
- `TestGetStoreLocation`: Tests store location parsing
- `TestIsValidCertificate`: Tests certificate validation
- `TestReplaceTags`: Tests Caddy replacer functionality for tags

### Integration Tests (module_darwin_test.go - macOS)

These tests are macOS-specific and use pre-generated test certificates:

- `TestCertStoreLoader_LoadCertificates_Integration`: Comprehensive integration test that:
  - Imports test certificate into login keychain
  - Tests loading by common name
  - Tests loading by issuer
  - Tests error handling for non-existent certificates
  - Tests tag functionality
  - Cleans up test certificates after completion
- `TestSerializeCertificateChain_Darwin`: Tests certificate chain serialization with real certificates
- `BenchmarkLoadCertificate_Darwin`: Performance benchmark for keychain operations

### Integration Tests (module_windows_test.go - Windows)

These tests are Windows-specific and use pre-generated test certificates:

- `TestCertStoreLoader_LoadCertificates_Integration`: Comprehensive integration test that:
  - Imports test certificate into CurrentUser\My certificate store
  - Tests loading by common name
  - Tests loading by issuer
  - Tests error handling for non-existent certificates
  - Tests tag functionality
  - Cleans up test certificates after completion
- `TestSerializeCertificateChain_Windows`: Tests certificate chain serialization with real certificates
- `BenchmarkLoadCertificate_Windows`: Performance benchmark for certificate store operations

### How Integration Tests Work

**macOS (`module_darwin_test.go`):**

1. **Test Certificate**: Located in `testdata/` (committed to repository):
   - `test-cert.pem` - Self-signed certificate
   - `test-key.pem` - Private key  
   - `test-cert.p12` - PKCS#12/PFX bundle
   - Common Name: `test.caddycertstore.local`
   - Valid for 5 years (2025-2030)

2. **Keychain Import**: Uses macOS `security` command-line tool to import the certificate into the **login keychain** (no sudo required)

3. **Module Testing**: Tests the actual `CertStoreLoader` functionality

4. **Cleanup**: Removes test certificates from the keychain after tests complete

**Note**: On macOS, when you open a certificate store (system or user), the certstore library provides access to certificates from both the system and login keychains. This is normal macOS keychain behavior.

**Windows (`module_windows_test.go`):**

1. **Test Certificate**: Same files in `testdata/`:
   - `test-cert.p12` serves as PFX file (PFX and P12 are the same format)
   - Password: `test123`

2. **Certificate Store Import**: Uses PowerShell `Import-PfxCertificate` cmdlet to import into **CurrentUser\My** (Personal) store (no administrator privileges required)

3. **Module Testing**: Tests the actual `CertStoreLoader` functionality

4. **Cleanup**: Removes test certificates from the certificate store after tests complete

**Note**: On Windows, the certstore library can access both CurrentUser and LocalMachine certificate stores. Integration tests use CurrentUser for simplicity.

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

- **`TEST_CERT_NAME`**: Used in provisioner tests for replacer validation
- **`ENVIRONMENT`**: Used in provisioner tests for tag replacer validation

## Test Coverage

Generate a coverage report:

```bash
# Unit tests only
SKIP_KEYCHAIN_TESTS=1 go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# With integration tests
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

### Linux Runners

```yaml
- name: Run Tests
  run: |
    # Only unit tests on Linux (no certificate store integration)
    SKIP_KEYCHAIN_TESTS=1 SKIP_CERTSTORE_TESTS=1 go test -v ./...
```

## Contributing

When adding new tests:

1. Follow the existing test patterns
2. Use `t.Helper()` for test helper functions
3. Clean up resources in defer statements or cleanup functions
4. Skip integration tests appropriately:
   - macOS: `SKIP_KEYCHAIN_TESTS`
   - Windows: `SKIP_CERTSTORE_TESTS`
5. Use platform-specific build tags (`//go:build darwin` or `//go:build windows`)
6. Document any new test requirements

## Questions?

For issues or questions about testing, please open an issue on the GitHub repository.
