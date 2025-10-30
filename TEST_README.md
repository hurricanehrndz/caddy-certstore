# Testing Guide for caddy-certstore

This document explains how to run the comprehensive test suite for the caddy-certstore module.

## Test Overview

The test suite is split into two files:

- **`module_test.go`**: Platform-agnostic unit tests that run on any OS
- **`module_darwin_test.go`**: macOS-specific integration tests using Keychain

Test types include:

- **Unit Tests**: Test individual functions and components (platform-agnostic)
- **Integration Tests**: Test actual certificate loading from macOS Keychain (Darwin only)
- **Provisioner Tests**: Test Caddy's provisioning and replacer functionality
- **Benchmark Tests**: Performance testing for certificate operations

## Prerequisites

### For All Tests

```bash
go version  # Go 1.25 or later required
```

### For Integration Tests (macOS only)

Integration tests require:

1. **macOS** operating system (Darwin)
2. **Test certificates** in `testdata/` directory
3. **No root privileges required** - uses login keychain

## Running Tests

### Run All Unit Tests (No Keychain Required)

```bash
# Run unit tests only (skips integration tests)
SKIP_KEYCHAIN_TESTS=1 go test -v ./...
```

### Run All Tests Including Integration (macOS)

```bash
# Run complete test suite with keychain integration
# No sudo needed - uses login keychain
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

### Integration Tests (module_darwin_test.go)

These tests are macOS-specific and use pre-generated test certificates:

- `TestCertStoreLoader_LoadCertificates_Integration`: Comprehensive integration test that:
  - Imports test certificate into login keychain
  - Tests loading by common name
  - Tests loading by issuer
  - Tests error handling for non-existent certificates
  - Tests tag functionality
  - Cleans up test certificates after completion
- `TestSerializeCertificateChain_Darwin`: Tests certificate chain serialization with real certificates

### How Integration Tests Work (macOS only)

The Darwin-specific tests (`module_darwin_test.go`) use pre-generated test certificates:

1. **Test Certificate**: Located in `testdata/` (committed to repository):
   - `test-cert.pem` - Self-signed certificate
   - `test-key.pem` - Private key  
   - `test-cert.p12` - PKCS#12 bundle for keychain import
   - Common Name: `test.caddycertstore.local`
   - Valid for 5 years (2025-2030)

2. **Keychain Import**: Uses macOS `security` command-line tool to import the certificate into the **login keychain** (not system keychain, no sudo required)

3. **Module Testing**: Tests the actual `CertStoreLoader` functionality

4. **Cleanup**: Removes test certificates from the keychain after tests complete

**Note**: On macOS, when you open a certificate store (system or user), the certstore library provides access to certificates from both the system and login keychains. This is normal macOS keychain behavior.

### Platform-Specific Build Tags

- **`module_darwin_test.go`**: Uses `//go:build darwin` to only compile on macOS
- **`module_test.go`**: No build tag, runs on all platforms

This ensures that CI/CD pipelines on non-macOS systems don't fail due to missing platform-specific APIs.

## Environment Variables

- `SKIP_KEYCHAIN_TESTS`: Set to skip integration tests that require keychain access
  ```bash
  SKIP_KEYCHAIN_TESTS=1 go test -v ./...
  ```

- `TEST_CERT_NAME`: Used in provisioner tests for replacer validation
- `ENVIRONMENT`: Used in provisioner tests for tag replacer validation

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


## Contributing

When adding new tests:

1. Follow the existing test patterns
2. Use `t.Helper()` for test helper functions
3. Clean up resources in defer statements or cleanup functions
4. Skip integration tests appropriately with `SKIP_KEYCHAIN_TESTS`
5. Document any new test requirements

## Questions?

For issues or questions about testing, please open an issue on the GitHub repository.
