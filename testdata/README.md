# Test Certificates

This directory contains pre-generated test certificates for the caddy-certstore integration tests.

## Files

- **test-cert.pem** - Self-signed X.509 certificate
- **test-key.pem** - ECDSA P-256 private key (unencrypted)
- **test-cert.p12** - PKCS#12 bundle containing both certificate and key

## Certificate Details

- **Common Name**: test.caddycertstore.local
- **Organization**: Caddy CertStore Test
- **Subject Alternative Names**:
  - DNS: test.caddycertstore.local
  - DNS: localhost
  - IP: 127.0.0.1
- **Key Type**: ECDSA with P-256 curve
- **Validity**: 5 years (October 2025 - October 2030)
- **Self-signed**: Yes (issuer = subject)

## PKCS#12 Password

The `test-cert.p12` file is encrypted with password: `test123`

## Usage

These certificates are used by `module_darwin_test.go` for integration testing on macOS. The tests import the certificate into the login keychain, run tests, then clean up.

## Regenerating Certificates

If the certificates expire or need to be updated:

```bash
# Generate new certificate (valid 5 years)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout test-key.pem -out test-cert.pem -days 1825 -nodes \
  -subj "/CN=test.caddycertstore.local/O=Caddy CertStore Test" \
  -addext "subjectAltName=DNS:test.caddycertstore.local,DNS:localhost,IP:127.0.0.1"

# Create PKCS#12 bundle
openssl pkcs12 -export -out test-cert.p12 \
  -inkey test-key.pem -in test-cert.pem \
  -passout pass:test123 \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1
```

## Security Note

These are **test certificates only**. The private key is intentionally unencrypted and committed to the repository. These certificates should **never** be used in production environments.

## Verification

View certificate details:
```bash
openssl x509 -in test-cert.pem -noout -text
openssl x509 -in test-cert.pem -noout -dates -subject
```

Verify PKCS#12 bundle:
```bash
openssl pkcs12 -in test-cert.p12 -info -noout -passin pass:test123
```
