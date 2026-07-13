package certstore

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

const (
	testCertCN   = "test.caddycertstore.local"
	testCertP12  = "testdata/test-cert.p12"
	testCertPEM  = "testdata/test-cert.pem"
	testCertPass = "test123"
)

func supportedCertificateRequestInfo() *tls.CertificateRequestInfo {
	return &tls.CertificateRequestInfo{
		SignatureSchemes: []tls.SignatureScheme{
			tls.ECDSAWithP256AndSHA256,
			tls.PSSWithSHA256,
			tls.PKCS1WithSHA256,
		},
	}
}

func TestHTTPTransport_Provision(t *testing.T) {
	importTestCertificate(t)
	defer removeTestCertificate(t)

	tests := []struct {
		name        string
		transport   *HTTPTransport
		expectError bool
		validate    func(*testing.T, *HTTPTransport)
	}{
		{
			name: "provision with exact certificate pattern",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Pattern:  "^" + testCertCN + "$",
					Location: "user",
				},
			},
			expectError: false,
			validate: func(t *testing.T, h *HTTPTransport) {
				if h.Transport.TLSClientConfig == nil {
					t.Fatal("Expected TLSClientConfig to be set")
				}
				if len(h.Transport.TLSClientConfig.Certificates) != 0 {
					t.Fatalf("Expected no static certificates, got %d", len(h.Transport.TLSClientConfig.Certificates))
				}
				if h.Transport.TLSClientConfig.GetClientCertificate == nil {
					t.Fatal("Expected GetClientCertificate to be set")
				}
				cert, err := h.Transport.TLSClientConfig.GetClientCertificate(supportedCertificateRequestInfo())
				if err != nil {
					t.Fatalf("Unexpected GetClientCertificate error: %v", err)
				}
				if cert.Leaf == nil {
					t.Error("Expected certificate Leaf to be set")
				}
				if cert.PrivateKey == nil {
					t.Error("Expected certificate to have private key")
				}
			},
		},
		{
			name: "provision with regex pattern",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Pattern:  "test\\.caddycertstore\\..*",
					Location: "user",
				},
			},
			expectError: false,
			validate: func(t *testing.T, h *HTTPTransport) {
				if h.Transport.TLSClientConfig == nil {
					t.Fatal("Expected TLSClientConfig to be set")
				}
				if len(h.Transport.TLSClientConfig.Certificates) != 0 {
					t.Fatalf("Expected no static certificates, got %d", len(h.Transport.TLSClientConfig.Certificates))
				}
				if h.Transport.TLSClientConfig.GetClientCertificate == nil {
					t.Fatal("Expected GetClientCertificate to be set")
				}
			},
		},
		{
			name: "provision with non-existent certificate",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Pattern:  "nonexistent.certificate.local",
					Location: "user",
				},
			},
			expectError: true,
		},
		{
			name: "provision without client cert",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
			},
			expectError: false,
			validate: func(t *testing.T, h *HTTPTransport) {
				if h.Transport.TLSClientConfig != nil && len(h.Transport.TLSClientConfig.Certificates) > 0 {
					t.Error("Expected no certificates when ClientCert is nil")
				}
			},
		},
		{
			name: "provision with empty pattern",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Pattern:  "",
					Location: "user",
				},
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := tt.transport.Provision(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, tt.transport)
				}
			}

			// Cleanup
			if err := tt.transport.Cleanup(); err != nil {
				t.Errorf("Failed to cleanup: %v", err)
			}
		})
	}
}

func TestHTTPTransport_GetClientCertificate(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	cert := newTestCertificate(t, "callback.example.test", key)
	provider := withFakeStoreLoads(t, newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("ok"))))

	h := &HTTPTransport{
		HTTPTransport: &reverseproxy.HTTPTransport{},
		ClientCert:    newTestSelector("^callback\\.example\\.test$"),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}
	}()

	if len(h.Transport.TLSClientConfig.Certificates) != 0 {
		t.Fatalf("Expected certstore transport to avoid static Certificates, got %d", len(h.Transport.TLSClientConfig.Certificates))
	}
	if h.Transport.TLSClientConfig.GetClientCertificate == nil {
		t.Fatal("Expected GetClientCertificate to be set")
	}

	supported, err := h.Transport.TLSClientConfig.GetClientCertificate(supportedCertificateRequestInfo())
	if err != nil {
		t.Fatalf("GetClientCertificate returned error: %v", err)
	}
	if supported.Leaf == nil || supported.Leaf.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("Expected supported request to return cached cert serial %s", cert.SerialNumber)
	}

	unsupportedCRI := supportedCertificateRequestInfo()
	unsupportedCRI.AcceptableCAs = [][]byte{[]byte("untrusted ca")}
	unsupported, err := h.Transport.TLSClientConfig.GetClientCertificate(unsupportedCRI)
	if err != nil {
		t.Fatalf("Unsupported certificate request should not return an error: %v", err)
	}
	if unsupported.PrivateKey != nil || len(unsupported.Certificate) != 0 {
		t.Fatal("Expected unsupported request to return an empty certificate")
	}
	if provider.openCount() != 1 {
		t.Fatalf("GetClientCertificate should use cache without reloading; got %d store opens", provider.openCount())
	}
}

func TestClientCertificateRefreshRotation(t *testing.T) {
	resetCertificateCache(t)

	initialKey := newTestKey(t)
	refreshedKey := newTestKey(t)
	initialCert := newTestCertificate(t, "rotation-callback.example.test", initialKey)
	refreshedCert := newTestCertificate(t, "rotation-callback.example.test", refreshedKey)
	loads := []*fakeStoreLoad{
		newFakeStoreLoad(initialCert, newFakeSignerWithErrors(initialKey.Public(), nil, errStaleSigner)),
		newFakeStoreLoad(refreshedCert, newFakeSigner(refreshedKey.Public(), []byte("future"))),
	}
	withFakeStoreLoads(t, loads...)

	h := &HTTPTransport{
		HTTPTransport: &reverseproxy.HTTPTransport{},
		ClientCert:    newTestSelector("^rotation-callback\\.example\\.test$"),
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}
	defer func() {
		if err := h.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}
	}()

	current, err := h.Transport.TLSClientConfig.GetClientCertificate(supportedCertificateRequestInfo())
	if err != nil {
		t.Fatalf("GetClientCertificate failed: %v", err)
	}
	if current.Leaf.SerialNumber.Cmp(initialCert.SerialNumber) != 0 {
		t.Fatalf("Expected initial serial %s, got %s", initialCert.SerialNumber, current.Leaf.SerialNumber)
	}

	_, err = current.PrivateKey.(crypto.Signer).Sign(nil, []byte("digest"), crypto.SHA256)
	assertErrorContains(t, err, "cache refreshed for future handshakes", "cannot be retried safely", errStaleSigner.Error())

	future, err := h.Transport.TLSClientConfig.GetClientCertificate(supportedCertificateRequestInfo())
	if err != nil {
		t.Fatalf("GetClientCertificate after refresh failed: %v", err)
	}
	if future.Leaf.SerialNumber.Cmp(refreshedCert.SerialNumber) != 0 {
		t.Fatalf("Expected refreshed serial %s, got %s", refreshedCert.SerialNumber, future.Leaf.SerialNumber)
	}
}

func TestCertSelector_LoadCertificate(t *testing.T) {
	importTestCertificate(t)
	defer removeTestCertificate(t)

	tests := []struct {
		name        string
		selector    *CertSelector
		expectError bool
		validate    func(*testing.T, tls.Certificate)
	}{
		{
			name: "load by exact pattern",
			selector: &CertSelector{
				Pattern:  "^" + testCertCN + "$",
				Location: "user",
			},
			expectError: false,
			validate: func(t *testing.T, cert tls.Certificate) {
				if cert.Leaf == nil {
					t.Error("Expected Leaf to be set")
				}
				if cert.Leaf.Subject.CommonName != testCertCN {
					t.Errorf("Expected CN '%s', got '%s'", testCertCN, cert.Leaf.Subject.CommonName)
				}
				if cert.PrivateKey == nil {
					t.Error("Expected private key to be set")
				}
			},
		},
		{
			name: "load by regex pattern",
			selector: &CertSelector{
				Pattern:  "test\\..*\\.local",
				Location: "user",
			},
			expectError: false,
			validate: func(t *testing.T, cert tls.Certificate) {
				if cert.Leaf == nil {
					t.Error("Expected Leaf to be set")
				}
			},
		},
		{
			name: "load non-existent certificate",
			selector: &CertSelector{
				Pattern:  "nonexistent.local",
				Location: "user",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Compile pattern
			var err error
			tt.selector.pattern, err = regexp.Compile(tt.selector.Pattern)
			if err != nil {
				t.Fatalf("Failed to compile pattern: %v", err)
			}

			cert, err := tt.selector.loadCertificate()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, cert)
				}
			}

			// Cleanup
			if tt.selector.cacheKey != "" {
				releaseCachedCertificate(tt.selector.cacheKey)
			}
		})
	}
}

func TestSerializeCertificateChain(t *testing.T) {
	pemPath, err := filepath.Abs(testCertPEM)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	certPEM, err := os.ReadFile(pemPath)
	if err != nil {
		t.Fatalf("Failed to read test certificate: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	chain := []*x509.Certificate{cert}
	result := serializeCertificateChain(chain)

	if len(result) != 1 {
		t.Fatalf("Expected 1 certificate in chain, got %d", len(result))
	}

	if len(result[0]) == 0 {
		t.Error("Expected non-empty certificate data")
	}

	parsed, err := x509.ParseCertificate(result[0])
	if err != nil {
		t.Errorf("Failed to parse serialized certificate: %v", err)
	}

	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("Expected CN '%s', got '%s'", cert.Subject.CommonName, parsed.Subject.CommonName)
	}
}
