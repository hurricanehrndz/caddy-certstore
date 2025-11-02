package certstore

import (
	"context"
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

func TestIsRegexPattern(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"simple FQDN", "example.com", false},
		{"FQDN with subdomain", "sub.example.com", false},
		{"asterisk wildcard", "*.example.com", true},
		{"plus quantifier", "test+", true},
		{"question mark", "test?", true},
		{"caret anchor", "^test", true},
		{"dollar anchor", "test$", true},
		{"parentheses", "(test)", true},
		{"square brackets", "[test]", true},
		{"curly braces", "{test}", true},
		{"pipe", "test|other", true},
		{"backslash", "test\\d", true},
		{"escaped dot", "test\\.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRegexPattern(tt.input)
			if result != tt.expected {
				t.Errorf("isRegexPattern(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
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
			name: "provision with exact certificate name",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Name:     testCertCN,
					Location: "user",
				},
			},
			expectError: false,
			validate: func(t *testing.T, h *HTTPTransport) {
				if h.Transport.TLSClientConfig == nil {
					t.Fatal("Expected TLSClientConfig to be set")
				}
				if len(h.Transport.TLSClientConfig.Certificates) != 1 {
					t.Fatalf("Expected 1 certificate, got %d", len(h.Transport.TLSClientConfig.Certificates))
				}
				cert := h.Transport.TLSClientConfig.Certificates[0]
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
					Name:     "test\\.caddycertstore\\..*",
					Location: "user",
				},
			},
			expectError: false,
			validate: func(t *testing.T, h *HTTPTransport) {
				if h.Transport.TLSClientConfig == nil {
					t.Fatal("Expected TLSClientConfig to be set")
				}
				if len(h.Transport.TLSClientConfig.Certificates) != 1 {
					t.Fatalf("Expected 1 certificate, got %d", len(h.Transport.TLSClientConfig.Certificates))
				}
			},
		},
		{
			name: "provision with non-existent certificate",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Name:     "nonexistent.certificate.local",
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
			name: "provision with empty name",
			transport: &HTTPTransport{
				HTTPTransport: &reverseproxy.HTTPTransport{},
				ClientCert: &CertSelector{
					Name:     "",
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
			name: "load by exact common name",
			selector: &CertSelector{
				Name:     testCertCN,
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
				Name:     "test\\..*\\.local",
				Location: "user",
				pattern:  regexp.MustCompile(`test\..*\.local`),
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
				Name:     "nonexistent.local",
				Location: "user",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
