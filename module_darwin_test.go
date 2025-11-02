//go:build darwin

package certstore

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
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

// importCertificateToKeychain imports the test certificate from testdata into login keychain
func importCertificateToKeychain(t *testing.T) {
	t.Helper()

	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain test (SKIP_KEYCHAIN_TESTS set)")
	}

	// Get absolute path to p12 file
	p12Path, err := filepath.Abs(testCertP12)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(p12Path); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s. Run 'make test-cert' to generate it.", p12Path)
	}

	// Import certificate into login keychain using security tool
	cmd := exec.Command("security", "import", p12Path,
		"-k", os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
		"-P", testCertPass,
		"-T", "/usr/bin/codesign",
		"-T", "/usr/bin/security",
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		outputStr := string(output)
		if len(outputStr) > 0 && (outputStr[0:1] == "s" || len(outputStr) > 15) {
			for i := 0; i < len(outputStr)-7; i++ {
				if outputStr[i:i+7] == "already" {
					t.Logf("Certificate already in keychain: %s", testCertCN)
					return
				}
			}
		}
		t.Fatalf("Failed to import certificate to keychain: %v\nOutput: %s", err, output)
	}

	t.Logf("Successfully imported certificate to keychain: %s", testCertCN)
}

// removeCertificateFromKeychain removes the test certificate from login keychain
func removeCertificateFromKeychain(t *testing.T) {
	t.Helper()

	cmd := exec.Command("security", "delete-certificate",
		"-c", testCertCN,
		os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
	)

	_ = cmd.Run()
}

func TestHTTPTransport_Provision_Darwin(t *testing.T) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain integration test (SKIP_KEYCHAIN_TESTS set)")
	}

	importCertificateToKeychain(t)
	defer removeCertificateFromKeychain(t)

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

func TestCertSelector_LoadCertificate_Darwin(t *testing.T) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain test (SKIP_KEYCHAIN_TESTS set)")
	}

	importCertificateToKeychain(t)
	defer removeCertificateFromKeychain(t)

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
				pattern:  regexp.MustCompile("test\\..*\\.local"),
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
			tt.selector.cleanup()
		})
	}
}

func TestSerializeCertificateChain_Darwin(t *testing.T) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain test (SKIP_KEYCHAIN_TESTS set)")
	}

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
