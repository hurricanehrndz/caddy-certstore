//go:build darwin

package caddycertstore

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

const (
	testCertCN     = "test.caddycertstore.local"
	testCertIssuer = "test.caddycertstore.local" // Self-signed, so issuer = subject
	testCertP12    = "testdata/test-cert.p12"
	testCertPEM    = "testdata/test-cert.pem"
	testCertPass   = "test123"
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
	// This imports both the certificate and private key
	cmd := exec.Command("security", "import", p12Path,
		"-k", os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
		"-P", testCertPass,
		"-T", "/usr/bin/codesign", // Allow codesign to access the key
		"-T", "/usr/bin/security", // Allow security to access the key
	)

	if output, err := cmd.CombinedOutput(); err != nil {
		// Check if certificate already exists
		outputStr := string(output)
		if len(outputStr) > 0 && (outputStr[0:1] == "s" || len(outputStr) > 15) {
			// Simple check - if output mentions "already", assume it exists
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

	// Remove from login keychain
	cmd := exec.Command("security", "delete-certificate",
		"-c", testCertCN,
		os.Getenv("HOME")+"/Library/Keychains/login.keychain-db",
	)

	// Ignore errors - certificate might not exist
	_ = cmd.Run()
}

func TestCertStoreLoader_LoadCertificates_Integration(t *testing.T) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain integration test (SKIP_KEYCHAIN_TESTS set)")
	}

	// Import test certificate
	importCertificateToKeychain(t)
	defer removeCertificateFromKeychain(t)

	tests := []struct {
		name        string
		loader      *CertStoreLoader
		expectError bool
		validate    func(*testing.T, []caddytls.Certificate)
	}{
		{
			name: "load certificate by common name",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name:     testCertCN,
						Location: "user", // Use user since we imported to login keychain
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, certs []caddytls.Certificate) {
				if len(certs) != 1 {
					t.Fatalf("Expected 1 certificate, got %d", len(certs))
				}
				if certs[0].Leaf.Subject.CommonName != testCertCN {
					t.Errorf("Expected CN '%s', got '%s'", testCertCN, certs[0].Leaf.Subject.CommonName)
				}
				if certs[0].PrivateKey == nil {
					t.Error("Expected certificate to have private key")
				}
			},
		},
		{
			name: "load certificate by issuer (self-signed)",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Issuer:   testCertIssuer,
						Location: "user",
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, certs []caddytls.Certificate) {
				if len(certs) != 1 {
					t.Fatalf("Expected 1 certificate, got %d", len(certs))
				}
				if certs[0].Leaf.Issuer.CommonName != testCertIssuer {
					t.Errorf("Expected Issuer CN '%s', got '%s'", testCertIssuer, certs[0].Leaf.Issuer.CommonName)
				}
			},
		},
		{
			name: "load non-existent certificate",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name:     "nonexistent.certificate.local",
						Location: "user",
					},
				},
			},
			expectError: true,
		},
		{
			name: "load certificate with tags",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name:     testCertCN,
						Location: "user",
						Tags:     []string{"test", "integration"},
					},
				},
			},
			expectError: false,
			validate: func(t *testing.T, certs []caddytls.Certificate) {
				if len(certs) != 1 {
					t.Fatalf("Expected 1 certificate, got %d", len(certs))
				}
				if len(certs[0].Tags) != 2 {
					t.Errorf("Expected 2 tags, got %d", len(certs[0].Tags))
				}
				if !slices.Contains(certs[0].Tags, "test") || !slices.Contains(certs[0].Tags, "integration") {
					t.Errorf("Expected tags to contain 'test' and 'integration', got %v", certs[0].Tags)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Provision the loader
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			if err := tt.loader.Provision(ctx); err != nil {
				t.Fatalf("Failed to provision loader: %v", err)
			}

			// Load certificates
			certs, err := tt.loader.LoadCertificates()

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.validate != nil {
					tt.validate(t, certs)
				}
			}

			// Cleanup
			if err := tt.loader.Cleanup(); err != nil {
				t.Errorf("Failed to cleanup: %v", err)
			}
		})
	}
}

func TestSerializeCertificateChain_Darwin(t *testing.T) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		t.Skip("Skipping keychain test (SKIP_KEYCHAIN_TESTS set)")
	}

	// Load the test certificate from testdata
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

	// Test serialization
	chain := []*x509.Certificate{cert}
	result := serializeCertificateChain(chain)

	if len(result) != 1 {
		t.Fatalf("Expected 1 certificate in chain, got %d", len(result))
	}

	if len(result[0]) == 0 {
		t.Error("Expected non-empty certificate data")
	}

	// Verify we can parse the serialized certificate
	parsed, err := x509.ParseCertificate(result[0])
	if err != nil {
		t.Errorf("Failed to parse serialized certificate: %v", err)
	}

	if parsed.Subject.CommonName != cert.Subject.CommonName {
		t.Errorf("Expected CN '%s', got '%s'", cert.Subject.CommonName, parsed.Subject.CommonName)
	}
}

func BenchmarkLoadCertificate_Darwin(b *testing.B) {
	if os.Getenv("SKIP_KEYCHAIN_TESTS") != "" {
		b.Skip("Skipping benchmark (SKIP_KEYCHAIN_TESTS set)")
	}

	// Note: This benchmark assumes the test certificate is already in the keychain
	selector := &CertificateSelector{
		Name:     testCertCN,
		Location: "user",
	}

	for b.Loop() {
		_, _, _, _ = loadCertificate(selector)
	}
}
