//go:build windows

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
	testCertPFX    = "testdata/test-cert.p12"    // PFX and P12 are the same format
	testCertPEM    = "testdata/test-cert.pem"
	testCertPass   = "test123"
)

// importCertificateToStore imports the test certificate from testdata into user certificate store
func importCertificateToStore(t *testing.T) {
	t.Helper()

	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store test (SKIP_CERTSTORE_TESTS set)")
	}

	// Get absolute path to pfx file
	pfxPath, err := filepath.Abs(testCertPFX)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	// Check if file exists
	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s", pfxPath)
	}

	// PowerShell script to import certificate
	// Import to CurrentUser\My (Personal) store
	psScript := `
		$password = ConvertTo-SecureString -String "` + testCertPass + `" -AsPlainText -Force
		try {
			$cert = Import-PfxCertificate -FilePath "` + pfxPath + `" -CertStoreLocation Cert:\CurrentUser\My -Password $password -Exportable
			Write-Output "SUCCESS: Imported certificate with thumbprint $($cert.Thumbprint)"
		} catch {
			if ($_.Exception.Message -like "*already exists*") {
				Write-Output "INFO: Certificate already exists"
				exit 0
			}
			Write-Error $_.Exception.Message
			exit 1
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to import certificate: %v\nOutput: %s", err, output)
	}

	t.Logf("Certificate import result: %s", output)
}

// removeCertificateFromStore removes the test certificate from user certificate store
func removeCertificateFromStore(t *testing.T) {
	t.Helper()

	// PowerShell script to remove certificate by subject
	psScript := `
		$certs = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*` + testCertCN + `*" }
		foreach ($cert in $certs) {
			Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
			Write-Output "Removed certificate: $($cert.Thumbprint)"
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	// Ignore errors - certificate might not exist
	_ = cmd.Run()
}

func TestCertStoreLoader_LoadCertificates_Integration(t *testing.T) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store integration test (SKIP_CERTSTORE_TESTS set)")
	}

	// Import test certificate
	importCertificateToStore(t)
	defer removeCertificateFromStore(t)

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
						Location: "user",
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

func TestSerializeCertificateChain_Windows(t *testing.T) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store test (SKIP_CERTSTORE_TESTS set)")
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

func BenchmarkLoadCertificate_Windows(b *testing.B) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		b.Skip("Skipping benchmark (SKIP_CERTSTORE_TESTS set)")
	}

	// Note: This benchmark assumes the test certificate is already in the certificate store
	selector := &CertificateSelector{
		Name:     testCertCN,
		Location: "user",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = loadCertificate(selector)
	}
}
