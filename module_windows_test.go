//go:build windows

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
	testCertPFX  = "testdata/test-cert.p12"
	testCertPEM  = "testdata/test-cert.pem"
	testCertPass = "test123"
)

// importTestCertificate imports the test certificate from testdata into user certificate store
func importTestCertificate(t *testing.T) {
	t.Helper()

	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store test (SKIP_CERTSTORE_TESTS set)")
	}

	pfxPath, err := filepath.Abs(testCertPFX)
	if err != nil {
		t.Fatalf("Failed to get absolute path: %v", err)
	}

	if _, err := os.Stat(pfxPath); os.IsNotExist(err) {
		t.Fatalf("Test certificate not found at %s", pfxPath)
	}

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

// removeTestCertificate removes the test certificate from user certificate store
func removeTestCertificate(t *testing.T) {
	t.Helper()

	psScript := `
		$certs = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.Subject -like "*` + testCertCN + `*" }
		foreach ($cert in $certs) {
			Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
			Write-Output "Removed certificate: $($cert.Thumbprint)"
		}
	`

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psScript)
	_ = cmd.Run()
}

func TestHTTPTransport_Provision_Windows(t *testing.T) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store integration test (SKIP_CERTSTORE_TESTS set)")
	}

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

			if err := tt.transport.Cleanup(); err != nil {
				t.Errorf("Failed to cleanup: %v", err)
			}
		})
	}
}

func TestCertSelector_LoadCertificate_Windows(t *testing.T) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store test (SKIP_CERTSTORE_TESTS set)")
	}

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

			if tt.selector.cacheKey != "" {
				releaseCachedCertificate(tt.selector.cacheKey)
			}
		})
	}
}

func TestSerializeCertificateChain_Windows(t *testing.T) {
	if os.Getenv("SKIP_CERTSTORE_TESTS") != "" {
		t.Skip("Skipping certificate store test (SKIP_CERTSTORE_TESTS set)")
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
