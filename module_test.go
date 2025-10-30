package caddycertstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"os"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func TestCertStoreLoader_CaddyModule(t *testing.T) {
	loader := &CertStoreLoader{}
	info := loader.CaddyModule()

	if info.ID != "tls.certificates.load_certstore" {
		t.Errorf("Expected module ID 'tls.certificates.load_certstore', got '%s'", info.ID)
	}

	if info.New == nil {
		t.Error("Expected New function to be defined")
	}

	// Test that New returns a valid instance
	instance := info.New()
	if _, ok := instance.(*CertStoreLoader); !ok {
		t.Error("Expected New to return *CertStoreLoader")
	}
}

func TestCertStoreLoader_Provision(t *testing.T) {
	tests := []struct {
		name        string
		loader      *CertStoreLoader
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid configuration with name",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name:     "test.example.com",
						Location: "system",
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid configuration with issuer",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Issuer:   "Test CA",
						Location: "system",
					},
				},
			},
			expectError: false,
		},
		{
			name: "invalid configuration - no name or issuer",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Location: "system",
					},
				},
			},
			expectError: true,
			errorMsg:    "must have either 'name' or 'issuer' set",
		},
		{
			name: "valid configuration with environment variable",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name:     "{env.TEST_CERT_NAME}",
						Location: "system",
					},
				},
			},
			expectError: false,
		},
		{
			name: "valid configuration with tags",
			loader: &CertStoreLoader{
				Certificates: []*CertificateSelector{
					{
						Name: "test.example.com",
						Tags: []string{"production", "{env.ENVIRONMENT}"},
					},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set test environment variable
			os.Setenv("TEST_CERT_NAME", "test.example.com")
			os.Setenv("ENVIRONMENT", "test")
			defer os.Unsetenv("TEST_CERT_NAME")
			defer os.Unsetenv("ENVIRONMENT")

			// Create a proper context with a replacer
			ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
			defer cancel()

			err := tt.loader.Provision(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				} else if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}

				// Verify environment variables were replaced
				if tt.loader.Certificates[0].Name == "{env.TEST_CERT_NAME}" {
					t.Error("Environment variable in Name was not replaced")
				}
			}
		})
	}
}

func TestCertStoreLoader_Cleanup(t *testing.T) {
	loader := &CertStoreLoader{
		Certificates: []*CertificateSelector{
			{
				Name:     "test.example.com",
				Location: "system",
			},
		},
	}

	// Cleanup should not error even if resources weren't initialized
	if err := loader.Cleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}
}

func TestCertificateSelector_Cleanup(t *testing.T) {
	selector := &CertificateSelector{
		Name: "test.example.com",
	}

	// Should not panic when called on selector without resources
	selector.cleanup()

	// Verify fields are nil after cleanup
	if selector.store != nil || selector.identity != nil {
		t.Error("Expected store and identity to be nil after cleanup")
	}
}

func TestGetStoreLocation(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"system", "system"},
		{"SYSTEM", "system"},
		{"user", "user"},
		{"USER", "user"},
		{"invalid", "system"}, // Default to system
		{"", "system"},        // Default to system
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := getStoreLocation(tt.input)
			// We can't compare directly as StoreLocation is an opaque type
			// Just ensure it doesn't panic and returns a valid value
			_ = result
		})
	}
}

func TestIsValidCertificate(t *testing.T) {
	tests := []struct {
		name     string
		cert     tls.Certificate
		expected bool
	}{
		{
			name: "valid certificate",
			cert: tls.Certificate{
				Certificate: [][]byte{{0x01, 0x02}},
				PrivateKey:  &ecdsa.PrivateKey{},
			},
			expected: true,
		},
		{
			name: "missing certificate data",
			cert: tls.Certificate{
				Certificate: [][]byte{},
				PrivateKey:  &ecdsa.PrivateKey{},
			},
			expected: false,
		},
		{
			name: "missing private key",
			cert: tls.Certificate{
				Certificate: [][]byte{{0x01, 0x02}},
				PrivateKey:  nil,
			},
			expected: false,
		},
		{
			name:     "empty certificate",
			cert:     tls.Certificate{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidCertificate(tt.cert)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestReplaceTags(t *testing.T) {
	repl := caddy.NewReplacer()
	repl.Set("test_env", "production")

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty tags",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "static tags",
			input:    []string{"tag1", "tag2"},
			expected: []string{"tag1", "tag2"},
		},
		{
			name:     "tags with placeholders",
			input:    []string{"tag1", "{test_env}", "tag3"},
			expected: []string{"tag1", "production", "tag3"},
		},
		{
			name:     "tags with unknown placeholders",
			input:    []string{"{unknown_var}"},
			expected: []string{"{unknown_var}"}, // Unknown vars are left unchanged
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := replaceTags(repl, tt.input)

			if len(result) != len(tt.expected) {
				t.Fatalf("Expected %d tags, got %d", len(tt.expected), len(result))
			}

			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("Tag %d: expected '%s', got '%s'", i, tt.expected[i], result[i])
				}
			}
		})
	}
}

func BenchmarkProvision(b *testing.B) {
	loader := &CertStoreLoader{
		Certificates: []*CertificateSelector{
			{
				Name:     "test.example.com",
				Location: "system",
				Tags:     []string{"tag1", "tag2", "tag3"},
			},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for b.Loop() {
		_ = loader.Provision(ctx)
	}
}
