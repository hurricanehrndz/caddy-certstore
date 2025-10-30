// Package caddycertstore provides a Caddy module for loading TLS certificates
// from OS-native certificate stores (macOS Keychain, Windows Certificate Store).
//
// This module implements the CertificateLoader interface and can be used in
// Caddy's TLS configuration with the module ID "tls.certificates.load_certstore".
package caddycertstore

import (
	"crypto/tls"
	"fmt"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func init() {
	caddy.RegisterModule((*CertStoreLoader)(nil))
}

// CertStoreLoader loads certificates from OS-native certificate stores.
// It keeps track of opened stores and identities for proper cleanup.
type CertStoreLoader struct {
	// Certificates is the list of certificates to load from the store
	Certificates []*CertificateSelector `json:"certificates,omitempty"`

	mu sync.Mutex
}

func (*CertStoreLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_certstore",
		New: func() caddy.Module { return new(CertStoreLoader) },
	}
}

// Provision implements caddy.Provisioner.
func (csl *CertStoreLoader) Provision(ctx caddy.Context) error {
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}

	for i, selector := range csl.Certificates {
		// Validate that either Name or Issuer is set
		if selector.Name == "" && selector.Issuer == "" {
			return fmt.Errorf("certificate selector at index %d must have either 'name' or 'issuer' set", i)
		}

		// Replace placeholders in selector fields
		csl.Certificates[i] = &CertificateSelector{
			Name:     repl.ReplaceKnown(selector.Name, ""),
			Location: repl.ReplaceKnown(selector.Location, ""),
			Issuer:   repl.ReplaceKnown(selector.Issuer, ""),
			Tags:     replaceTags(repl, selector.Tags),
		}
	}

	return nil
}

// replaceTags applies the replacer to each tag in the slice.
func replaceTags(repl *caddy.Replacer, tags []string) []string {
	if len(tags) == 0 {
		return tags
	}

	replaced := make([]string, len(tags))
	for i, tag := range tags {
		replaced[i] = repl.ReplaceKnown(tag, "")
	}
	return replaced
}

// LoadCertificates returns the certificates for each search parameter contained in csl.
func (csl *CertStoreLoader) LoadCertificates() ([]caddytls.Certificate, error) {
	certs := make([]caddytls.Certificate, 0, len(csl.Certificates))

	// Load certificates from keychain/certificate store
	for _, cs := range csl.Certificates {
		cert, err := csl.loadFromCertStore(cs)
		if err != nil {
			return nil, err
		}

		if !isValidCertificate(cert) {
			// Close resources for invalid certificates
			cs.cleanup()
			continue
		}

		certs = append(certs, caddytls.Certificate{
			Certificate: cert,
			Tags:        cs.Tags,
		})
	}

	return certs, nil
}

// loadFromCertStore loads a certificate and stores the resources in the CertificateSelector instance.
func (csl *CertStoreLoader) loadFromCertStore(selector *CertificateSelector) (tls.Certificate, error) {
	cert, store, identity, err := loadCertificate(selector)
	if err != nil {
		return cert, err
	}

	// Store resources in the CertificateSelector for later cleanup
	selector.store = store
	selector.identity = identity

	return cert, nil
}

// Cleanup implements caddy.CleanerUpper and closes all opened certificate store resources.
func (csl *CertStoreLoader) Cleanup() error {
	csl.mu.Lock()
	defer csl.mu.Unlock()

	for _, cs := range csl.Certificates {
		cs.cleanup()
	}

	return nil
}

// Interface guards
var (
	_ caddytls.CertificateLoader = (*CertStoreLoader)(nil)
	_ caddy.Provisioner          = (*CertStoreLoader)(nil)
	_ caddy.CleanerUpper         = (*CertStoreLoader)(nil)
)
