// Package caddycertstore provides a Caddy module for loading TLS certificates
// from OS-native certificate stores (macOS Keychain, Windows Certificate Store).
//
// This module implements the CertificateLoader interface and can be used in
// Caddy's TLS configuration with the module ID "tls.certificates.load_certstore".
package caddycertstore

import (
	"crypto/tls"
	"sync"

	"github.com/tailscale/certstore"

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
	Certificates []*CertInStore `json:"certificates,omitempty"`

	mu sync.Mutex
}

type CertInStore struct {
	// Name is the common name of the certificate to load
	Name string `json:"name,omitempty"`

	// Location specifies which certificate store to use ("user" or "system")
	Location string `json:"location,omitempty"`

	// Issuer is the common name of the signing authority (optional filter)
	Issuer string `json:"issuer,omitempty"`

	// Arbitrary values to associate with this certificate.
	// Can be useful when you want to select a particular
	// certificate when there may be multiple valid candidates.
	Tags []string `json:"tags,omitempty"`

	// runtime resources kept for cleanup (unexported, not serialized)
	store    certstore.Store
	identity certstore.Identity
}

func (*CertStoreLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.load_certstore",
		New: func() caddy.Module { return new(CertStoreLoader) },
	}
}

// TODO: Implement provisioner and do config validation - confirm Name or Issuer has been set

// LoadCertificates returns the certificates for each search parameter contained in csl.
func (csl *CertStoreLoader) LoadCertificates() ([]caddytls.Certificate, error) {
	certs := make([]caddytls.Certificate, 0, len(csl.Certificates))

	// Load certificates from keychain/certificate store
	for _, cis := range csl.Certificates {
		cert, err := csl.loadFromCertStore(cis)
		if err != nil {
			return nil, err
		}

		if !isValidCertificate(cert) {
			// Close resources for invalid certificates
			cis.cleanup()
			continue
		}

		certs = append(certs, caddytls.Certificate{
			Certificate: cert,
			Tags:        cis.Tags,
		})
	}

	return certs, nil
}

// loadFromCertStore loads a certificate and stores the resources in the CertInStore instance.
func (csl *CertStoreLoader) loadFromCertStore(cis *CertInStore) (tls.Certificate, error) {
	cert, store, identity, err := loadCertificateByName(cis.Name, getStoreLocation(cis.Location))
	if err != nil {
		return cert, err
	}

	// Store resources in the CertInStore for later cleanup
	cis.store = store
	cis.identity = identity

	return cert, nil
}

// Cleanup implements caddy.CleanerUpper and closes all opened certificate store resources.
func (csl *CertStoreLoader) Cleanup() error {
	csl.mu.Lock()
	defer csl.mu.Unlock()

	for _, cis := range csl.Certificates {
		cis.cleanup()
	}

	return nil
}

// cleanup closes the identity and store resources
func (cis *CertInStore) cleanup() {
	if cis.identity != nil {
		cis.identity.Close()
		cis.identity = nil
	}
	if cis.store != nil {
		cis.store.Close()
		cis.store = nil
	}
}
