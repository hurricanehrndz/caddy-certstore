package caddycertstore

import (
	"github.com/tailscale/certstore"
)

// CertificateSelector specifies criteria for selecting a certificate from the store.
type CertificateSelector struct {
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

// cleanup closes the identity and store resources
func (selector *CertificateSelector) cleanup() {
	if selector.identity != nil {
		selector.identity.Close()
		selector.identity = nil
	}
	if selector.store != nil {
		selector.store.Close()
		selector.store = nil
	}
}
