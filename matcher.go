package caddycertstore

import (
	"crypto/tls"
	"fmt"

	"github.com/tailscale/certstore"
)

// Matcher specifies criteria for matching a certificate from the store.
type Matcher struct {
	// Name is the common name of the certificate to load
	Name string `json:"name,omitempty"`

	// Location specifies which certificate store to use.
	// On Windows: "user" (CurrentUser) or "machine" (LocalMachine)
	// On macOS: "user" or "system" (no effect - Keychain searches both automatically)
	Location string `json:"location,omitempty"`

	// runtime resources kept for cleanup (unexported, not serialized)
	store    certstore.Store
	identity certstore.Identity
}

// cleanup closes the identity and store resources
func (m *Matcher) cleanup() {
	if m.identity != nil {
		m.identity.Close()
		m.identity = nil
	}
	if m.store != nil {
		m.store.Close()
		m.store = nil
	}
}

// getCertificate
func (m *Matcher) getCertificate() (tls.Certificate, error) {
	var cert tls.Certificate

	storeLocation := getStoreLocation(m.Location)

	store, err := certstore.Open(storeLocation, certstore.ReadOnly)
	if err != nil {
		return cert, err
	}

	identities, err := store.Identities()
	if err != nil {
		store.Close()
		return cert, err
	}

	identity, err := findMatchingIdentity(identities, m.Name)
	if err != nil {
		store.Close()
		return cert, fmt.Errorf("%w in %s store", err, m.Location)
	}

	cert, err = buildTLSCertificate(identity)
	if err != nil {
		identity.Close()
		store.Close()
		return cert, err
	}

	m.store = store
	m.identity = identity

	return cert, nil
}
