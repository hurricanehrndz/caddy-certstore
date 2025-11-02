package caddycertstore

import (
	"crypto/tls"
	"fmt"
	"regexp"

	"github.com/tailscale/certstore"
)

// Matcher specifies criteria for matching a certificate from the store.
type Matcher struct {
	// Name is the common name or regex pattern of the certificate to load.
	// If the value is a valid regex pattern (contains regex metacharacters),
	// it will be compiled and used for pattern matching. Otherwise, exact
	// string matching is used.
	Name string `json:"name,omitempty"`

	// Location specifies which certificate store to use.
	// On Windows: "user" (CurrentUser) or "machine" (LocalMachine)
	// On macOS: "user" or "system" (no effect - Keychain searches both automatically)
	Location string `json:"location,omitempty"`

	// runtime resources kept for cleanup (unexported, not serialized)
	store    certstore.Store
	identity certstore.Identity
	pattern  *regexp.Regexp
}

// cleanup closes the identity and store resources and resets internal state.
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

// getCertificate loads a certificate from the store matching the configured name/pattern.
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

	identity, err := findMatchingIdentity(identities, m.Name, m.pattern)
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
