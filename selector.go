package certstore

import (
	"crypto/tls"
	"fmt"
	"regexp"

	"github.com/tailscale/certstore"
	"go.uber.org/zap"
)

// CertSelector specifies criteria for selecting a certificate from the store.
type CertSelector struct {
	// Name is the common name or regex pattern of the certificate to load.
	// If the value is a valid regex pattern (contains regex metacharacters),
	// it will be compiled and used for pattern matching. Otherwise, exact
	// string matching is used.
	Name string `json:"name,omitempty"`

	// Location specifies which certificate store to use.
	// On Windows: "user" (CurrentUser) or "machine" (LocalMachine)
	// On macOS: "user" or "system" (no effect - Keychain searches both automatically)
	Location string `json:"location,omitempty"`

	// Issuer is the common name of ceritifcate authority that issued the certificate to be loaded,
	// only exact matches are supported.
	Issuer string `json:"issuer,omitempty"`

	// runtime resources kept for cleanup (unexported, not serialized)
	cacheKey string
	pattern  *regexp.Regexp
	logger   *zap.Logger
}

// loadCertificateWithResources loads a certificate from the store and returns
// the certificate along with the store and identity handles for resource management.
func (cs *CertSelector) loadCertificateWithResources() (tls.Certificate, certstore.Store, certstore.Identity, error) {
	var cert tls.Certificate

	storeLocation := getStoreLocation(cs.Location)

	store, err := certstore.Open(storeLocation, certstore.ReadOnly)
	if err != nil {
		return cert, nil, nil, err
	}

	identities, err := store.Identities()
	if err != nil {
		store.Close()
		return cert, nil, nil, err
	}

	identity, err := findMatchingIdentity(identities, cs.Issuer, cs.Name, cs.pattern)
	if err != nil {
		store.Close()
		return cert, nil, nil, fmt.Errorf("%w in %s store", err, cs.Location)
	}

	// Log the certificate details if logger is available
	if cs.logger != nil {
		certInfo, err := identity.Certificate()
		if err == nil {
			issuer := certInfo.Issuer.CommonName
			if issuer == "" {
				issuer = certInfo.Issuer.String()
			}
			cs.logger.Info("loaded client certificate from OS certificate store",
				zap.String("common_name", certInfo.Subject.CommonName),
				zap.String("issuer", issuer),
				zap.String("serial_number", certInfo.SerialNumber.String()),
				zap.String("location", cs.Location),
			)
		}
	}

	cert, err = buildTLSCertificate(identity)
	if err != nil {
		identity.Close()
		store.Close()
		return cert, nil, nil, err
	}

	return cert, store, identity, nil
}

// loadCertificate loads a certificate from the store matching the configured name/pattern.
// This is kept for backward compatibility but internally uses the cached version.
func (cs *CertSelector) loadCertificate() (tls.Certificate, error) {
	cert, cacheKey, err := cs.getCachedCertificate()
	if err != nil {
		return cert, err
	}

	cs.cacheKey = cacheKey
	return cert, nil
}
