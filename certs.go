package caddycertstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/tailscale/certstore"
)

func getStoreLocation(loc string) certstore.StoreLocation {
	location := strings.ToLower(loc)
	switch location {
	case "system":
		return certstore.System
	case "user":
		return certstore.User
	default:
		return certstore.System
	}
}

func loadCertificateByName(commonName string, location certstore.StoreLocation) (tls.Certificate, certstore.Store, certstore.Identity, error) {
	var cert tls.Certificate

	store, err := certstore.Open(location, certstore.ReadOnly)
	if err != nil {
		return cert, nil, nil, err
	}

	identities, err := store.Identities()
	if err != nil {
		store.Close()
		return cert, nil, nil, err
	}

	identity := findMatchingIdentity(identities, commonName)
	if identity == nil {
		store.Close()
		return cert, nil, nil, fmt.Errorf("no identity found with CN '%s' in %v store", commonName, location)
	}

	cert, err = buildTLSCertificate(identity)
	if err != nil {
		identity.Close()
		store.Close()
		return cert, nil, nil, err
	}

	return cert, store, identity, nil
}

// findMatchingIdentity searches for an identity with the given common name.
// It closes all non-matching identities and returns the first match, or nil if not found.
func findMatchingIdentity(identities []certstore.Identity, commonName string) certstore.Identity {
	var match certstore.Identity

	for _, tmpID := range identities {
		certInfo, err := tmpID.Certificate()
		if err != nil {
			tmpID.Close()
			continue
		}

		if certInfo.Subject.CommonName != commonName {
			tmpID.Close()
			continue
		}

		// Found a match - close any previous match and keep this one
		if match != nil {
			match.Close()
		}
		match = tmpID
		break
	}

	return match
}

// buildTLSCertificate constructs a tls.Certificate from a certstore.Identity.
func buildTLSCertificate(identity certstore.Identity) (tls.Certificate, error) {
	var cert tls.Certificate

	certChain, err := identity.CertificateChain()
	if err != nil {
		return cert, err
	}

	signer, err := identity.Signer()
	if err != nil {
		return cert, err
	}

	cert = tls.Certificate{
		Leaf:        certChain[0],
		Certificate: serializeCertificateChain(certChain),
		PrivateKey:  signer,
	}

	return cert, nil
}

func isValidCertificate(cert tls.Certificate) bool {
	return len(cert.Certificate) != 0 && cert.PrivateKey != nil
}

func serializeCertificateChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
