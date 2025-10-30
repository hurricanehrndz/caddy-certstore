package caddycertstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/tailscale/certstore"
)

// getStoreLocation converts a string location to certstore.StoreLocation.
func getStoreLocation(location string) certstore.StoreLocation {
	switch strings.ToLower(location) {
	case "system":
		return certstore.System
	case "user":
		return certstore.User
	default:
		return certstore.System
	}
}

// loadCertificate loads a certificate from the OS certificate store based on the selector criteria.
func loadCertificate(selector *CertificateSelector) (tls.Certificate, certstore.Store, certstore.Identity, error) {
	var cert tls.Certificate

	storeLocation := getStoreLocation(selector.Location)

	store, err := certstore.Open(storeLocation, certstore.ReadOnly)
	if err != nil {
		return cert, nil, nil, err
	}

	identities, err := store.Identities()
	if err != nil {
		store.Close()
		return cert, nil, nil, err
	}

	identity, err := findMatchingIdentity(identities, selector)
	if err != nil {
		store.Close()
		return cert, nil, nil, fmt.Errorf("%w in %s store", err, selector.Location)
	}

	cert, err = buildTLSCertificate(identity)
	if err != nil {
		identity.Close()
		store.Close()
		return cert, nil, nil, err
	}

	return cert, store, identity, nil
}

// findMatchingIdentity searches for an identity based on the certificate selector criteria.
// It delegates to specific matching functions based on which selector fields are set.
// It closes all non-matching identities and returns the first match, or an error if not found.
func findMatchingIdentity(identities []certstore.Identity, selector *CertificateSelector) (certstore.Identity, error) {
	switch {
	case selector.Issuer != "":
		return findMatchingIdentityByIssuer(identities, selector.Issuer)
	default:
		return findMatchingIdentityByCommonName(identities, selector.Name)
	}
}

// findMatchingIdentityByCommonName searches for an identity with the given common name.
// It closes all non-matching identities and returns the first match, or an error if not found.
func findMatchingIdentityByCommonName(identities []certstore.Identity, commonName string) (match certstore.Identity, err error) {
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

		match = tmpID
		break
	}

	if match == nil {
		err = fmt.Errorf("no identity found with CN '%s'", commonName)
	}

	return match, err
}

// findMatchingIdentityByIssuer searches for an identity with the given issuer common name.
// It closes all non-matching identities and returns the first match, or an error if not found.
func findMatchingIdentityByIssuer(identities []certstore.Identity, issuer string) (match certstore.Identity, err error) {
	for _, tmpID := range identities {
		certInfo, err := tmpID.Certificate()
		if err != nil {
			tmpID.Close()
			continue
		}

		if certInfo.Issuer.CommonName != issuer {
			tmpID.Close()
			continue
		}

		match = tmpID
		break
	}

	if match == nil {
		err = fmt.Errorf("no identity found with Issuer '%s'", issuer)
	}

	return match, err
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

// isValidCertificate checks if a certificate has the required components.
func isValidCertificate(cert tls.Certificate) bool {
	return len(cert.Certificate) != 0 && cert.PrivateKey != nil
}

// serializeCertificateChain converts a certificate chain to raw DER format.
func serializeCertificateChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
