package certstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"regexp"
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

// findMatchingIdentity searches for an identity based on the certificate matcher criteria.
// If pattern is non-nil, it delegates to regex-based matching; otherwise, it uses exact
// common name matching. It closes all non-matching identities.
func findMatchingIdentity(identities []certstore.Identity, commonName string, pattern *regexp.Regexp) (match certstore.Identity, err error) {
	switch {
	case pattern != nil:
		return findMatchingIdentityByPattern(identities, pattern)
	default:
		return findMatchingIdentityByCommonName(identities, commonName)
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

		matched := certInfo.Subject.CommonName == commonName
		if matched {
			match = tmpID
			break
		}

		tmpID.Close()
	}

	if match == nil {
		err = fmt.Errorf("no identity found with CN '%s'", commonName)
	}

	return match, err
}

// findMatchingIdentityByPattern searches for an identity with the given regex pattern.
// It closes all non-matching identities and returns the first match, or an error if not found.
func findMatchingIdentityByPattern(identities []certstore.Identity, pattern *regexp.Regexp) (match certstore.Identity, err error) {
	for _, tmpID := range identities {
		certInfo, err := tmpID.Certificate()
		if err != nil {
			tmpID.Close()
			continue
		}

		matched := pattern.MatchString(certInfo.Subject.CommonName)
		if matched {
			match = tmpID
			break
		}

		tmpID.Close()
	}

	if match == nil {
		err = fmt.Errorf("no identity found matching pattern '%s'", pattern.String())
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
