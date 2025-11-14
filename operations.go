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

// findMatchingIdentity searches for an identity using regex pattern matching.
// It closes all non-matching identities and returns the first match, or an error if not found.
func findMatchingIdentity(identities []certstore.Identity, pattern *regexp.Regexp, field string) (match certstore.Identity, err error) {
	if pattern == nil {
		return nil, fmt.Errorf("pattern is required")
	}

	selector := getFieldSelector(field)
	for _, tmpID := range identities {
		certInfo, err := tmpID.Certificate()
		if err != nil {
			tmpID.Close()
			continue
		}

		fieldValue := selector(certInfo)
		if pattern.MatchString(fieldValue) {
			match = tmpID
			break
		}

		tmpID.Close()
	}

	if match == nil {
		err = fmt.Errorf("no identity found matching pattern '%s' in field '%s'", pattern.String(), field)
	}

	return match, err
}

// getFieldSelector returns a function that extracts the specified field from a certificate.
func getFieldSelector(field string) func(*x509.Certificate) string {
	switch field {
	case "issuer":
		return func(cert *x509.Certificate) string { return cert.Issuer.CommonName }
	case "serial":
		return func(cert *x509.Certificate) string { return cert.SerialNumber.String() }
	case "dns_names":
		return func(cert *x509.Certificate) string {
			if len(cert.DNSNames) == 0 {
				return ""
			}
			return cert.DNSNames[0]
		}
	default:
		return func(cert *x509.Certificate) string { return cert.Subject.CommonName }
	}
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

// serializeCertificateChain converts a certificate chain to raw DER format.
func serializeCertificateChain(chain []*x509.Certificate) [][]byte {
	out := [][]byte{}
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
