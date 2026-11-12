package certstore

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/tailscale/certstore"
)

// openCertStore and timeNow are package variables so tests can replace the
// OS store and the clock.
var (
	openCertStore = certstore.Open
	timeNow       = time.Now
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

// findMatchingIdentity picks, among the identities whose field matches pattern,
// the one valid at now with the latest NotAfter: after a renewal the old and new
// certificates often sit in the store together, in no guaranteed order.
// It closes every other identity and returns an error if no valid identity matches.
func findMatchingIdentity(identities []certstore.Identity, pattern *regexp.Regexp, field string, now time.Time) (certstore.Identity, error) {
	if pattern == nil {
		return nil, fmt.Errorf("pattern is required")
	}

	selector := getFieldSelector(field)
	var match certstore.Identity
	var matchCert *x509.Certificate
	for _, tmpID := range identities {
		certInfo, err := tmpID.Certificate()
		if err != nil || !pattern.MatchString(selector(certInfo)) ||
			now.Before(certInfo.NotBefore) || now.After(certInfo.NotAfter) ||
			(matchCert != nil && !certInfo.NotAfter.After(matchCert.NotAfter)) {
			tmpID.Close()
			continue
		}

		if match != nil {
			match.Close()
		}
		match, matchCert = tmpID, certInfo
	}

	if match == nil {
		return nil, fmt.Errorf("no valid identity found matching pattern '%s' in field '%s'", pattern.String(), field)
	}

	return match, nil
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
	out := make([][]byte, 0, len(chain))
	for _, cert := range chain {
		out = append(out, cert.Raw)
	}
	return out
}
