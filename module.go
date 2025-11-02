package caddycertstore

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(HTTPTransport{})
}

// HTTPTransport wraps reverseproxy.HTTPTransport to provide client certificate
// authentication using certificates from OS certificate stores (macOS Keychain,
// Windows Certificate Store) for mTLS connections to upstream servers.
type HTTPTransport struct {
	// Embed the standard HTTP transport
	*reverseproxy.HTTPTransport

	// ClientCertificateMatcher specifies the criteria for selecting a client
	// certificate from the OS certificate store for mTLS authentication.
	ClientCertificateMatcher *Matcher `json:"client_certificate_match,omitempty"`
}

// CaddyModule returns the Caddy module information.
func (h HTTPTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.certstore",
		New: func() caddy.Module { return new(HTTPTransport) },
	}
}

// Provision sets up the HTTP transport by loading the client certificate
// from the OS certificate store based on the configured matcher criteria.
// It compiles regex patterns if needed and validates the certificate exists.
func (h *HTTPTransport) Provision(ctx caddy.Context) error {
	// Provision the embedded transport first
	if err := h.HTTPTransport.Provision(ctx); err != nil {
		return err
	}

	if h.ClientCertificateMatcher == nil {
		return nil
	}

	// Validate that Name is set
	if h.ClientCertificateMatcher.Name == "" {
		return fmt.Errorf("client_certificate_match must set 'name' property")
	}

	// Compile regex pattern if Name looks like a regex
	certNameOrPattern := h.ClientCertificateMatcher.Name
	if isRegexPattern(h.ClientCertificateMatcher.Name) {
		var err error
		h.ClientCertificateMatcher.pattern, err = regexp.Compile(certNameOrPattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", certNameOrPattern, err)
		}
	}

	clientCert, err := h.ClientCertificateMatcher.getCertificate()
	if err != nil {
		return fmt.Errorf("no client certificate found in: %s with common name: %s", h.ClientCertificateMatcher.Location, h.ClientCertificateMatcher.Name)
	}

	if h.Transport.TLSClientConfig == nil {
		h.Transport.TLSClientConfig = new(tls.Config)
	}
	h.Transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}

	return nil
}

// Cleanup implements caddy.CleanerUpper. It closes any idle connections
// and frees resources allocated from accessing the certificate store.
func (h *HTTPTransport) Cleanup() error {
	if h.ClientCertificateMatcher != nil {
		defer h.ClientCertificateMatcher.cleanup()
	}

	err := h.HTTPTransport.Cleanup()
	if err != nil {
		return err
	}

	return nil
}

// isRegexPattern checks if a string contains regex metacharacters
// such as *, +, ?, ^, $, (, ), [, ], {, }, |, or \.
// The dot (.) is intentionally excluded to avoid treating FQDNs as patterns.
func isRegexPattern(s string) bool {
	// Check for common regex metacharacters
	regexChars := []rune{'*', '+', '?', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\'}
	for _, r := range s {
		for _, metachar := range regexChars {
			if r == metachar {
				return true
			}
		}
	}
	return false
}

// Interface guards
var (
	_ caddy.Provisioner         = (*HTTPTransport)(nil)
	_ http.RoundTripper         = (*HTTPTransport)(nil)
	_ caddy.CleanerUpper        = (*HTTPTransport)(nil)
	_ reverseproxy.TLSTransport = (*HTTPTransport)(nil)
)
