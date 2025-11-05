// Package certstore provides a Caddy v2 HTTP transport module that enables
// client certificate authentication using certificates from OS certificate stores
// (macOS Keychain and Windows Certificate Store) for mTLS connections to upstream servers.
package certstore

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"regexp"
	"slices"

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

	// ClientCert specifies the criteria for selecting a client
	// certificate from the OS certificate store for mTLS authentication.
	ClientCert *CertSelector `json:"client_certificate,omitempty"`
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
	// Support placeholders:
	repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		repl = caddy.NewReplacer()
	}

	// Provision the embedded transport first
	if err := h.HTTPTransport.Provision(ctx); err != nil {
		return err
	}

	if h.ClientCert == nil {
		return nil
	}

	// Validate config
	hasName := h.ClientCert.Name != ""
	hasIssuer := h.ClientCert.Issuer != ""
	if hasName == hasIssuer {
		return fmt.Errorf("client_certificate must set 'name' property")
	}

	// Set up logger for the cert selector
	h.ClientCert.logger = ctx.Logger()

	h.ClientCert.Name = repl.ReplaceKnown(h.ClientCert.Name, "")
	h.ClientCert.Issuer = repl.ReplaceKnown(h.ClientCert.Issuer, "")

	// Compile regex pattern if Name looks like a regex
	certNameOrPattern := h.ClientCert.Name
	if isRegexPattern(certNameOrPattern) && certNameOrPattern != "" {
		var err error
		h.ClientCert.pattern, err = regexp.Compile(certNameOrPattern)
		if err != nil {
			return fmt.Errorf("invalid regex pattern '%s': %w", certNameOrPattern, err)
		}
	}

	// Load certificate from cache (or load and cache it)
	clientCert, err := h.ClientCert.loadCertificate()
	if err != nil {
		return fmt.Errorf("no client certificate found in: %s with common name: %s", h.ClientCert.Location, h.ClientCert.Name)
	}

	if h.Transport.TLSClientConfig == nil {
		h.Transport.TLSClientConfig = new(tls.Config)
	}
	h.Transport.TLSClientConfig.Certificates = []tls.Certificate{clientCert}

	return nil
}

// Cleanup implements caddy.CleanerUpper. It closes any idle connections
// and decrements the reference count for the cached certificate. When the
// reference count reaches zero, the certificate's OS resources are freed.
func (h *HTTPTransport) Cleanup() error {
	if h.ClientCert != nil && h.ClientCert.cacheKey != "" {
		releaseCachedCertificate(h.ClientCert.cacheKey)
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
		if slices.Contains(regexChars, r) {
			return true
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
