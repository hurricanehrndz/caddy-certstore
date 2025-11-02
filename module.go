package caddycertstore

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
)

func init() {
	caddy.RegisterModule(HTTPTransport{})
}

// HTTPTransport is an HTTP transport wrapper that uses certificates from given matcher for MTLS
type HTTPTransport struct {
	// Embed the standard HTTP transport
	*reverseproxy.HTTPTransport

	// Your custom field for certificate name/tag
	ClientCertificateMatcher *Matcher `json:"client_certificate_match,omitempty"`
}

func (h HTTPTransport) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.transport.certstore",
		New: func() caddy.Module { return new(HTTPTransport) },
	}
}

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

// Cleanup implements caddy.CleanerUpper, closes any idle connections.
// and frees any allocations from accessing certificate store
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

// Interface guards
var (
	_ caddy.Provisioner         = (*HTTPTransport)(nil)
	_ http.RoundTripper         = (*HTTPTransport)(nil)
	_ caddy.CleanerUpper        = (*HTTPTransport)(nil)
	_ reverseproxy.TLSTransport = (*HTTPTransport)(nil)
)
