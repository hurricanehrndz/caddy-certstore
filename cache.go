package certstore

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	"github.com/tailscale/certstore"
	"go.uber.org/zap"
)

var (
	certCache  = make(map[string]*cachedCert)
	cacheMutex sync.Mutex
)

// cachedCert holds a cached certificate along with its OS resources
// and a reference count for tracking active users.
type cachedCert struct {
	mu sync.RWMutex

	cert     tls.Certificate
	signer   crypto.Signer
	identity certstore.Identity
	store    certstore.Store
	selector selectorSnapshot

	refCount int32
	cacheKey string
}

func makeLeafThumbprint(cert *x509.Certificate) string {
	thumbprint := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", thumbprint)
}

// makeCacheKey generates a selector-aware cache key from the resolved selector
// and the initially loaded certificate thumbprint.
func makeCacheKey(selector selectorSnapshot, cert *x509.Certificate) string {
	h := sha256.New()
	writeCacheKeyPart(h, selector.patternString)
	writeCacheKeyPart(h, selector.field)
	writeCacheKeyPart(h, selector.location)
	writeCacheKeyPart(h, makeLeafThumbprint(cert))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func writeCacheKeyPart(w io.Writer, part string) {
	_, _ = w.Write([]byte(part))
	_, _ = w.Write([]byte{0})
}

// getCachedCertificate attempts to retrieve a cached certificate or loads it
// if not present. It increments the reference count for the certificate.
// Returns the certificate, its cache key, and any error encountered.
func (cs *CertSelector) getCachedCertificate() (tls.Certificate, string, error) {
	var emptyCert tls.Certificate

	selector := cs.snapshot()

	// Load the certificate to determine its selector-aware cache key.
	cert, store, identity, err := selector.loadCertificateWithResources()
	if err != nil {
		return emptyCert, "", err
	}

	signer, err := extractCertificateSigner(cert)
	if err != nil {
		closeCertificateResources(identity, store)
		return emptyCert, "", err
	}
	cert.PrivateKey = nil

	cacheKey := makeCacheKey(selector, cert.Leaf)

	cacheMutex.Lock()
	cached, exists := certCache[cacheKey]
	if exists {
		// Certificate already cached - close the newly loaded resources.
		closeCertificateResources(identity, store)

		// Increment reference count and return cached certificate.
		atomic.AddInt32(&cached.refCount, 1)

		if selector.logger != nil {
			selector.logger.Debug(
				"reusing cached certificate",
				zap.String("cache_key", cacheKey[:16]),
				zap.Int32("ref_count", atomic.LoadInt32(&cached.refCount)),
			)
		}
	} else {
		cached = &cachedCert{
			cert:     cert,
			signer:   signer,
			identity: identity,
			store:    store,
			selector: selector,
			refCount: 1,
			cacheKey: cacheKey,
		}
		certCache[cacheKey] = cached

		if selector.logger != nil {
			selector.logger.Debug(
				"cached new certificate",
				zap.String("cache_key", cacheKey[:16]),
				zap.String("common_name", cert.Leaf.Subject.CommonName),
			)
		}
	}
	cacheMutex.Unlock()

	cs.cacheKey = cacheKey
	cs.cacheEntry = cached

	currentCert, err := cached.currentCertificate()
	if err != nil {
		return emptyCert, "", err
	}

	return currentCert, cacheKey, nil
}

func (cs *CertSelector) currentCertificate() (tls.Certificate, error) {
	if cs.cacheEntry == nil {
		return tls.Certificate{}, fmt.Errorf("client certificate cache entry is not initialized")
	}
	return cs.cacheEntry.currentCertificate()
}

func (cached *cachedCert) currentCertificate() (tls.Certificate, error) {
	cached.mu.RLock()
	defer cached.mu.RUnlock()

	cert := cloneTLSCertificate(cached.cert)
	expectedPublicKey, err := certificatePublicKey(cert)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert.PrivateKey = &refreshingSigner{
		entry:             cached,
		expectedPublicKey: expectedPublicKey,
		leafSerial:        cert.Leaf.SerialNumber.String(),
		leafThumbprint:    makeLeafThumbprint(cert.Leaf),
	}
	return cert, nil
}

func cloneTLSCertificate(cert tls.Certificate) tls.Certificate {
	clone := cert
	clone.Certificate = cloneCertificateBytes(cert.Certificate)
	clone.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
	clone.SignedCertificateTimestamps = cloneCertificateBytes(cert.SignedCertificateTimestamps)
	clone.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
	return clone
}

func cloneCertificateBytes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, item := range in {
		out[i] = append([]byte(nil), item...)
	}
	return out
}

func extractCertificateSigner(cert tls.Certificate) (crypto.Signer, error) {
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return nil, fmt.Errorf("client certificate private key does not implement crypto.Signer")
	}
	return signer, nil
}

func certificatePublicKey(cert tls.Certificate) (crypto.PublicKey, error) {
	if cert.Leaf != nil {
		return cert.Leaf.PublicKey, nil
	}
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("client certificate has no leaf certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse client certificate leaf: %w", err)
	}
	return leaf.PublicKey, nil
}

type refreshingSigner struct {
	entry             *cachedCert
	expectedPublicKey crypto.PublicKey
	leafSerial        string
	leafThumbprint    string
}

func (s *refreshingSigner) Public() crypto.PublicKey {
	return s.expectedPublicKey
}

func (s *refreshingSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	sig, err := s.signCurrent(rand, digest, opts)
	if err == nil {
		return sig, nil
	}
	originalErr := err

	canRetry, err := s.entry.refresh(s.expectedPublicKey, s.leafSerial, s.leafThumbprint, originalErr)
	if err != nil {
		return nil, err
	}
	if !canRetry {
		return nil, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: cache refreshed for future handshakes, but current handshake cannot be retried safely with a different public key: original signing error: %w",
			s.leafSerial, thumbprintPrefix(s.leafThumbprint), originalErr)
	}

	sig, retryErr := s.signCurrent(rand, digest, opts)
	if retryErr != nil {
		return nil, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: refresh succeeded, but retry failed: original signing error: %w; retry error: %v",
			s.leafSerial, thumbprintPrefix(s.leafThumbprint), originalErr, retryErr)
	}
	return sig, nil
}

func (s *refreshingSigner) signCurrent(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.entry.mu.RLock()
	defer s.entry.mu.RUnlock()

	if s.entry.signer == nil {
		return nil, fmt.Errorf("client certificate signer is closed")
	}
	return s.entry.signer.Sign(rand, digest, opts)
}

func (cached *cachedCert) refresh(expectedPublicKey crypto.PublicKey, oldSerial, oldThumbprint string, originalErr error) (bool, error) {
	cached.mu.Lock()
	defer cached.mu.Unlock()

	freshCert, freshStore, freshIdentity, err := cached.selector.loadCertificateWithResources()
	if err != nil {
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: refresh failed: original signing error: %w; refresh error: %v",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
	}

	freshSigner, err := extractCertificateSigner(freshCert)
	if err != nil {
		closeCertificateResources(freshIdentity, freshStore)
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: refresh loaded an unusable signer: original signing error: %w; refresh error: %v",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
	}
	freshCert.PrivateKey = nil

	mayRetry, err := publicKeysEqual(freshSigner.Public(), expectedPublicKey)
	if err != nil {
		closeCertificateResources(freshIdentity, freshStore)
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: refresh could not compare public keys: original signing error: %w; compare error: %v",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
	}

	oldCert := cached.cert
	oldIdentity := cached.identity
	oldStore := cached.store

	cached.cert = freshCert
	cached.signer = freshSigner
	cached.identity = freshIdentity
	cached.store = freshStore

	if cached.selector.logger != nil {
		cached.selector.logger.Warn(
			"refreshed client certificate after signer error",
			zap.String("cache_key", thumbprintPrefix(cached.cacheKey)),
			zap.String("old_serial_number", certificateSerial(oldCert)),
			zap.String("new_serial_number", certificateSerial(freshCert)),
			zap.String("old_leaf_thumbprint", thumbprintPrefix(makeLeafThumbprint(oldCert.Leaf))),
			zap.String("new_leaf_thumbprint", thumbprintPrefix(makeLeafThumbprint(freshCert.Leaf))),
			zap.Bool("retry_current_handshake", mayRetry),
			zap.Error(originalErr),
		)
	}

	closeCertificateResources(oldIdentity, oldStore)

	return mayRetry, nil
}

func publicKeysEqual(a, b crypto.PublicKey) (bool, error) {
	encodedA, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false, err
	}
	encodedB, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(encodedA, encodedB), nil
}

func certificateSerial(cert tls.Certificate) string {
	if cert.Leaf == nil || cert.Leaf.SerialNumber == nil {
		return ""
	}
	return cert.Leaf.SerialNumber.String()
}

func thumbprintPrefix(thumbprint string) string {
	if len(thumbprint) <= 16 {
		return thumbprint
	}
	return thumbprint[:16]
}

// releaseCachedCertificate decrements the reference count for a cached certificate.
// When the reference count reaches zero, it closes the associated OS resources
// and removes the certificate from the cache.
func releaseCachedCertificate(cacheKey string) {
	var toClose *cachedCert

	cacheMutex.Lock()
	cached, exists := certCache[cacheKey]
	if exists {
		newCount := atomic.AddInt32(&cached.refCount, -1)
		if newCount <= 0 {
			delete(certCache, cacheKey)
			toClose = cached
		}
	}
	cacheMutex.Unlock()

	if toClose != nil {
		toClose.close()
	}
}

func (cached *cachedCert) close() {
	cached.mu.Lock()
	defer cached.mu.Unlock()

	closeCertificateResources(cached.identity, cached.store)
	cached.identity = nil
	cached.store = nil
	cached.signer = nil
}

func closeCertificateResources(identity certstore.Identity, store certstore.Store) {
	if identity != nil {
		identity.Close()
	}
	if store != nil {
		store.Close()
	}
}
