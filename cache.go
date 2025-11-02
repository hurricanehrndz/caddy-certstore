package certstore

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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
	cert     tls.Certificate
	identity certstore.Identity
	store    certstore.Store
	refCount int32
	cacheKey string
}

// makeCacheKey generates a unique cache key from a certificate's thumbprint.
// The thumbprint is the SHA256 hash of the DER-encoded certificate.
func makeCacheKey(cert *x509.Certificate) string {
	thumbprint := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", thumbprint)
}

// getCachedCertificate attempts to retrieve a cached certificate or loads it
// if not present. It increments the reference count for the certificate.
// Returns the certificate, its cache key, and any error encountered.
func (cs *CertSelector) getCachedCertificate() (tls.Certificate, string, error) {
	var emptyCert tls.Certificate

	// Load the certificate to determine its cache key
	cert, store, identity, err := cs.loadCertificateWithResources()
	if err != nil {
		return emptyCert, "", err
	}

	// Generate cache key from certificate thumbprint
	cacheKey := makeCacheKey(cert.Leaf)

	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	// Check if this certificate is already cached
	if cached, exists := certCache[cacheKey]; exists {
		// Certificate already cached - close the newly loaded resources
		identity.Close()
		store.Close()

		// Increment reference count and return cached certificate
		atomic.AddInt32(&cached.refCount, 1)

		if cs.logger != nil {
			cs.logger.Debug("reusing cached certificate",
				zap.String("cache_key", cacheKey[:16]),
				zap.Int32("ref_count", atomic.LoadInt32(&cached.refCount)),
			)
		}

		return cached.cert, cacheKey, nil
	}

	// Not cached yet - add it to the cache
	cached := &cachedCert{
		cert:     cert,
		identity: identity,
		store:    store,
		refCount: 1,
		cacheKey: cacheKey,
	}
	certCache[cacheKey] = cached

	if cs.logger != nil {
		cs.logger.Debug("cached new certificate",
			zap.String("cache_key", cacheKey[:16]),
			zap.String("common_name", cert.Leaf.Subject.CommonName),
		)
	}

	return cert, cacheKey, nil
}

// releaseCachedCertificate decrements the reference count for a cached certificate.
// When the reference count reaches zero, it closes the associated OS resources
// and removes the certificate from the cache.
func releaseCachedCertificate(cacheKey string) {
	cacheMutex.Lock()
	defer cacheMutex.Unlock()

	cached, exists := certCache[cacheKey]
	if !exists {
		return
	}

	newCount := atomic.AddInt32(&cached.refCount, -1)
	if newCount <= 0 {
		// Last reference removed - cleanup resources
		if cached.identity != nil {
			cached.identity.Close()
		}
		if cached.store != nil {
			cached.store.Close()
		}
		delete(certCache, cacheKey)
	}
}
