package certstore

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

	// generation counts identity swaps, so a signer created before a swap can
	// tell that another handshake already reloaded the store.
	generation uint64
	// lastReload is when the store was last reloaded, by either trigger. It
	// starts zero, not at the initial load, so a signer that fails right after
	// provisioning still refreshes; the cost is one extra load when the initial
	// leaf is already in its last 10%.
	lastReload time.Time

	refCount int32
	cacheKey string
}

// reloadThrottle bounds how often an entry reloads the store, so a certificate
// removed with no replacement does not cost a store enumeration per handshake.
const reloadThrottle = 5 * time.Minute

func makeLeafThumbprint(cert *x509.Certificate) string {
	thumbprint := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", thumbprint)
}

// makeCacheKey generates a selector-aware cache key from the resolved selector
// and the initially loaded certificate thumbprint.
//
// After a reload swaps the identity, the key no longer matches the served leaf,
// so a later config reload creates a second entry for the same identity. That
// duplicates OS handles until the old config is released, which is cheaper than
// rekeying a shared entry; it is not a correctness problem.
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
	expiring := cached.expiryReloadDueLocked(timeNow())
	cached.mu.RUnlock()
	if expiring {
		cached.reloadNearExpiry()
	}

	cached.mu.RLock()
	defer cached.mu.RUnlock()

	cert := cloneTLSCertificate(cached.cert)
	expectedPublicKey, err := certificatePublicKey(cert)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert.PrivateKey = &refreshingSigner{
		entry:             cached,
		generation:        cached.generation,
		expectedPublicKey: expectedPublicKey,
		leafSerial:        cert.Leaf.SerialNumber.String(),
		leafThumbprint:    makeLeafThumbprint(cert.Leaf),
	}
	return cert, nil
}

// expiryReloadDueLocked reports whether the served leaf is in the last 10% of
// its lifetime and the reload throttle allows another store load. The signers
// cache the OS key handle, so a renewal that keeps the keypair never makes
// signing fail; without this check the old leaf is served until it expires.
// Callers must hold cached.mu.
func (cached *cachedCert) expiryReloadDueLocked(now time.Time) bool {
	leaf := cached.cert.Leaf
	if leaf == nil || cached.store == nil || now.Sub(cached.lastReload) < reloadThrottle {
		return false
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	return !now.Before(leaf.NotBefore.Add(lifetime - lifetime/10))
}

// reloadNearExpiry reloads the store to pick up a renewed leaf. No handshake
// is in flight, so unlike refresh it needs no public key gate. On failure it
// keeps serving the current leaf; the throttle limits the warning to one per window.
//
// A reload that finds the same leaf still swaps in the fresh handles. Each
// expiry reload restarts the throttle, so if it kept the old handles a stale
// signer could never be replaced by the failure path in the last 10%.
func (cached *cachedCert) reloadNearExpiry() {
	cached.mu.Lock()
	defer cached.mu.Unlock()

	// Concurrent handshakes all see the leaf expiring; only the first reloads.
	if !cached.expiryReloadDueLocked(timeNow()) {
		return
	}

	oldCert, err := cached.reloadLocked()
	logger := cached.selector.logger
	if logger == nil {
		return
	}
	if err != nil {
		logger.Warn(
			"could not reload expiring client certificate; keeping the current one",
			zap.String("cache_key", thumbprintPrefix(cached.cacheKey)),
			zap.String("serial_number", certificateSerial(cached.cert)),
			zap.Time("not_after", cached.cert.Leaf.NotAfter),
			zap.Duration("next_attempt_in", reloadThrottle),
			zap.Error(err),
		)
		return
	}
	if !bytes.Equal(oldCert.Leaf.Raw, cached.cert.Leaf.Raw) {
		logger.Info(
			"reloaded expiring client certificate",
			zap.String("cache_key", thumbprintPrefix(cached.cacheKey)),
			zap.String("old_serial_number", certificateSerial(oldCert)),
			zap.String("new_serial_number", certificateSerial(cached.cert)),
			zap.String("old_leaf_thumbprint", thumbprintPrefix(makeLeafThumbprint(oldCert.Leaf))),
			zap.String("new_leaf_thumbprint", thumbprintPrefix(makeLeafThumbprint(cached.cert.Leaf))),
		)
	}
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
	generation        uint64
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

	// A key whose access control leaves out this process fails the same way
	// after a reload, so refreshing would only reopen the store on every handshake.
	if isKeyAccessDenied(originalErr) {
		return nil, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: %w",
			s.leafSerial, thumbprintPrefix(s.leafThumbprint), signHint(originalErr))
	}

	canRetry, err := s.entry.refresh(s.generation, s.expectedPublicKey, s.leafSerial, s.leafThumbprint, originalErr)
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

// isKeyAccessDenied reports whether err is macOS errSecInteractionNotAllowed
// (-25308), which a keychain signer returns when the key's access control
// leaves out this process: a launchd daemon cannot show the access prompt.
func isKeyAccessDenied(err error) bool {
	return err != nil && strings.Contains(err.Error(), "-25308")
}

// signHint names the fix for a key whose access control leaves out this
// process, and returns any other error unchanged.
func signHint(err error) error {
	if !isKeyAccessDenied(err) {
		return err
	}
	return fmt.Errorf("%w: the key's access control does not allow this service; deploy the identity with AllowAllAppsAccess in its MDM payload, or import it with security import -A", err)
}

func (s *refreshingSigner) signCurrent(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.entry.mu.RLock()
	defer s.entry.mu.RUnlock()

	if s.entry.signer == nil {
		return nil, fmt.Errorf("client certificate signer is closed")
	}
	// A reload since this handshake sent its leaf may have swapped in another
	// key; signing with it would produce a CertificateVerify the server rejects.
	if s.entry.generation != s.generation {
		sameKey, err := publicKeysEqual(s.entry.signer.Public(), s.expectedPublicKey)
		if err != nil {
			return nil, fmt.Errorf("compare reloaded public key: %w", err)
		}
		if !sameKey {
			return nil, fmt.Errorf("client certificate was reloaded with a different key after this handshake sent its leaf")
		}
	}
	return s.entry.signer.Sign(rand, digest, opts)
}

// refresh reloads the identity after a signing failure and reports whether the
// failed handshake may retry: only when the now-current key equals
// expectedPublicKey, the key whose leaf was already sent. generation is the one
// the failing signer was created with; if it has moved on, another handshake
// already reloaded and the store is left alone.
func (cached *cachedCert) refresh(generation uint64, expectedPublicKey crypto.PublicKey, oldSerial, oldThumbprint string, originalErr error) (bool, error) {
	cached.mu.Lock()
	defer cached.mu.Unlock()

	// A released entry is out of the cache; resources loaded now would never close.
	if cached.store == nil {
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: client certificate was released: original signing error: %w",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr)
	}

	if cached.generation != generation {
		currentPublicKey, err := certificatePublicKey(cached.cert)
		if err != nil {
			return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: could not read the reloaded public key: original signing error: %w; error: %v",
				oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
		}
		mayRetry, err := publicKeysEqual(currentPublicKey, expectedPublicKey)
		if err != nil {
			return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: could not compare public keys: original signing error: %w; compare error: %v",
				oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
		}
		return mayRetry, nil
	}

	if sinceReload := timeNow().Sub(cached.lastReload); sinceReload < reloadThrottle {
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: store reload throttled, last attempt %s ago (at most one per %s): original signing error: %w",
			oldSerial, thumbprintPrefix(oldThumbprint), sinceReload.Round(time.Second), reloadThrottle, originalErr)
	}

	oldCert, err := cached.reloadLocked()
	if err != nil {
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: refresh failed: original signing error: %w; refresh error: %v",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
	}
	freshCert := cached.cert

	mayRetry, err := publicKeysEqual(cached.signer.Public(), expectedPublicKey)
	if err != nil {
		return false, fmt.Errorf("certstore signer failed for certificate serial %s thumbprint %s: cache refreshed for future handshakes, but could not compare public keys: original signing error: %w; compare error: %v",
			oldSerial, thumbprintPrefix(oldThumbprint), originalErr, err)
	}

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

	return mayRetry, nil
}

// reloadLocked loads the identity from the store, records the attempt for the
// reload throttle, swaps in the fresh identity, bumps the generation and closes
// the old resources. It returns the certificate it replaced. It swaps even when
// the store yields the same leaf, since the fresh load replaces a signer handle
// that may be stale. Callers must hold cached.mu for writing.
func (cached *cachedCert) reloadLocked() (tls.Certificate, error) {
	cached.lastReload = timeNow()

	freshCert, freshStore, freshIdentity, err := cached.selector.loadCertificateWithResources()
	if err != nil {
		return tls.Certificate{}, err
	}

	freshSigner, err := extractCertificateSigner(freshCert)
	if err != nil {
		closeCertificateResources(freshIdentity, freshStore)
		return tls.Certificate{}, fmt.Errorf("loaded an unusable signer: %w", err)
	}
	freshCert.PrivateKey = nil

	oldCert := cached.cert
	oldIdentity := cached.identity
	oldStore := cached.store

	cached.cert = freshCert
	cached.signer = freshSigner
	cached.identity = freshIdentity
	cached.store = freshStore
	cached.generation++

	closeCertificateResources(oldIdentity, oldStore)

	return oldCert, nil
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
