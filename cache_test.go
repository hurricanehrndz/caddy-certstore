package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tailscale/certstore"
)

func TestCertificateCache_SelectorAwareReuseAndRefCounting(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	cert := newTestCertificate(t, "cache.example.test", key)
	loads := []*fakeStoreLoad{
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("first"))),
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("reused"))),
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("separate"))),
	}
	provider := withFakeStoreLoads(t, loads...)

	selectorA := newTestSelector("^cache\\.example\\.test$")
	selectorB := newTestSelector("^cache\\.example\\.test$")
	selectorC := newTestSelector("cache\\.example\\..*")

	_, cacheKeyA, err := selectorA.getCachedCertificate()
	if err != nil {
		t.Fatalf("first selector load failed: %v", err)
	}
	_, cacheKeyB, err := selectorB.getCachedCertificate()
	if err != nil {
		t.Fatalf("identical selector load failed: %v", err)
	}
	_, cacheKeyC, err := selectorC.getCachedCertificate()
	if err != nil {
		t.Fatalf("different selector load failed: %v", err)
	}

	if cacheKeyA != cacheKeyB {
		t.Fatalf("identical selectors should share cache key: %s != %s", cacheKeyA, cacheKeyB)
	}
	if cacheKeyA == cacheKeyC {
		t.Fatal("different selectors matching the same leaf should not share mutable cache entries")
	}
	if provider.openCount() != 3 {
		t.Fatalf("expected each lookup to load once for cache-key calculation, got %d opens", provider.openCount())
	}
	if loads[1].identity.closeCount() != 1 || loads[1].store.closeCount() != 1 {
		t.Fatalf("reused lookup resources should be closed immediately, got identity=%d store=%d", loads[1].identity.closeCount(), loads[1].store.closeCount())
	}

	cacheMutex.Lock()
	cacheSize := len(certCache)
	sharedRefCount := atomic.LoadInt32(&certCache[cacheKeyA].refCount)
	separateRefCount := atomic.LoadInt32(&certCache[cacheKeyC].refCount)
	cacheMutex.Unlock()

	if cacheSize != 2 {
		t.Fatalf("expected 2 selector-aware cache entries, got %d", cacheSize)
	}
	if sharedRefCount != 2 {
		t.Fatalf("expected shared refCount=2, got %d", sharedRefCount)
	}
	if separateRefCount != 1 {
		t.Fatalf("expected separate refCount=1, got %d", separateRefCount)
	}

	releaseCachedCertificate(cacheKeyA)
	if loads[0].identity.closeCount() != 0 || loads[0].store.closeCount() != 0 {
		t.Fatal("active shared resources closed before final release")
	}

	releaseCachedCertificate(cacheKeyB)
	if loads[0].identity.closeCount() != 1 || loads[0].store.closeCount() != 1 {
		t.Fatalf("shared resources should close exactly once after final release, got identity=%d store=%d", loads[0].identity.closeCount(), loads[0].store.closeCount())
	}

	releaseCachedCertificate(cacheKeyC)
	if loads[2].identity.closeCount() != 1 || loads[2].store.closeCount() != 1 {
		t.Fatalf("separate resources should close exactly once, got identity=%d store=%d", loads[2].identity.closeCount(), loads[2].store.closeCount())
	}

	cacheMutex.Lock()
	cacheSize = len(certCache)
	cacheMutex.Unlock()
	if cacheSize != 0 {
		t.Fatalf("expected empty cache after cleanup, got %d entries", cacheSize)
	}
}

func TestCachedCertificateRefresh_SameKeySwapsResources(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	initialCert := newTestCertificate(t, "refresh.example.test", key)
	refreshedCert := newTestCertificate(t, "refresh.example.test", key)
	loads := []*fakeStoreLoad{
		newFakeStoreLoad(initialCert, newFakeSignerWithErrors(key.Public(), nil, errStaleSigner)),
		newFakeStoreLoad(refreshedCert, newFakeSigner(key.Public(), []byte("refreshed-signature"))),
	}
	withFakeStoreLoads(t, loads...)

	selector := newTestSelector("^refresh\\.example\\.test$")
	cert, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	sig, err := cert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
	if err != nil {
		t.Fatalf("expected same-key refresh retry to succeed: %v", err)
	}
	if string(sig) != "refreshed-signature" {
		t.Fatalf("expected refreshed signature, got %q", sig)
	}
	if loads[0].identity.closeCount() != 1 || loads[0].store.closeCount() != 1 {
		t.Fatalf("old resources should close after refresh, got identity=%d store=%d", loads[0].identity.closeCount(), loads[0].store.closeCount())
	}
	if loads[1].identity.closeCount() != 0 || loads[1].store.closeCount() != 0 {
		t.Fatal("refreshed resources closed before cache release")
	}

	current, err := selector.cacheEntry.currentCertificate()
	if err != nil {
		t.Fatalf("current certificate failed: %v", err)
	}
	if current.Leaf.SerialNumber.Cmp(refreshedCert.SerialNumber) != 0 {
		t.Fatalf("expected current leaf serial %s, got %s", refreshedCert.SerialNumber, current.Leaf.SerialNumber)
	}

	releaseCachedCertificate(cacheKey)
	if loads[1].identity.closeCount() != 1 || loads[1].store.closeCount() != 1 {
		t.Fatalf("refreshed resources should close exactly once on release, got identity=%d store=%d", loads[1].identity.closeCount(), loads[1].store.closeCount())
	}
}

func TestRefreshingSigner(t *testing.T) {
	t.Run("first sign success does not refresh", func(t *testing.T) {
		resetCertificateCache(t)

		key := newTestKey(t)
		cert := newTestCertificate(t, "sign.example.test", key)
		provider := withFakeStoreLoads(t, newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("ok"))))

		selector := newTestSelector("^sign\\.example\\.test$")
		loadedCert, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}

		sig, err := loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		if err != nil {
			t.Fatalf("sign failed: %v", err)
		}
		if string(sig) != "ok" {
			t.Fatalf("unexpected signature %q", sig)
		}
		if provider.openCount() != 1 {
			t.Fatalf("expected no refresh loads, got %d opens", provider.openCount())
		}

		releaseCachedCertificate(cacheKey)
	})

	t.Run("refresh load failure preserves original signing error", func(t *testing.T) {
		resetCertificateCache(t)

		key := newTestKey(t)
		cert := newTestCertificate(t, "refresh-failure.example.test", key)
		loads := []*fakeStoreLoad{
			newFakeStoreLoad(cert, newFakeSignerWithErrors(key.Public(), nil, errStaleSigner)),
			{openErr: errRefreshLoad},
		}
		withFakeStoreLoads(t, loads...)

		selector := newTestSelector("^refresh-failure\\.example\\.test$")
		loadedCert, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}

		_, err = loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		assertErrorContains(t, err, "refresh failed", errStaleSigner.Error(), errRefreshLoad.Error())

		releaseCachedCertificate(cacheKey)
	})

	t.Run("retry failure preserves original and retry errors", func(t *testing.T) {
		resetCertificateCache(t)

		key := newTestKey(t)
		initialCert := newTestCertificate(t, "retry-failure.example.test", key)
		refreshedCert := newTestCertificate(t, "retry-failure.example.test", key)
		loads := []*fakeStoreLoad{
			newFakeStoreLoad(initialCert, newFakeSignerWithErrors(key.Public(), nil, errStaleSigner)),
			newFakeStoreLoad(refreshedCert, newFakeSignerWithErrors(key.Public(), nil, errRetrySigner)),
		}
		withFakeStoreLoads(t, loads...)

		selector := newTestSelector("^retry-failure\\.example\\.test$")
		loadedCert, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}

		_, err = loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		assertErrorContains(t, err, "retry failed", errStaleSigner.Error(), errRetrySigner.Error())

		releaseCachedCertificate(cacheKey)
	})

	t.Run("different key rotation refreshes cache for future handshakes", func(t *testing.T) {
		resetCertificateCache(t)

		initialKey := newTestKey(t)
		refreshedKey := newTestKey(t)
		initialCert := newTestCertificate(t, "rotation.example.test", initialKey)
		refreshedCert := newTestCertificate(t, "rotation.example.test", refreshedKey)
		loads := []*fakeStoreLoad{
			newFakeStoreLoad(initialCert, newFakeSignerWithErrors(initialKey.Public(), nil, errStaleSigner)),
			newFakeStoreLoad(refreshedCert, newFakeSigner(refreshedKey.Public(), []byte("future"))),
		}
		withFakeStoreLoads(t, loads...)

		selector := newTestSelector("^rotation\\.example\\.test$")
		loadedCert, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}

		_, err = loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		assertErrorContains(t, err, "cache refreshed for future handshakes", "cannot be retried safely", errStaleSigner.Error())

		current, err := selector.cacheEntry.currentCertificate()
		if err != nil {
			t.Fatalf("current certificate failed: %v", err)
		}
		if current.Leaf.SerialNumber.Cmp(refreshedCert.SerialNumber) != 0 {
			t.Fatalf("expected future handshakes to see refreshed serial %s, got %s", refreshedCert.SerialNumber, current.Leaf.SerialNumber)
		}

		releaseCachedCertificate(cacheKey)
	})
}

var (
	errStaleSigner = fmt.Errorf("stale signer")
	errRefreshLoad = fmt.Errorf("refresh load failed")
	errRetrySigner = fmt.Errorf("retry signer failed")
	testSerial     int64
)

func resetCertificateCache(t *testing.T) {
	t.Helper()

	cacheMutex.Lock()
	certCache = make(map[string]*cachedCert)
	cacheMutex.Unlock()
}

func withFakeStoreLoads(t *testing.T, loads ...*fakeStoreLoad) *fakeStoreProvider {
	t.Helper()

	provider := &fakeStoreProvider{loads: loads}
	oldOpen := openCertStore
	openCertStore = provider.open
	t.Cleanup(func() {
		openCertStore = oldOpen
	})
	return provider
}

type fakeStoreProvider struct {
	mu    sync.Mutex
	loads []*fakeStoreLoad
	opens int
}

func (p *fakeStoreProvider) open(certstore.StoreLocation, ...certstore.StorePermission) (certstore.Store, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.opens >= len(p.loads) {
		return nil, fmt.Errorf("unexpected certificate store open #%d", p.opens+1)
	}
	load := p.loads[p.opens]
	p.opens++
	if load.openErr != nil {
		return nil, load.openErr
	}
	return load.store, nil
}

func (p *fakeStoreProvider) openCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.opens
}

type fakeStoreLoad struct {
	store    *fakeStore
	identity *fakeIdentity
	openErr  error
}

func newFakeStoreLoad(cert *x509.Certificate, signer crypto.Signer) *fakeStoreLoad {
	identity := &fakeIdentity{cert: cert, signer: signer}
	store := &fakeStore{identities: []certstore.Identity{identity}}
	return &fakeStoreLoad{store: store, identity: identity}
}

type fakeStore struct {
	identities []certstore.Identity
	closed     int32
}

func (s *fakeStore) Identities() ([]certstore.Identity, error) { return s.identities, nil }
func (s *fakeStore) Import([]byte, string) error               { return nil }
func (s *fakeStore) Close()                                    { atomic.AddInt32(&s.closed, 1) }
func (s *fakeStore) closeCount() int32                         { return atomic.LoadInt32(&s.closed) }

type fakeIdentity struct {
	cert   *x509.Certificate
	signer crypto.Signer
	closed int32
}

func (i *fakeIdentity) Certificate() (*x509.Certificate, error) { return i.cert, nil }
func (i *fakeIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}
func (i *fakeIdentity) Signer() (crypto.Signer, error) { return i.signer, nil }
func (i *fakeIdentity) Delete() error                  { return nil }
func (i *fakeIdentity) Close()                         { atomic.AddInt32(&i.closed, 1) }
func (i *fakeIdentity) closeCount() int32              { return atomic.LoadInt32(&i.closed) }

type fakeSigner struct {
	public crypto.PublicKey
	sig    []byte

	mu     sync.Mutex
	errors []error
}

func newFakeSigner(public crypto.PublicKey, sig []byte) *fakeSigner {
	return &fakeSigner{public: public, sig: sig}
}

func newFakeSignerWithErrors(public crypto.PublicKey, sig []byte, errors ...error) *fakeSigner {
	return &fakeSigner{public: public, sig: sig, errors: errors}
}

func (s *fakeSigner) Public() crypto.PublicKey { return s.public }

func (s *fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.errors) > 0 {
		err := s.errors[0]
		s.errors = s.errors[1:]
		if err != nil {
			return nil, err
		}
	}
	return append([]byte(nil), s.sig...), nil
}

func newTestSelector(pattern string) *CertSelector {
	return &CertSelector{
		Pattern:  pattern,
		Location: "user",
		pattern:  regexp.MustCompile(pattern),
	}
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func newTestCertificate(t *testing.T, commonName string, key *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	serial := atomic.AddInt64(&testSerial, 1)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(crand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func assertErrorContains(t *testing.T, err error, parts ...string) {
	t.Helper()

	if err == nil {
		t.Fatal("expected error")
	}
	message := err.Error()
	for _, part := range parts {
		if !strings.Contains(message, part) {
			t.Fatalf("expected error %q to contain %q", message, part)
		}
	}
}
