package certstore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
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

// TestCertificateSelection_RenewedCertificate guards renewals: the old and new
// certificates coexist in the store in no guaranteed order, and picking the
// first match would keep presenting the old one until it expires.
func TestCertificateSelection_RenewedCertificate(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	now := time.Now()
	old := &fakeIdentity{cert: newTestCertificateValidity(t, "renew.example.test", key, now.Add(-48*time.Hour), now.Add(time.Hour))}
	renewed := &fakeIdentity{cert: newTestCertificateValidity(t, "renew.example.test", key, now.Add(-time.Hour), now.Add(48*time.Hour))}
	middle := &fakeIdentity{cert: newTestCertificateValidity(t, "renew.example.test", key, now.Add(-24*time.Hour), now.Add(2*time.Hour))}
	other := &fakeIdentity{cert: newTestCertificateValidity(t, "other.example.test", key, now.Add(-time.Hour), now.Add(72*time.Hour))}
	for _, id := range []*fakeIdentity{old, renewed, middle, other} {
		id.signer = newFakeSigner(key.Public(), []byte("ok"))
	}
	// The newest certificate is neither first nor last, so neither
	// first-match nor last-match would pick it.
	store := &fakeStore{identities: []certstore.Identity{old, renewed, middle, other}}
	withFakeStoreLoads(t, &fakeStoreLoad{store: store, identity: renewed})

	selector := newTestSelector("^renew\\.example\\.test$")
	cert, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if cert.Leaf.SerialNumber.Cmp(renewed.cert.SerialNumber) != 0 {
		t.Fatalf("expected the latest-expiring valid certificate %s, got %s", renewed.cert.SerialNumber, cert.Leaf.SerialNumber)
	}
	for name, id := range map[string]*fakeIdentity{"old": old, "middle": middle, "other": other} {
		if id.closeCount() != 1 {
			t.Fatalf("unselected %s identity should be closed once, got %d", name, id.closeCount())
		}
	}
	if renewed.closeCount() != 0 {
		t.Fatal("selected identity closed before cache release")
	}

	releaseCachedCertificate(cacheKey)
}

// TestFindMatchingIdentity_Validity guards against presenting a certificate the
// upstream will reject: an expired or not-yet-valid match must never be chosen,
// even when it is the only match or expires last.
func TestFindMatchingIdentity_Validity(t *testing.T) {
	key := newTestKey(t)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	pattern := regexp.MustCompile("^valid\\.example\\.test$")

	t.Run("only expired match is an error", func(t *testing.T) {
		expired := &fakeIdentity{cert: newTestCertificateValidity(t, "valid.example.test", key, now.Add(-48*time.Hour), now.Add(-time.Hour))}

		match, err := findMatchingIdentity([]certstore.Identity{expired}, pattern, "subject", now)
		if match != nil {
			t.Fatal("expired certificate must not be selected")
		}
		assertErrorContains(t, err, "no valid identity")
		if expired.closeCount() != 1 {
			t.Fatalf("expired identity should be closed once, got %d", expired.closeCount())
		}
	})

	t.Run("not yet valid match is skipped", func(t *testing.T) {
		current := &fakeIdentity{cert: newTestCertificateValidity(t, "valid.example.test", key, now.Add(-time.Hour), now.Add(time.Hour))}
		future := &fakeIdentity{cert: newTestCertificateValidity(t, "valid.example.test", key, now.Add(time.Hour), now.Add(48*time.Hour))}

		match, err := findMatchingIdentity([]certstore.Identity{future, current}, pattern, "subject", now)
		if err != nil {
			t.Fatalf("expected the current certificate: %v", err)
		}
		if match != current {
			t.Fatal("not-yet-valid certificate selected despite a later NotAfter")
		}
		if future.closeCount() != 1 {
			t.Fatalf("not-yet-valid identity should be closed once, got %d", future.closeCount())
		}
	})
}

// TestRefreshingSigner_KeyAccessDenied guards the launchd daemon case: macOS
// denies a key whose ACL leaves out the process with -25308 on every attempt,
// so reloading the store per handshake only adds load and hides the fix.
func TestRefreshingSigner_KeyAccessDenied(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	cert := newTestCertificate(t, "denied.example.test", key)
	denied := fmt.Errorf("CFError -25308 (The operation couldn't be completed.)")
	// The second load would let a reload succeed, so the open count alone
	// shows whether Sign skipped the refresh.
	provider := withFakeStoreLoads(
		t,
		newFakeStoreLoad(cert, newFakeSignerWithErrors(key.Public(), nil, denied)),
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("reloaded"))),
	)

	selector := newTestSelector("^denied\\.example\\.test$")
	loadedCert, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	_, err = loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
	assertErrorContains(t, err, "AllowAllAppsAccess", "security import -A", cert.SerialNumber.String())
	if !errors.Is(err, denied) {
		t.Fatalf("expected the original signing error to be wrapped, got %v", err)
	}
	if provider.openCount() != 1 {
		t.Fatalf("access denial must not reload the store, got %d opens", provider.openCount())
	}

	releaseCachedCertificate(cacheKey)
}

// TestSignHint guards against misleading advice: only -25308 means the key's
// access control excludes this process.
func TestSignHint(t *testing.T) {
	if signHint(nil) != nil {
		t.Fatal("signHint(nil) != nil")
	}
	other := fmt.Errorf("CFError -1")
	if hinted := signHint(other); hinted != other {
		t.Fatalf("hint added to an unrelated error: %v", hinted)
	}
}

// expiryTestBase is the fake clock start. Expiry tests use certificates valid
// for 100 hours around it, so the last 10% of the lifetime starts at +40h.
var expiryTestBase = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func newExpiryTestCertificate(t *testing.T, commonName string, key *ecdsa.PrivateKey, notAfter time.Time) *x509.Certificate {
	t.Helper()

	return newTestCertificateValidity(t, commonName, key, notAfter.Add(-100*time.Hour), notAfter)
}

// TestExpiryReload_SameKeyRenewal guards issue #18: the signers cache the OS key
// handle, so a renewal that keeps the keypair never makes signing fail. Only the
// expiry check moves handshakes onto the renewed leaf before the old one expires.
func TestExpiryReload_SameKeyRenewal(t *testing.T) {
	resetCertificateCache(t)
	clock := withFakeClock(t, expiryTestBase)

	key := newTestKey(t)
	oldCert := newExpiryTestCertificate(t, "renewal.example.test", key, expiryTestBase.Add(50*time.Hour))
	renewedCert := newExpiryTestCertificate(t, "renewal.example.test", key, expiryTestBase.Add(140*time.Hour))
	loads := []*fakeStoreLoad{
		newFakeStoreLoad(oldCert, newFakeSigner(key.Public(), []byte("old"))),
		newFakeStoreLoad(renewedCert, newFakeSigner(key.Public(), []byte("renewed"))),
	}
	withFakeStoreLoads(t, loads...)

	selector := newTestSelector("^renewal\\.example\\.test$")
	_, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	clock.Advance(45 * time.Hour)
	current, err := selector.currentCertificate()
	if err != nil {
		t.Fatalf("current certificate failed: %v", err)
	}
	if current.Leaf.SerialNumber.Cmp(renewedCert.SerialNumber) != 0 {
		t.Fatalf("expected renewed serial %s near expiry, got %s", renewedCert.SerialNumber, current.Leaf.SerialNumber)
	}
	sig, err := current.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
	if err != nil || string(sig) != "renewed" {
		t.Fatalf("expected the renewed signer, got %q, %v", sig, err)
	}
	if loads[0].identity.closeCount() != 1 || loads[0].store.closeCount() != 1 {
		t.Fatalf("replaced resources should close once, got identity=%d store=%d", loads[0].identity.closeCount(), loads[0].store.closeCount())
	}

	releaseCachedCertificate(cacheKey)
}

// TestExpiryReload_Throttle guards the store against a reload per handshake
// while the leaf is near expiry and no renewal is in the store yet.
func TestExpiryReload_Throttle(t *testing.T) {
	resetCertificateCache(t)
	clock := withFakeClock(t, expiryTestBase)

	key := newTestKey(t)
	cert := newExpiryTestCertificate(t, "throttle.example.test", key, expiryTestBase.Add(50*time.Hour))
	loads := []*fakeStoreLoad{
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("ok"))),
		{openErr: errRefreshLoad},
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("ok"))),
	}
	provider := withFakeStoreLoads(t, loads...)

	selector := newTestSelector("^throttle\\.example\\.test$")
	_, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	assertCurrentSerial := func(wantOpens int) {
		t.Helper()
		current, err := selector.currentCertificate()
		if err != nil {
			t.Fatalf("current certificate failed: %v", err)
		}
		if current.Leaf.SerialNumber.Cmp(cert.SerialNumber) != 0 {
			t.Fatalf("expected the current serial %s to be kept, got %s", cert.SerialNumber, current.Leaf.SerialNumber)
		}
		if provider.openCount() != wantOpens {
			t.Fatalf("expected %d store opens, got %d", wantOpens, provider.openCount())
		}
	}

	t.Run("not near expiry does not reload", func(t *testing.T) {
		clock.Advance(39 * time.Hour)
		assertCurrentSerial(1)
	})
	t.Run("failed reload keeps the current certificate", func(t *testing.T) {
		clock.Advance(2 * time.Hour)
		assertCurrentSerial(2)
	})
	t.Run("within the throttle window does not reload", func(t *testing.T) {
		clock.Advance(reloadThrottle - time.Second)
		assertCurrentSerial(2)
	})
	t.Run("after the throttle window reloads again", func(t *testing.T) {
		clock.Advance(time.Second)
		assertCurrentSerial(3)
		// A same-leaf reload still swaps in the fresh handles: it restarts the
		// throttle, so keeping a stale handle would block the failure path too.
		if loads[0].identity.closeCount() != 1 || loads[0].store.closeCount() != 1 {
			t.Fatalf("replaced resources should close once, got identity=%d store=%d", loads[0].identity.closeCount(), loads[0].store.closeCount())
		}
		if loads[2].identity.closeCount() != 0 {
			t.Fatal("fresh resources closed instead of served")
		}
	})

	releaseCachedCertificate(cacheKey)
}

// TestExpiryReload_ConcurrentHandshakes guards against every in-flight handshake
// enumerating the store when the leaf crosses into its last 10%.
func TestExpiryReload_ConcurrentHandshakes(t *testing.T) {
	resetCertificateCache(t)
	clock := withFakeClock(t, expiryTestBase)

	key := newTestKey(t)
	oldCert := newExpiryTestCertificate(t, "concurrent.example.test", key, expiryTestBase.Add(50*time.Hour))
	renewedCert := newExpiryTestCertificate(t, "concurrent.example.test", key, expiryTestBase.Add(140*time.Hour))
	provider := withFakeStoreLoads(
		t,
		newFakeStoreLoad(oldCert, newFakeSigner(key.Public(), []byte("old"))),
		newFakeStoreLoad(renewedCert, newFakeSigner(key.Public(), []byte("renewed"))),
	)

	selector := newTestSelector("^concurrent\\.example\\.test$")
	_, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}

	clock.Advance(45 * time.Hour)
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if _, err := selector.currentCertificate(); err != nil {
				t.Errorf("current certificate failed: %v", err)
			}
		})
	}
	wg.Wait()

	// A handshake that passed the read-locked check before the swap still
	// reaches reloadNearExpiry; the recheck under the write lock must stop it.
	selector.cacheEntry.reloadNearExpiry()

	if provider.openCount() != 2 {
		t.Fatalf("expected one reload for concurrent handshakes, got %d store opens", provider.openCount())
	}

	releaseCachedCertificate(cacheKey)
}

// TestRefreshingSigner_ReloadThrottle guards the "certificate removed with no
// replacement" case: the cached key handle keeps failing, and without a
// throttle every handshake would reload the store.
func TestRefreshingSigner_ReloadThrottle(t *testing.T) {
	resetCertificateCache(t)
	clock := withFakeClock(t, time.Now())

	key := newTestKey(t)
	cert := newTestCertificate(t, "removed.example.test", key)
	provider := withFakeStoreLoads(
		t,
		newFakeStoreLoad(cert, newFakeSignerWithErrors(key.Public(), nil, errStaleSigner)),
		newFakeStoreLoad(cert, newFakeSignerWithErrors(key.Public(), nil, errRetrySigner, errStaleSigner, errStaleSigner)),
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("recovered"))),
	)

	selector := newTestSelector("^removed\\.example\\.test$")
	_, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	sign := func() ([]byte, error) {
		current, err := selector.currentCertificate()
		if err != nil {
			t.Fatalf("current certificate failed: %v", err)
		}
		return current.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
	}

	_, err = sign()
	assertErrorContains(t, err, "retry failed")
	if provider.openCount() != 2 {
		t.Fatalf("expected the first failure to reload, got %d store opens", provider.openCount())
	}

	clock.Advance(reloadThrottle - time.Second)
	_, err = sign()
	assertErrorContains(t, err, "throttled", errStaleSigner.Error())
	if provider.openCount() != 2 {
		t.Fatalf("expected no reload within the throttle window, got %d store opens", provider.openCount())
	}

	clock.Advance(time.Second)
	sig, err := sign()
	if err != nil || string(sig) != "recovered" {
		t.Fatalf("expected a reload after the throttle window, got %q, %v", sig, err)
	}

	releaseCachedCertificate(cacheKey)
}

// TestRefreshingSigner_ReleasedEntry guards against leaking OS handles: a
// handshake still signing after its config was released must not reload the
// store into an entry that nothing will close again.
func TestRefreshingSigner_ReleasedEntry(t *testing.T) {
	resetCertificateCache(t)

	key := newTestKey(t)
	cert := newTestCertificate(t, "released.example.test", key)
	provider := withFakeStoreLoads(
		t,
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("ok"))),
		newFakeStoreLoad(cert, newFakeSigner(key.Public(), []byte("leaked"))),
	)

	selector := newTestSelector("^released\\.example\\.test$")
	loadedCert, cacheKey, err := selector.getCachedCertificate()
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	releaseCachedCertificate(cacheKey)

	_, err = loadedCert.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
	assertErrorContains(t, err, "released", "signer is closed")
	if provider.openCount() != 1 {
		t.Fatalf("expected no reload into a released entry, got %d store opens", provider.openCount())
	}
}

// TestRefreshingSigner_AlreadyReloaded guards against N failing handshakes each
// reloading the store: a signer created before another handshake's reload must
// reuse that reload, and still retry only with the key its leaf was sent with.
func TestRefreshingSigner_AlreadyReloaded(t *testing.T) {
	t.Run("same key retries on the current signer", func(t *testing.T) {
		resetCertificateCache(t)

		key := newTestKey(t)
		initialCert := newTestCertificate(t, "dedup.example.test", key)
		renewedCert := newTestCertificate(t, "dedup.example.test", key)
		provider := withFakeStoreLoads(
			t,
			newFakeStoreLoad(initialCert, newFakeSignerWithErrors(key.Public(), nil, errStaleSigner)),
			newFakeStoreLoad(renewedCert, newFakeSignerWithErrors(key.Public(), []byte("current"), nil, errStaleSigner)),
		)

		selector := newTestSelector("^dedup\\.example\\.test$")
		first, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		second, err := selector.currentCertificate()
		if err != nil {
			t.Fatalf("current certificate failed: %v", err)
		}

		if _, err := first.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256); err != nil {
			t.Fatalf("first handshake should refresh and retry: %v", err)
		}
		sig, err := second.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		if err != nil || string(sig) != "current" {
			t.Fatalf("expected a retry on the current signer, got %q, %v", sig, err)
		}
		if provider.openCount() != 2 {
			t.Fatalf("expected the second failure to reuse the first reload, got %d store opens", provider.openCount())
		}

		releaseCachedCertificate(cacheKey)
	})

	t.Run("different key fails loudly", func(t *testing.T) {
		resetCertificateCache(t)

		initialKey := newTestKey(t)
		rotatedKey := newTestKey(t)
		initialCert := newTestCertificate(t, "dedup-rotation.example.test", initialKey)
		rotatedCert := newTestCertificate(t, "dedup-rotation.example.test", rotatedKey)
		provider := withFakeStoreLoads(
			t,
			newFakeStoreLoad(initialCert, newFakeSignerWithErrors(initialKey.Public(), nil, errStaleSigner)),
			// The rotated key signs fine: the risk is a valid signature from the
			// wrong key, which the server rejects against the leaf already sent.
			newFakeStoreLoad(rotatedCert, newFakeSigner(rotatedKey.Public(), []byte("wrong-key"))),
		)

		selector := newTestSelector("^dedup-rotation\\.example\\.test$")
		first, cacheKey, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("load failed: %v", err)
		}
		second, err := selector.currentCertificate()
		if err != nil {
			t.Fatalf("current certificate failed: %v", err)
		}

		_, err = first.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		assertErrorContains(t, err, "cannot be retried safely")
		sig, err := second.PrivateKey.(crypto.Signer).Sign(crand.Reader, []byte("digest"), crypto.SHA256)
		if sig != nil {
			t.Fatalf("handshake that sent the old leaf signed with the rotated key: %q", sig)
		}
		assertErrorContains(t, err, "cannot be retried safely", "reloaded with a different key")
		if provider.openCount() != 2 {
			t.Fatalf("expected the second failure to reuse the first reload, got %d store opens", provider.openCount())
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

func withFakeClock(t *testing.T, start time.Time) *fakeClock {
	t.Helper()

	clock := &fakeClock{now: start}
	oldNow := timeNow
	timeNow = clock.Now
	t.Cleanup(func() {
		timeNow = oldNow
	})
	return clock
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type fakeStoreProvider struct {
	mu    sync.Mutex
	loads []*fakeStoreLoad
	opens int
}

func (p *fakeStoreProvider) open(certstore.StoreLocation, ...certstore.StorePermission) (certstore.Store, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Count unexpected opens too, so a test asserting openCount sees them even
	// when the caller swallows the error.
	p.opens++
	if p.opens > len(p.loads) {
		return nil, fmt.Errorf("unexpected certificate store open #%d", p.opens)
	}
	load := p.loads[p.opens-1]
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

	return newTestCertificateValidity(t, commonName, key, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
}

func newTestCertificateValidity(t *testing.T, commonName string, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()

	serial := atomic.AddInt64(&testSerial, 1)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
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
