package certstore

import (
	"crypto/tls"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertificateCache_ConcurrentAccess(t *testing.T) {
	// Import test certificate
	importTestCertificate(t)
	defer removeTestCertificate(t)

	// Clear cache before test
	cacheMutex.Lock()
	certCache = make(map[string]*cachedCert)
	cacheMutex.Unlock()

	// Create multiple selectors with different patterns that match the same cert
	selectors := []*CertSelector{
		{Pattern: "^" + testCertCN + "$", Location: "user"},
		{Pattern: "test\\..*\\.local", Location: "user"},
		{Pattern: ".*caddycertstore.*", Location: "user"},
	}

	// Compile patterns for all selectors
	for _, sel := range selectors {
		var err error
		sel.pattern, err = regexp.Compile(sel.Pattern)
		if err != nil {
			t.Fatalf("Failed to compile pattern: %v", err)
		}
	}

	var wg sync.WaitGroup
	results := make([]struct {
		cert     tls.Certificate
		cacheKey string
		err      error
	}, len(selectors))

	// Load certificates concurrently
	for i, sel := range selectors {
		wg.Add(1)
		go func(idx int, selector *CertSelector) {
			defer wg.Done()

			// Small delay to increase concurrency likelihood
			time.Sleep(time.Millisecond * 10)

			cert, key, err := selector.getCachedCertificate()
			results[idx].cert = cert
			results[idx].cacheKey = key
			results[idx].err = err
		}(i, sel)
	}

	wg.Wait()

	// Verify all loads succeeded
	for i, result := range results {
		if result.err != nil {
			t.Errorf("Selector %d failed to load: %v", i, result.err)
		}
	}

	// All selectors should have the same cache key (same certificate)
	firstKey := results[0].cacheKey
	for i := 1; i < len(results); i++ {
		if results[i].cacheKey != firstKey {
			t.Errorf("Cache key mismatch: selector 0 has %s, selector %d has %s",
				firstKey[:16], i, results[i].cacheKey[:16])
		}
	}

	// Verify only one certificate is cached
	cacheMutex.Lock()
	cacheSize := len(certCache)
	cacheMutex.Unlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 cached certificate, got %d", cacheSize)
	}

	// Verify reference count
	cacheMutex.Lock()
	cached := certCache[firstKey]
	refCount := atomic.LoadInt32(&cached.refCount)
	cacheMutex.Unlock()

	expectedRefCount := int32(len(selectors))
	if refCount != expectedRefCount {
		t.Errorf("Expected refCount=%d, got %d", expectedRefCount, refCount)
	}

	// Cleanup all references
	for _, result := range results {
		releaseCachedCertificate(result.cacheKey)
	}

	// Verify cache is empty after cleanup
	cacheMutex.Lock()
	cacheSize = len(certCache)
	cacheMutex.Unlock()

	if cacheSize != 0 {
		t.Errorf("Expected empty cache after cleanup, got %d entries", cacheSize)
	}
}

func TestCertificateCache_RefCounting(t *testing.T) {
	// Import test certificate
	importTestCertificate(t)
	defer removeTestCertificate(t)

	// Clear cache before test
	cacheMutex.Lock()
	certCache = make(map[string]*cachedCert)
	cacheMutex.Unlock()

	selector := &CertSelector{
		Pattern:  "^" + testCertCN + "$",
		Location: "user",
	}

	// Compile pattern
	var err error
	selector.pattern, err = regexp.Compile(selector.Pattern)
	if err != nil {
		t.Fatalf("Failed to compile pattern: %v", err)
	}

	// Load certificate 3 times
	var cacheKeys []string
	for i := range 3 {
		_, key, err := selector.getCachedCertificate()
		if err != nil {
			t.Fatalf("Failed to load certificate (iteration %d): %v", i, err)
		}
		cacheKeys = append(cacheKeys, key)
	}

	// Verify all keys are the same
	for i := 1; i < len(cacheKeys); i++ {
		if cacheKeys[i] != cacheKeys[0] {
			t.Errorf("Cache key mismatch at iteration %d", i)
		}
	}

	// Verify reference count is 3
	cacheMutex.Lock()
	cached := certCache[cacheKeys[0]]
	refCount := atomic.LoadInt32(&cached.refCount)
	cacheMutex.Unlock()

	if refCount != 3 {
		t.Errorf("Expected refCount=3, got %d", refCount)
	}

	// Release 2 references
	releaseCachedCertificate(cacheKeys[0])
	releaseCachedCertificate(cacheKeys[1])

	// Verify reference count is 1
	cacheMutex.Lock()
	cached = certCache[cacheKeys[0]]
	refCount = atomic.LoadInt32(&cached.refCount)
	cacheMutex.Unlock()

	if refCount != 1 {
		t.Errorf("Expected refCount=1 after 2 releases, got %d", refCount)
	}

	// Verify certificate still in cache
	cacheMutex.Lock()
	cacheSize := len(certCache)
	cacheMutex.Unlock()

	if cacheSize != 1 {
		t.Errorf("Expected 1 cached certificate, got %d", cacheSize)
	}

	// Release last reference
	releaseCachedCertificate(cacheKeys[2])

	// Verify cache is now empty
	cacheMutex.Lock()
	cacheSize = len(certCache)
	cacheMutex.Unlock()

	if cacheSize != 0 {
		t.Errorf("Expected empty cache after final release, got %d entries", cacheSize)
	}
}
