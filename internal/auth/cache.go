package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// defaultCacheTTL is the default time-to-live for cached introspection results.
const defaultCacheTTL = 5 * time.Minute

// defaultMaxEntries is the maximum number of entries the cache will hold.
// When this limit is reached, expired entries are evicted first; if still
// over capacity, the oldest entry is removed.
const defaultMaxEntries = 10000

// cacheEntry holds a cached introspection result with expiration.
type cacheEntry struct {
	result    *IntrospectionResult
	expiresAt time.Time
}

// TokenCache provides a thread-safe, TTL-based in-memory cache for token
// introspection results. Tokens are hashed before being used as cache keys
// to avoid storing raw token values in memory.
//
// The cache enforces a maximum entry count to prevent unbounded memory growth.
// When capacity is reached, expired entries are evicted; if still over capacity,
// the entry closest to expiration is removed.
type TokenCache struct {
	entries    map[string]cacheEntry
	now        func() time.Time // injectable for testing
	ttl        time.Duration
	maxEntries int
	mu         sync.RWMutex
}

// CacheOption configures the TokenCache.
type CacheOption func(*TokenCache)

// WithCacheTTL sets a custom TTL for cache entries.
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *TokenCache) {
		c.ttl = ttl
	}
}

// WithMaxEntries sets the maximum number of cache entries.
func WithMaxEntries(n int) CacheOption {
	return func(c *TokenCache) {
		if n > 0 {
			c.maxEntries = n
		}
	}
}

// withNowFunc sets a custom time function for testing.
func withNowFunc(now func() time.Time) CacheOption {
	return func(c *TokenCache) {
		c.now = now
	}
}

// NewTokenCache creates a new TokenCache with the given options.
func NewTokenCache(opts ...CacheOption) *TokenCache {
	c := &TokenCache{
		entries:    make(map[string]cacheEntry),
		ttl:        defaultCacheTTL,
		maxEntries: defaultMaxEntries,
		now:        time.Now,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c
}

// Get retrieves a cached introspection result for the given token.
// Returns the result and true if found and not expired, nil and false otherwise.
func (c *TokenCache) Get(token string) (*IntrospectionResult, bool) {
	key := hashToken(token)

	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}

	if c.now().After(entry.expiresAt) {
		// Entry has expired; clean it up.
		c.mu.Lock()
		delete(c.entries, key)
		c.mu.Unlock()
		return nil, false
	}

	return entry.result, true
}

// Set stores an introspection result in the cache.
// The cache entry TTL is the minimum of the configured TTL and the token's
// remaining lifetime (derived from its exp claim). This prevents caching a
// token beyond its actual expiration.
//
// If the cache is at capacity, expired entries are evicted first. If still
// at capacity after eviction, the entry closest to expiration is removed.
func (c *TokenCache) Set(token string, result *IntrospectionResult) {
	key := hashToken(token)

	ttl := c.ttl
	if result.ExpiresAt > 0 {
		tokenExpiry := time.Unix(result.ExpiresAt, 0)
		remaining := tokenExpiry.Sub(c.now())
		if remaining <= 0 {
			// Token is already expired; do not cache.
			return
		}
		if remaining < ttl {
			ttl = remaining
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// If the key already exists, just update it (no capacity issue).
	if _, exists := c.entries[key]; !exists && len(c.entries) >= c.maxEntries {
		c.evictExpiredLocked()

		// Still at capacity after evicting expired entries —
		// remove the entry closest to expiration.
		if len(c.entries) >= c.maxEntries {
			c.evictOldestLocked()
		}
	}

	c.entries[key] = cacheEntry{
		result:    result,
		expiresAt: c.now().Add(ttl),
	}
}

// Len returns the number of entries in the cache (including expired ones).
func (c *TokenCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// evictExpiredLocked removes all expired entries from the cache.
// Caller must hold c.mu write lock.
func (c *TokenCache) evictExpiredLocked() {
	now := c.now()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
}

// evictOldestLocked removes the entry with the earliest expiresAt timestamp.
// Caller must hold c.mu write lock.
func (c *TokenCache) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	first := true

	for key, entry := range c.entries {
		if first || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
			first = false
		}
	}

	if !first {
		delete(c.entries, oldestKey)
	}
}

// hashToken returns a SHA-256 hash of the token to use as a cache key.
// This avoids storing raw token values in memory.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
