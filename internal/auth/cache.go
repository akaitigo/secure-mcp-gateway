package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// defaultCacheTTL is the default time-to-live for cached introspection results.
const defaultCacheTTL = 60 * time.Second

// cacheEntry holds a cached introspection result with expiration.
type cacheEntry struct {
	result    *IntrospectionResult
	expiresAt time.Time
}

// TokenCache provides a thread-safe, TTL-based in-memory cache for token
// introspection results. Tokens are hashed before being used as cache keys
// to avoid storing raw token values in memory.
type TokenCache struct {
	entries map[string]cacheEntry
	now     func() time.Time // injectable for testing
	ttl     time.Duration
	mu      sync.RWMutex
}

// CacheOption configures the TokenCache.
type CacheOption func(*TokenCache)

// WithCacheTTL sets a custom TTL for cache entries.
func WithCacheTTL(ttl time.Duration) CacheOption {
	return func(c *TokenCache) {
		c.ttl = ttl
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
		entries: make(map[string]cacheEntry),
		ttl:     defaultCacheTTL,
		now:     time.Now,
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
func (c *TokenCache) Set(token string, result *IntrospectionResult) {
	key := hashToken(token)

	c.mu.Lock()
	c.entries[key] = cacheEntry{
		result:    result,
		expiresAt: c.now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// Len returns the number of entries in the cache (including expired ones).
func (c *TokenCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// hashToken returns a SHA-256 hash of the token to use as a cache key.
// This avoids storing raw token values in memory.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
