package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenCache_SetAndGet(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()
	result := &IntrospectionResult{
		Active:   true,
		ClientID: "client-1",
		Scope:    "tools:read",
	}

	cache.Set("token-abc", result)

	got, ok := cache.Get("token-abc")
	require.True(t, ok)
	assert.Equal(t, "client-1", got.ClientID)
	assert.True(t, got.Active)
}

func TestTokenCache_Miss(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()

	_, ok := cache.Get("nonexistent-token")
	assert.False(t, ok)
}

func TestTokenCache_Expiration(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cache := NewTokenCache(
		WithCacheTTL(1*time.Second),
		withNowFunc(func() time.Time { return now }),
	)

	result := &IntrospectionResult{Active: true, ClientID: "client-1"}
	cache.Set("token-abc", result)

	// Should be present before TTL.
	got, ok := cache.Get("token-abc")
	require.True(t, ok)
	assert.Equal(t, "client-1", got.ClientID)

	// Advance time past TTL.
	now = now.Add(2 * time.Second)

	_, ok = cache.Get("token-abc")
	assert.False(t, ok)
}

func TestTokenCache_DifferentTokensDifferentEntries(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()

	cache.Set("token-1", &IntrospectionResult{Active: true, ClientID: "client-1"})
	cache.Set("token-2", &IntrospectionResult{Active: true, ClientID: "client-2"})

	got1, ok1 := cache.Get("token-1")
	got2, ok2 := cache.Get("token-2")

	require.True(t, ok1)
	require.True(t, ok2)
	assert.Equal(t, "client-1", got1.ClientID)
	assert.Equal(t, "client-2", got2.ClientID)
}

func TestTokenCache_OverwriteEntry(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()

	cache.Set("token-1", &IntrospectionResult{Active: true, ClientID: "old-client"})
	cache.Set("token-1", &IntrospectionResult{Active: false, ClientID: "new-client"})

	got, ok := cache.Get("token-1")
	require.True(t, ok)
	assert.False(t, got.Active)
	assert.Equal(t, "new-client", got.ClientID)
}

func TestTokenCache_Len(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()
	assert.Equal(t, 0, cache.Len())

	cache.Set("token-1", &IntrospectionResult{Active: true})
	assert.Equal(t, 1, cache.Len())

	cache.Set("token-2", &IntrospectionResult{Active: true})
	assert.Equal(t, 2, cache.Len())
}

func TestTokenCache_TokenHashing(t *testing.T) {
	t.Parallel()

	// Verify that token hashing produces a consistent key.
	h1 := hashToken("same-token")
	h2 := hashToken("same-token")
	assert.Equal(t, h1, h2)

	// Different tokens produce different hashes.
	h3 := hashToken("different-token")
	assert.NotEqual(t, h1, h3)
}

func TestTokenCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cache := NewTokenCache()
	done := make(chan bool)

	// Concurrently set and get.
	for i := range 100 {
		go func(id int) {
			token := "token-" + string(rune('A'+id%26))
			cache.Set(token, &IntrospectionResult{Active: true, ClientID: "client"})
			cache.Get(token)
			done <- true
		}(i)
	}

	for range 100 {
		<-done
	}

	// Should not panic or deadlock.
	assert.True(t, cache.Len() > 0)
}

func TestTokenCache_ExpiredEntryCleanup(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cache := NewTokenCache(
		WithCacheTTL(1*time.Second),
		withNowFunc(func() time.Time { return now }),
	)

	cache.Set("token-1", &IntrospectionResult{Active: true})

	// Advance time past TTL.
	now = now.Add(2 * time.Second)

	// Get should trigger cleanup.
	_, ok := cache.Get("token-1")
	assert.False(t, ok)

	// Entry should be removed.
	assert.Equal(t, 0, cache.Len())
}

func TestTokenCache_CustomTTL(t *testing.T) {
	t.Parallel()

	now := time.Now()
	cache := NewTokenCache(
		WithCacheTTL(5*time.Minute),
		withNowFunc(func() time.Time { return now }),
	)

	cache.Set("token-1", &IntrospectionResult{Active: true, ClientID: "client"})

	// Still valid after 4 minutes.
	now = now.Add(4 * time.Minute)
	got, ok := cache.Get("token-1")
	require.True(t, ok)
	assert.Equal(t, "client", got.ClientID)

	// Expired after 6 minutes.
	now = now.Add(2 * time.Minute)
	_, ok = cache.Get("token-1")
	assert.False(t, ok)
}
