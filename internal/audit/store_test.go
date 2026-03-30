package audit

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStore_AppendAndList(t *testing.T) {
	t.Parallel()

	store := NewStore()

	// Append 3 entries.
	for i := 0; i < 3; i++ {
		store.Append(NewEntry(
			fmt.Sprintf("client-%d", i),
			"tools/call",
			DecisionAllow,
			fmt.Sprintf("req-%d", i),
			nil,
		))
	}

	entries, total := store.List(0, 10)
	assert.Equal(t, 3, total)
	require.Len(t, entries, 3)
	// Newest first.
	assert.Equal(t, "client-2", entries[0].ClientID)
	assert.Equal(t, "client-1", entries[1].ClientID)
	assert.Equal(t, "client-0", entries[2].ClientID)
}

func TestStore_Pagination(t *testing.T) {
	t.Parallel()

	store := NewStore()

	for i := 0; i < 5; i++ {
		store.Append(NewEntry(
			fmt.Sprintf("client-%d", i),
			"tools/call",
			DecisionAllow,
			fmt.Sprintf("req-%d", i),
			nil,
		))
	}

	// Page 1: offset=0, limit=2.
	entries, total := store.List(0, 2)
	assert.Equal(t, 5, total)
	require.Len(t, entries, 2)
	assert.Equal(t, "client-4", entries[0].ClientID)
	assert.Equal(t, "client-3", entries[1].ClientID)

	// Page 2: offset=2, limit=2.
	entries, total = store.List(2, 2)
	assert.Equal(t, 5, total)
	require.Len(t, entries, 2)
	assert.Equal(t, "client-2", entries[0].ClientID)
	assert.Equal(t, "client-1", entries[1].ClientID)

	// Page 3: offset=4, limit=2 (only 1 remaining).
	entries, total = store.List(4, 2)
	assert.Equal(t, 5, total)
	require.Len(t, entries, 1)
	assert.Equal(t, "client-0", entries[0].ClientID)
}

func TestStore_OffsetBeyondTotal(t *testing.T) {
	t.Parallel()

	store := NewStore()
	store.Append(NewEntry("c1", "tools/call", DecisionAllow, "r1", nil))

	entries, total := store.List(10, 5)
	assert.Equal(t, 1, total)
	assert.Empty(t, entries)
}

func TestStore_DefaultLimit(t *testing.T) {
	t.Parallel()

	store := NewStore()
	for i := 0; i < 30; i++ {
		store.Append(NewEntry("c", "tools/call", DecisionAllow, "r", nil))
	}

	// limit=0 should default to 20.
	entries, total := store.List(0, 0)
	assert.Equal(t, 30, total)
	assert.Len(t, entries, 20)
}

func TestStore_MaxLimit(t *testing.T) {
	t.Parallel()

	store := NewStore()
	for i := 0; i < 150; i++ {
		store.Append(NewEntry("c", "tools/call", DecisionAllow, "r", nil))
	}

	// limit=200 should be capped to 100.
	entries, total := store.List(0, 200)
	assert.Equal(t, 150, total)
	assert.Len(t, entries, 100)
}

func TestStore_RingBufferOverflow(t *testing.T) {
	t.Parallel()

	store := NewStore()

	// Fill beyond max capacity.
	for i := 0; i < maxStoreSize+50; i++ {
		store.Append(NewEntry(
			fmt.Sprintf("client-%d", i),
			"tools/call",
			DecisionAllow,
			fmt.Sprintf("req-%d", i),
			nil,
		))
	}

	assert.Equal(t, maxStoreSize, store.Count())

	entries, total := store.List(0, 1)
	assert.Equal(t, maxStoreSize, total)
	require.Len(t, entries, 1)
	// Most recent entry should be the last one appended.
	assert.Equal(t, fmt.Sprintf("client-%d", maxStoreSize+49), entries[0].ClientID)

	// Oldest surviving entry should be client-50 (first 50 were overwritten).
	entries, _ = store.List(maxStoreSize-1, 1)
	require.Len(t, entries, 1)
	assert.Equal(t, "client-50", entries[0].ClientID)
}

func TestStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewStore()

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			store.Append(NewEntry(
				fmt.Sprintf("client-%d", n),
				"tools/call",
				DecisionAllow,
				fmt.Sprintf("req-%d", n),
				nil,
			))
		}(i)
	}
	wg.Wait()

	assert.Equal(t, 100, store.Count())

	// Concurrent reads during writes.
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			store.Append(NewEntry("writer", "tools/call", DecisionAllow, "r", nil))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			_, _ = store.List(0, 10)
		}
	}()
	wg.Wait()
}

func TestStore_Count(t *testing.T) {
	t.Parallel()

	store := NewStore()
	assert.Equal(t, 0, store.Count())

	store.Append(NewEntry("c1", "tools/call", DecisionAllow, "r1", nil))
	assert.Equal(t, 1, store.Count())

	store.Append(NewEntry("c2", "tools/call", DecisionDeny, "r2", nil))
	assert.Equal(t, 2, store.Count())
}
