package audit

import "sync"

// maxStoreSize is the maximum number of audit entries in the ring buffer.
const maxStoreSize = 10_000

// Store is an in-memory ring buffer that stores audit log entries.
// It is safe for concurrent access.
type Store struct {
	entries []*Entry
	mu      sync.RWMutex
	head    int
	count   int
}

// NewStore creates a new in-memory audit store with ring buffer semantics.
func NewStore() *Store {
	return &Store{
		entries: make([]*Entry, maxStoreSize),
	}
}

// Append adds an audit entry to the store.
// When the store is full, the oldest entry is overwritten.
func (s *Store) Append(entry *Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.entries[s.head] = entry
	s.head = (s.head + 1) % maxStoreSize
	if s.count < maxStoreSize {
		s.count++
	}
}

// List returns a page of audit entries ordered newest-first.
// offset is the zero-based starting position and limit is the maximum
// number of entries to return.
func (s *Store) List(offset, limit int) (entries []*Entry, total int) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total = s.count
	if offset >= total {
		return nil, total
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	result := make([]*Entry, 0, limit)
	for i := 0; i < limit; i++ {
		idx := offset + i
		if idx >= total {
			break
		}
		// Convert logical index (newest-first) to physical ring buffer index.
		physIdx := (s.head - 1 - idx + maxStoreSize) % maxStoreSize
		result = append(result, s.entries[physIdx])
	}
	return result, total
}

// Count returns the number of entries in the store.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}
