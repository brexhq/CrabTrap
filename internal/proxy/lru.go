package proxy

import (
	"container/list"
	"sync"
)

// lruEntry stores a key-value pair for the LRU cache list element.
type lruEntry[V any] struct {
	key string
	val V
}

// lruCache is a thread-safe generic LRU cache implemented using
// container/list and a map with no external dependencies.
type lruCache[V any] struct {
	maxSize int
	items   map[string]*list.Element
	order   *list.List
	mu      sync.Mutex
}

// newLRUCache creates a new LRU cache with the given maximum size.
func newLRUCache[V any](maxSize int) *lruCache[V] {
	return &lruCache[V]{
		maxSize: maxSize,
		items:   make(map[string]*list.Element),
		order:   list.New(),
	}
}

// evictOldest removes the least recently used entry when full and reports it
// so callers can preserve state that must survive eviction. Caller holds mu.
func (c *lruCache[V]) evictOldest() (string, V, bool) {
	var zero V
	if c.order.Len() < c.maxSize {
		return "", zero, false
	}
	tail := c.order.Back()
	if tail == nil {
		return "", zero, false
	}
	c.order.Remove(tail)
	e := tail.Value.(*lruEntry[V])
	delete(c.items, e.key)
	return e.key, e.val, true
}

// Get retrieves a value from the cache by key. If found, the entry
// is promoted to the front of the LRU list (most recently used).
func (c *lruCache[V]) Get(key string) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*lruEntry[V]).val, true
	}
	var zero V
	return zero, false
}

// Put adds a value to the cache. If the key already exists, the entry is
// updated and promoted. If the cache is at capacity, the least recently used
// entry is evicted.
func (c *lruCache[V]) Put(key string, val V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		elem.Value.(*lruEntry[V]).val = val
		return
	}

	c.evictOldest()
	c.items[key] = c.order.PushFront(&lruEntry[V]{key: key, val: val})
}

// GetOrCreate retrieves the value for key, or atomically creates and inserts
// one using the provided function if the key is absent. This avoids the TOCTOU
// race of separate Get + Put calls where two goroutines could each create a
// value for the same key.
func (c *lruCache[V]) GetOrCreate(key string, create func() V) V {
	return c.GetOrCreateWithEvict(key, create, nil)
}

// GetOrCreateWithEvict is GetOrCreate plus a hook for the displaced entry,
// allowing callers to migrate its state instead of dropping it.
func (c *lruCache[V]) GetOrCreateWithEvict(key string, create func() V, onEvict func(string, V)) V {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.order.MoveToFront(elem)
		return elem.Value.(*lruEntry[V]).val
	}

	val := create()
	if k, old, ok := c.evictOldest(); ok && onEvict != nil {
		onEvict(k, old)
	}

	c.items[key] = c.order.PushFront(&lruEntry[V]{key: key, val: val})
	return val
}

// Len returns the number of entries in the cache.
func (c *lruCache[V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
