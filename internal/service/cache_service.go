package service

import (
	"sync"
	"time"
)

// CacheService defines the interface for caching operations
type CacheService interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{})
	SetWithTTL(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
	Close() error
}

// cacheEntry represents a cached item with expiration
type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// memoryCache is an in-memory cache implementation
// Use this for single-instance deployments or development only
type memoryCache struct {
	data    map[string]cacheEntry
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
	stopCh  chan struct{}
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache(ttlSeconds, maxSize, cleanupMinutes int) CacheService {
	cache := &memoryCache{
		data:    make(map[string]cacheEntry),
		ttl:     time.Duration(ttlSeconds) * time.Second,
		maxSize: maxSize,
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup(time.Duration(cleanupMinutes) * time.Minute)

	return cache
}

func (c *memoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.value, true
}

func (c *memoryCache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.ttl)
}

func (c *memoryCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if len(c.data) >= c.maxSize {
		c.evictExpired()
	}

	c.data[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
}

func (c *memoryCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, key)
}

func (c *memoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]cacheEntry)
}

func (c *memoryCache) Close() error {
	close(c.stopCh)
	return nil
}

// evictExpired removes expired entries (must be called with lock held)
func (c *memoryCache) evictExpired() {
	now := time.Now()
	for key, entry := range c.data {
		if now.After(entry.expiresAt) {
			delete(c.data, key)
		}
	}
}

// cleanup periodically removes expired entries
func (c *memoryCache) cleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			c.evictExpired()
			c.mu.Unlock()
		case <-c.stopCh:
			return
		}
	}
}

// noOpCache is a no-operation cache for stateless deployments
type noOpCache struct{}

// NewNoOpCache creates a cache that does nothing (for stateless deployments)
func NewNoOpCache() CacheService {
	return &noOpCache{}
}

func (c *noOpCache) Get(key string) (interface{}, bool) {
	return nil, false
}

func (c *noOpCache) Set(key string, value interface{}) {}

func (c *noOpCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {}

func (c *noOpCache) Delete(key string) {}

func (c *noOpCache) Clear() {}

func (c *noOpCache) Close() error {
	return nil
}
