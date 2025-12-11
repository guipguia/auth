package service

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/guipguia/auth/internal/config"
)

// redisCache is a distributed cache implementation using Redis/Valkey
// Use this for stateless deployments with multiple replicas
type redisCache struct {
	client *redis.Client
	ttl    time.Duration
	ctx    context.Context
}

// NewRedisCache creates a new Redis/Valkey-backed cache service
// This ensures cache consistency across multiple service instances
func NewRedisCache(cfg *config.RedisCacheConfig) (CacheService, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.DB,
	})

	ctx := context.Background()

	// Test connection
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis/valkey: %w", err)
	}

	return &redisCache{
		client: client,
		ttl:    time.Duration(cfg.TTLSeconds) * time.Second,
		ctx:    ctx,
	}, nil
}

func (c *redisCache) Get(key string) (interface{}, bool) {
	val, err := c.client.Get(c.ctx, key).Result()
	if err == redis.Nil {
		return nil, false
	}
	if err != nil {
		// Log error but don't fail - just cache miss
		return nil, false
	}

	// Deserialize the value
	var result interface{}
	if err := json.Unmarshal([]byte(val), &result); err != nil {
		return nil, false
	}

	return result, true
}

func (c *redisCache) Set(key string, value interface{}) {
	c.SetWithTTL(key, value, c.ttl)
}

func (c *redisCache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	// Serialize the value
	data, err := json.Marshal(value)
	if err != nil {
		// Log error but don't fail
		return
	}

	// Set with TTL
	c.client.Set(c.ctx, key, data, ttl)
}

func (c *redisCache) Delete(key string) {
	c.client.Del(c.ctx, key)
}

func (c *redisCache) Clear() {
	// Clear all keys with auth prefix
	iter := c.client.Scan(c.ctx, 0, "auth:*", 0).Iterator()
	for iter.Next(c.ctx) {
		c.client.Del(c.ctx, iter.Val())
	}
}

// Close closes the Redis connection
func (c *redisCache) Close() error {
	return c.client.Close()
}
