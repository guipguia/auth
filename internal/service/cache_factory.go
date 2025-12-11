package service

import (
	"fmt"

	"github.com/guipguia/auth/internal/config"
)

// NewCacheService creates a cache service based on configuration
func NewCacheService(cfg *config.CacheConfig) (CacheService, error) {
	if !cfg.Enabled {
		return NewNoOpCache(), nil
	}

	switch cfg.Type {
	case "none", "":
		return NewNoOpCache(), nil
	case "memory":
		return NewMemoryCache(cfg.TTLSeconds, cfg.MaxSize, cfg.CleanupMinutes), nil
	case "redis":
		return NewRedisCache(&cfg.Redis)
	default:
		return nil, fmt.Errorf("unknown cache type: %s", cfg.Type)
	}
}
