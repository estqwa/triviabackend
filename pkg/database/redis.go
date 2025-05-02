package database

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/yourusername/trivia-api/internal/config" // Импортируем конфиг
)

// NewUniversalRedisClient создает новый клиент Redis на основе унифицированной конфигурации.
// Поддерживает режимы single, sentinel, cluster.
func NewUniversalRedisClient(cfg config.RedisConfig) (redis.UniversalClient, error) {
	ctx := context.Background()
	var client redis.UniversalClient
	var options *redis.UniversalOptions

	// Определяем адреса
	addresses := cfg.Addrs
	if len(addresses) == 0 {
		if cfg.Addr != "" {
			addresses = []string{cfg.Addr}
		} else {
			return nil, fmt.Errorf("redis configuration error: Addrs or Addr must be provided")
		}
	}

	// Устанавливаем базовые опции
	options = &redis.UniversalOptions{
		Addrs:    addresses,
		Password: cfg.Password,
		DB:       cfg.DB,
	}

	// Настраиваем ретраи, если указаны
	if cfg.MaxRetries != 0 {
		options.MaxRetries = cfg.MaxRetries
	}
	if cfg.MinRetryBackoff != 0 {
		options.MinRetryBackoff = time.Duration(cfg.MinRetryBackoff) * time.Millisecond
	}
	if cfg.MaxRetryBackoff != 0 {
		options.MaxRetryBackoff = time.Duration(cfg.MaxRetryBackoff) * time.Millisecond
	}

	// Определяем режим работы
	redisMode := cfg.Mode
	if redisMode == "" {
		redisMode = "single" // По умолчанию
	}

	switch redisMode {
	case "sentinel":
		if cfg.MasterName == "" {
			return nil, fmt.Errorf("redis sentinel mode requires MasterName")
		}
		options.MasterName = cfg.MasterName
		// Для sentinel NewUniversalClient сам определит, что это sentinel по MasterName
	case "cluster":
		// Для cluster NewUniversalClient сам определит по количеству адресов
		// или можно явно указать, но обычно не требуется
	case "single":
		// NewUniversalClient по умолчанию работает как single, если адреса и MasterName не указывают на другое
	default:
		return nil, fmt.Errorf("unsupported redis mode: %s", redisMode)
	}

	// Создаем универсальный клиент
	client = redis.NewUniversalClient(options)

	// Проверка подключения
	_, err := client.Ping(ctx).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Redis (mode: %s, addrs: %v): %w", redisMode, addresses, err)
	}

	return client, nil
}
