package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"

	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
)

// CacheRepo реализует repository.CacheRepository
type CacheRepo struct {
	client redis.UniversalClient
	ctx    context.Context
}

// NewCacheRepo создает новый репозиторий кеша и возвращает ошибку при проблемах
func NewCacheRepo(client redis.UniversalClient) (*CacheRepo, error) {
	if client == nil {
		// log.Fatal("Redis client cannot be nil for CacheRepo")
		return nil, fmt.Errorf("Redis client cannot be nil for CacheRepo")
	}
	return &CacheRepo{
		client: client,
		ctx:    context.Background(),
	}, nil
}

// Set сохраняет значение в кеше
func (r *CacheRepo) Set(key string, value interface{}, expiration time.Duration) error {
	return r.client.Set(r.ctx, key, value, expiration).Err()
}

// Get получает значение из кеша
func (r *CacheRepo) Get(key string) (string, error) {
	val, err := r.client.Get(r.ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", apperrors.ErrNotFound
		}
		return "", err
	}
	return val, nil
}

// Delete удаляет значение из кеша
func (r *CacheRepo) Delete(key string) error {
	return r.client.Del(r.ctx, key).Err()
}

// Increment увеличивает значение на 1
func (r *CacheRepo) Increment(key string) (int64, error) {
	return r.client.Incr(r.ctx, key).Result()
}

// SetJSON сохраняет структуру JSON в кеше
func (r *CacheRepo) SetJSON(key string, value interface{}, expiration time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return r.client.Set(r.ctx, key, data, expiration).Err()
}

// GetJSON получает структуру JSON из кеша
func (r *CacheRepo) GetJSON(key string, dest interface{}) error {
	data, err := r.client.Get(r.ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return apperrors.ErrNotFound
		}
		return err
	}
	return json.Unmarshal(data, dest)
}

// Exists проверяет существование ключа
func (r *CacheRepo) Exists(key string) (bool, error) {
	result, err := r.client.Exists(r.ctx, key).Result()
	if err != nil {
		return false, err
	}
	return result > 0, nil
}

// ExpireAt устанавливает время истечения ключа
func (r *CacheRepo) ExpireAt(key string, expiration time.Time) error {
	return r.client.ExpireAt(r.ctx, key, expiration).Err()
}

// SetNX устанавливает значение ключа, только если ключ не существует.
// Возвращает true, если ключ был установлен, false - если ключ уже существовал.
func (r *CacheRepo) SetNX(key string, value interface{}, expiration time.Duration) (bool, error) {
	return r.client.SetNX(r.ctx, key, value, expiration).Result()
}
