package repository

import (
	"time"
)

// CacheRepository определяет методы для работы с кешем
type CacheRepository interface {
	Set(key string, value interface{}, expiration time.Duration) error
	Get(key string) (string, error)
	Delete(key string) error
	Increment(key string) (int64, error)
	SetJSON(key string, value interface{}, expiration time.Duration) error
	GetJSON(key string, dest interface{}) error
	Exists(key string) (bool, error)
	ExpireAt(key string, expiration time.Time) error
	SetNX(key string, value interface{}, expiration time.Duration) (bool, error)
}
