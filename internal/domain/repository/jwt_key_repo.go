package repository

import (
	"context"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// JWTKeyRepository определяет интерфейс для управления ключами подписи JWT.
type JWTKeyRepository interface {
	// CreateKey создает новый ключ подписи JWT в хранилище.
	// Секрет в entity.JWTKey.Key должен быть уже зашифрован перед вызовом этого метода.
	CreateKey(ctx context.Context, key *entity.JWTKey) error

	// GetKeyByID извлекает ключ по его ID.
	// Возвращает ключ с зашифрованным секретом.
	GetKeyByID(ctx context.Context, id string) (*entity.JWTKey, error)

	// GetActiveKey извлекает текущий активный ключ для подписи токенов.
	// Возвращает ключ с зашифрованным секретом.
	GetActiveKey(ctx context.Context) (*entity.JWTKey, error)

	// GetValidationKeys извлекает все ключи, которые могут быть использованы для проверки подписи токенов.
	// Сюда входит активный ключ и недавно ротированные неактивные ключи, которые еще не истекли для валидации.
	// Возвращает ключи с зашифрованными секретами.
	GetValidationKeys(ctx context.Context) ([]*entity.JWTKey, error)

	// DeactivateKey помечает ключ как неактивный (ротированный).
	// Устанавливает IsActive = false и RotatedAt = rotatedAtTime.
	DeactivateKey(ctx context.Context, id string, rotatedAtTime time.Time) error

	// ListAllKeys извлекает все ключи из хранилища (например, для инициализации).
	// Возвращает ключи с зашифрованными секретами.
	ListAllKeys(ctx context.Context) ([]*entity.JWTKey, error)

	// PruneExpiredKeys удаляет из хранилища ключи, которые истекли и больше не нужны для валидации.
	// (например, ExpiresAt + grace_period < now)
	PruneExpiredKeys(ctx context.Context, gracePeriod time.Duration) (int64, error)
}
