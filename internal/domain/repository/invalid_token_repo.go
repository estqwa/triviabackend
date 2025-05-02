package repository

import (
	"context"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// InvalidTokenRepository определяет методы для работы с инвалидированными токенами
type InvalidTokenRepository interface {
	// AddInvalidToken добавляет запись об инвалидированном токене
	AddInvalidToken(ctx context.Context, userID uint, invalidationTime time.Time) error

	// RemoveInvalidToken удаляет запись об инвалидированном токене
	RemoveInvalidToken(ctx context.Context, userID uint) error

	// IsTokenInvalid проверяет, инвалидирован ли токен пользователя
	IsTokenInvalid(ctx context.Context, userID uint, tokenIssuedAt time.Time) (bool, error)

	// GetAllInvalidTokens возвращает все записи об инвалидированных токенах
	GetAllInvalidTokens(ctx context.Context) ([]entity.InvalidToken, error)

	// CleanupOldInvalidTokens удаляет устаревшие записи об инвалидированных токенах
	CleanupOldInvalidTokens(ctx context.Context, cutoffTime time.Time) error
}
