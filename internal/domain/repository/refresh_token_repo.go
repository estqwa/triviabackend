package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// RefreshTokenRepository интерфейс для работы с refresh-токенами
type RefreshTokenRepository interface {
	// CreateToken создает новый refresh-токен и возвращает его ID
	CreateToken(refreshToken *entity.RefreshToken) (uint, error)

	// GetTokenByValue находит refresh-токен по его значению
	GetTokenByValue(token string) (*entity.RefreshToken, error)

	// GetTokenByID находит refresh-токен по его ID
	GetTokenByID(id uint) (*entity.RefreshToken, error)

	// CheckToken проверяет действительность refresh-токена
	CheckToken(token string) (bool, error)

	// MarkTokenAsExpired помечает токен как истекший
	MarkTokenAsExpired(token string) error

	// MarkTokenAsExpiredByID помечает токен как истекший по его ID
	MarkTokenAsExpiredByID(id uint) error

	// DeleteToken физически удаляет токен по его значению (используется в критических ситуациях)
	DeleteToken(token string) error

	// MarkAllAsExpiredForUser помечает все токены пользователя как истекшие
	MarkAllAsExpiredForUser(userID uint) error

	// CleanupExpiredTokens удаляет все просроченные и истекшие токены
	CleanupExpiredTokens() (int64, error)

	// GetActiveTokensForUser получает все активные токены пользователя
	GetActiveTokensForUser(userID uint) ([]*entity.RefreshToken, error)

	// CountTokensForUser подсчитывает количество активных токенов пользователя
	CountTokensForUser(userID uint) (int, error)

	// MarkOldestAsExpiredForUser помечает самые старые токены пользователя как истекшие, оставляя только limit токенов
	MarkOldestAsExpiredForUser(userID uint, limit int) error
}
