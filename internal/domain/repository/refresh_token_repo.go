package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// Ошибки репозитория
var (
// ErrNotFound возвращается, когда запись не найдена - ПЕРЕНЕСЕНО В internal/pkg/errors
// ErrNotFound = errors.New("запись не найдена")

// ErrExpiredToken возвращается, когда токен помечен как истекший - ПЕРЕНЕСЕНО В internal/pkg/errors
// ErrExpiredToken = errors.New("token is expired")
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

	// MarkTokenAsExpired помечает токен как истекший с указанием причины
	MarkTokenAsExpired(token string, reason string) error

	// MarkTokenAsExpiredByID помечает токен как истекший по его ID с указанием причины
	MarkTokenAsExpiredByID(id uint, reason string) error

	// DeleteToken физически удаляет токен по его значению (используется в критических ситуациях)
	DeleteToken(token string) error

	// MarkAllAsExpiredForUser помечает все токены пользователя как истекшие с указанием причины
	MarkAllAsExpiredForUser(userID uint, reason string) error

	// CleanupExpiredTokens помечает все просроченные токены как истекшие
	CleanupExpiredTokens() (int64, error)

	// GetActiveTokensForUser получает все активные токены пользователя
	GetActiveTokensForUser(userID uint) ([]*entity.RefreshToken, error)

	// CountTokensForUser подсчитывает количество активных токенов пользователя
	CountTokensForUser(userID uint) (int, error)

	// MarkOldestAsExpiredForUser помечает самые старые токены пользователя как истекшие, оставляя только limit токенов
	MarkOldestAsExpiredForUser(userID uint, limit int, reason string) error
}
