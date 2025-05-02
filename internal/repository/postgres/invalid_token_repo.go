package postgres

import (
	"context"
	"errors"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// InvalidTokenRepo реализует repository.InvalidTokenRepository
type InvalidTokenRepo struct {
	db *gorm.DB
}

// NewInvalidTokenRepo создает новый репозиторий инвалидированных токенов
func NewInvalidTokenRepo(db *gorm.DB) *InvalidTokenRepo {
	return &InvalidTokenRepo{db: db}
}

// AddInvalidToken добавляет запись об инвалидированном токене
func (r *InvalidTokenRepo) AddInvalidToken(ctx context.Context, userID uint, invalidationTime time.Time) error {
	// Используем Upsert (INSERT ... ON CONFLICT DO UPDATE) для обновления
	// существующей записи, если пользователь уже в черном списке
	err := r.db.WithContext(ctx).Exec(`
		INSERT INTO invalid_tokens (user_id, invalidation_time)
		VALUES (?, ?)
		ON CONFLICT (user_id)
		DO UPDATE SET invalidation_time = ?
	`, userID, invalidationTime, invalidationTime).Error

	if err != nil {
		log.Printf("Ошибка при добавлении записи в invalid_tokens: %v", err)
		return err
	}

	log.Printf("Добавлена запись в invalid_tokens для пользователя ID=%d", userID)
	return nil
}

// RemoveInvalidToken удаляет запись об инвалидированном токене
func (r *InvalidTokenRepo) RemoveInvalidToken(ctx context.Context, userID uint) error {
	result := r.db.WithContext(ctx).Delete(&entity.InvalidToken{}, userID)
	if result.Error != nil {
		log.Printf("Ошибка при удалении записи из invalid_tokens: %v", result.Error)
		return result.Error
	}

	if result.RowsAffected > 0 {
		log.Printf("Удалена запись из invalid_tokens для пользователя ID=%d", userID)
	} else {
		log.Printf("Запись в invalid_tokens для пользователя ID=%d не найдена", userID)
	}

	return nil
}

// IsTokenInvalid проверяет, инвалидирован ли токен пользователя
func (r *InvalidTokenRepo) IsTokenInvalid(ctx context.Context, userID uint, tokenIssuedAt time.Time) (bool, error) {
	var invalidToken entity.InvalidToken

	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&invalidToken).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Запись не найдена - токен валиден
			return false, nil
		}
		log.Printf("Ошибка при проверке токена в invalid_tokens: %v", err)
		return false, err
	}

	// Если токен был выдан до инвалидации, он недействителен
	isInvalid := tokenIssuedAt.Before(invalidToken.InvalidationTime)

	if isInvalid {
		log.Printf("Токен недействителен для пользователя ID=%d: выдан в %v, инвалидирован в %v",
			userID, tokenIssuedAt, invalidToken.InvalidationTime)
	}

	return isInvalid, nil
}

// GetAllInvalidTokens возвращает все записи об инвалидированных токенах
func (r *InvalidTokenRepo) GetAllInvalidTokens(ctx context.Context) ([]entity.InvalidToken, error) {
	var tokens []entity.InvalidToken
	err := r.db.WithContext(ctx).Find(&tokens).Error
	if err != nil {
		log.Printf("Ошибка при получении списка инвалидированных токенов: %v", err)
		return nil, err
	}

	log.Printf("Получено %d записей из invalid_tokens", len(tokens))
	return tokens, nil
}

// CleanupOldInvalidTokens удаляет устаревшие записи об инвалидированных токенах
func (r *InvalidTokenRepo) CleanupOldInvalidTokens(ctx context.Context, cutoffTime time.Time) error {
	result := r.db.WithContext(ctx).Where("invalidation_time < ?", cutoffTime).Delete(&entity.InvalidToken{})
	if result.Error != nil {
		log.Printf("Ошибка при очистке устаревших записей в invalid_tokens: %v", result.Error)
		return result.Error
	}

	log.Printf("Удалено %d устаревших записей из invalid_tokens", result.RowsAffected)
	return nil
}
