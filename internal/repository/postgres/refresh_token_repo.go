package postgres

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	// "github.com/yourusername/trivia-api/internal/domain/repository" // Удаляем старый импорт
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors" // Используем новый пакет ошибок
	"gorm.io/gorm"
)

// RefreshTokenRepo реализует интерфейс RefreshTokenRepository с использованием PostgreSQL и GORM
type RefreshTokenRepo struct {
	// db *sql.DB // Убираем старое поле
	db *gorm.DB // Используем GORM DB
}

// NewRefreshTokenRepo создает новый экземпляр RefreshTokenRepo и возвращает ошибку при проблемах
func NewRefreshTokenRepo(gormDB *gorm.DB) (*RefreshTokenRepo, error) {
	// Проверяем, что переданный gormDB не nil
	if gormDB == nil {
		// log.Fatal("GORM DB instance is required for RefreshTokenRepo")
		return nil, fmt.Errorf("GORM DB instance is required for RefreshTokenRepo") // Возвращаем ошибку
	}
	return &RefreshTokenRepo{db: gormDB}, nil // Возвращаем репо и nil ошибку
}

// CreateToken сохраняет новый refresh токен в базе данных и возвращает его ID
func (r *RefreshTokenRepo) CreateToken(token *entity.RefreshToken) (uint, error) {
	// Используем GORM для создания записи
	result := r.db.Create(token)
	if result.Error != nil {
		return 0, fmt.Errorf("ошибка создания refresh токена: %w", result.Error)
	}
	// GORM автоматически заполняет поле ID в переданной структуре token
	if token.ID == 0 {
		// Дополнительная проверка, хотя GORM обычно гарантирует заполнение ID
		return 0, fmt.Errorf("не удалось получить ID после создания refresh токена")
	}
	// Возвращаем ID созданного токена
	return token.ID, nil
}

// GetTokenByValue находит refresh токен по его значению
func (r *RefreshTokenRepo) GetTokenByValue(tokenValue string) (*entity.RefreshToken, error) {
	var token entity.RefreshToken
	// Ищем токен по значению
	result := r.db.Where("token = ?", tokenValue).First(&token)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound // Используем новую ошибку
		}
		return nil, fmt.Errorf("ошибка получения refresh токена по значению: %w", result.Error)
	}

	// Проверяем срок действия и флаг отзыва
	if token.IsExpired || token.ExpiresAt.Before(time.Now()) {
		return nil, apperrors.ErrExpiredToken
	}

	return &token, nil
}

// GetTokenByID находит refresh токен по его ID
func (r *RefreshTokenRepo) GetTokenByID(tokenID uint) (*entity.RefreshToken, error) {
	var token entity.RefreshToken
	result := r.db.First(&token, tokenID) // GORM ищет по первичному ключу
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound // Используем новую ошибку
		}
		return nil, fmt.Errorf("ошибка получения refresh токена по ID: %w", result.Error)
	}
	return &token, nil
}

// GetActiveTokensForUser возвращает все активные (не истекшие) refresh-токены для пользователя
func (r *RefreshTokenRepo) GetActiveTokensForUser(userID uint) ([]*entity.RefreshToken, error) {
	var tokens []*entity.RefreshToken
	result := r.db.Where("user_id = ? AND is_expired = false AND expires_at > ?", userID, time.Now()).
		Order("created_at DESC"). // Сортируем по дате создания (самые новые первыми)
		Find(&tokens)

	if result.Error != nil {
		// GORM Find не возвращает ErrRecordNotFound, если ничего не найдено, поэтому проверяем только другие ошибки
		return nil, fmt.Errorf("ошибка получения активных токенов пользователя: %w", result.Error)
	}
	return tokens, nil
}

// CheckToken проверяет существование и срок действия refresh-токена
func (r *RefreshTokenRepo) CheckToken(tokenValue string) (bool, error) {
	var count int64
	result := r.db.Model(&entity.RefreshToken{}).
		Where("token = ? AND is_expired = false AND expires_at > ?", tokenValue, time.Now()).
		Count(&count)

	if result.Error != nil {
		return false, fmt.Errorf("ошибка проверки refresh токена: %w", result.Error)
	}
	return count > 0, nil
}

// MarkTokenAsExpired помечает токен как истекший (устанавливает expires_at в прошлое)
func (r *RefreshTokenRepo) MarkTokenAsExpired(tokenValue string, reason string) error {
	now := time.Now()
	// Используем Updates для обновления только определенных полей
	result := r.db.Model(&entity.RefreshToken{}).
		Where("token = ?", tokenValue).
		Updates(map[string]interface{}{ // Используем map для обновления
			"is_expired": true,
			"revoked_at": now,
			"reason":     reason,
		})

	if result.Error != nil {
		return fmt.Errorf("ошибка маркировки refresh токена как истекшего: %w", result.Error)
	}

	// Проверяем, была ли обновлена хотя бы одна строка
	if result.RowsAffected == 0 {
		return apperrors.ErrNotFound // Если ничего не обновлено, токен не найден
	}

	return nil
}

// MarkAllAsExpiredForUser помечает все токены пользователя как истекшие
func (r *RefreshTokenRepo) MarkAllAsExpiredForUser(userID uint, reason string) error {
	now := time.Now()
	result := r.db.Model(&entity.RefreshToken{}).
		Where("user_id = ? AND is_expired = false AND expires_at > ?", userID, time.Now()). // Обновляем только активные
		Updates(map[string]interface{}{                                                     // Используем map для обновления
			"is_expired": true,
			"revoked_at": now,
			"reason":     reason,
		})

	if result.Error != nil {
		return fmt.Errorf("ошибка маркировки всех токенов пользователя %d как истекших: %w", userID, result.Error)
	}
	// Не возвращаем ErrNotFound, если у пользователя не было активных токенов
	return nil
}

// CleanupExpiredTokens удаляет истекшие токены из базы данных
func (r *RefreshTokenRepo) CleanupExpiredTokens() (int64, error) {
	now := time.Now()
	result := r.db.Model(&entity.RefreshToken{}).
		Where("is_expired = false AND expires_at <= ?", now).
		Updates(map[string]interface{}{
			"is_expired": true,
			"revoked_at": now,
			"reason":     "expired",
		})
	if result.Error != nil {
		return 0, fmt.Errorf("ошибка очистки истекших refresh токенов: %w", result.Error)
	}
	// Возвращаем количество удаленных строк
	return result.RowsAffected, nil
}

// CountTokensForUser возвращает количество активных токенов для пользователя
func (r *RefreshTokenRepo) CountTokensForUser(userID uint) (int, error) {
	var count int64
	result := r.db.Model(&entity.RefreshToken{}).
		Where("user_id = ? AND is_expired = false AND expires_at > ?", userID, time.Now()).
		Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("ошибка подсчета токенов пользователя %d: %w", userID, result.Error)
	}
	return int(count), nil
}

// MarkOldestAsExpiredForUser помечает самые старые активные токены пользователя как истекшие,
// оставляя указанное количество (`keepCount`).
func (r *RefreshTokenRepo) MarkOldestAsExpiredForUser(userID uint, keepCount int, reason string) error {
	// --- Реализация через два шага GORM --- (Предпочтительнее для чистоты GORM)

	// 1. Найти ID токенов, которые нужно пометить как истекшие.
	// Сначала получаем все активные токены, сортируем по дате создания (старые первыми)
	var tokensToMarkIDs []uint
	result := r.db.Model(&entity.RefreshToken{}).
		Select("id"). // Выбираем только ID
		Where("user_id = ? AND is_expired = false AND expires_at > ?", userID, time.Now()).
		Order("created_at ASC"). // Сортируем старые первыми
		Offset(keepCount).       // Пропускаем `keepCount` самых новых (т.к. сортировка ASC)
		Find(&tokensToMarkIDs)   // Находим ID остальных (самых старых)

	if result.Error != nil {
		return fmt.Errorf("ошибка получения ID старых токенов пользователя %d: %w", userID, result.Error)
	}

	// Если нет токенов для пометки, выходим
	if len(tokensToMarkIDs) == 0 {
		return nil
	}

	// 2. Пометить найденные токены как истекшие
	updateResult := r.db.Model(&entity.RefreshToken{}).
		Where("id IN ?", tokensToMarkIDs).
		Updates(map[string]interface{}{ // Используем map для обновления
			"is_expired": true,
			"revoked_at": time.Now(),
			"reason":     reason,
		})

	if updateResult.Error != nil {
		return fmt.Errorf("ошибка маркировки старых токенов пользователя %d как истекших: %w", userID, updateResult.Error)
	}

	log.Printf("[RefreshTokenRepo] Помечено %d старых токенов как истекшие для пользователя %d", len(tokensToMarkIDs), userID)
	return nil

	/* --- Старая реализация через database/sql --- (Оставлена для примера, если GORM не справится)
	query := `
		UPDATE refresh_tokens
		SET expires_at = NOW() - INTERVAL '1 hour'
		WHERE id IN (
			SELECT id
			FROM refresh_tokens
			WHERE user_id = $1 AND expires_at > NOW()
			ORDER BY created_at ASC
			OFFSET $2
		)
	`
	_, err := r.db.Exec(query, userID, keepCount)
	if err != nil {
		return fmt.Errorf("ошибка маркировки старых токенов пользователя %d: %w", userID, err)
	}
	return nil
	*/
}

// DeleteToken удаляет refresh токен по его значению
func (r *RefreshTokenRepo) DeleteToken(tokenValue string) error {
	// Используем GORM для удаления записи по значению токена
	result := r.db.Where("token = ?", tokenValue).Delete(&entity.RefreshToken{})
	if result.Error != nil {
		return fmt.Errorf("ошибка удаления refresh токена %s: %w", tokenValue, result.Error)
	}

	// Проверяем, была ли удалена хотя бы одна строка
	if result.RowsAffected == 0 {
		// Можно вернуть ErrNotFound, если нужно явно сообщать, что токен не найден
		// return repository.ErrNotFound
		log.Printf("[RefreshTokenRepo] Токен %s не найден для удаления", tokenValue)
		// Возвращаем nil, так как операция удаления с точки зрения запроса прошла успешно
		// (цель - чтобы токена не было, и его нет)
		return nil
	}

	log.Printf("[RefreshTokenRepo] Токен %s успешно удален", tokenValue)
	return nil
}

// MarkTokenAsExpiredByID помечает токен как истекший по его ID
func (r *RefreshTokenRepo) MarkTokenAsExpiredByID(id uint, reason string) error {
	now := time.Now()
	// Используем Updates для обновления только определенных полей по ID
	result := r.db.Model(&entity.RefreshToken{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{ // Используем map для обновления
			"is_expired": true,
			"revoked_at": now,
			"reason":     reason,
		})

	if result.Error != nil {
		return fmt.Errorf("ошибка маркировки refresh токена ID=%d как истекшего: %w", id, result.Error)
	}

	// Проверяем, была ли обновлена хотя бы одна строка
	if result.RowsAffected == 0 {
		// В отличие от MarkTokenAsExpired (по значению), здесь, если ID не найден,
		// это обычно означает ошибку в логике вызова (передан неверный ID),
		// поэтому возвращаем ErrNotFound.
		return apperrors.ErrNotFound // Используем новую ошибку
	}

	log.Printf("[RefreshTokenRepo] Токен ID=%d помечен как истекший", id)
	return nil
}
