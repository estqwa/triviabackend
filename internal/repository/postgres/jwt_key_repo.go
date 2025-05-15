// trivia-api/internal/repository/postgres/jwt_key_repo.go

package postgres

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"time"

	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors" // Используем ваш пакет ошибок
)

// PostgresJWTKeyRepository реализует JWTKeyRepository для PostgreSQL.
type PostgresJWTKeyRepository struct {
	db            *gorm.DB
	encryptionKey []byte // Ключ для шифрования/дешифрования JWT ключей в БД
}

// NewPostgresJWTKeyRepository создает новый экземпляр PostgresJWTKeyRepository.
// encryptionKeyHex должен быть строкой HEX представления ключа шифрования (32 байта для AES-256 -> 64 hex символа).
func NewPostgresJWTKeyRepository(db *gorm.DB, encryptionKeyHex string) (*PostgresJWTKeyRepository, error) {
	if db == nil {
		return nil, errors.New("gorm DB instance is required")
	}
	if encryptionKeyHex == "" {
		return nil, errors.New("encryption key is required for JWTKeyRepository")
	}

	keyBytes, err := hex.DecodeString(encryptionKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encryption key from hex: %w", err)
	}

	// Проверяем длину ключа (16 для AES-128, 24 для AES-192, 32 для AES-256)
	if len(keyBytes) != 32 { // Рекомендуем AES-256
		return nil, fmt.Errorf("invalid encryption key length: must be 32 bytes (for AES-256), got %d bytes", len(keyBytes))
	}

	return &PostgresJWTKeyRepository{
		db:            db,
		encryptionKey: keyBytes,
	}, nil
}

// --- Реализация методов интерфейса JWTKeyRepository ---

// CreateKey создает новый ключ подписи JWT в хранилище.
func (r *PostgresJWTKeyRepository) CreateKey(ctx context.Context, key *entity.JWTKey) error {
	// Шифруем секрет ключа перед сохранением
	encryptedSecret, err := r.encryptKey(key.Key)
	if err != nil {
		return fmt.Errorf("failed to encrypt JWT key secret: %w", err)
	}
	keyToSave := *key // Копируем, чтобы не изменять оригинальный объект
	keyToSave.Key = encryptedSecret

	return r.db.WithContext(ctx).Create(&keyToSave).Error
}

// GetKeyByID извлекает ключ по его ID.
func (r *PostgresJWTKeyRepository) GetKeyByID(ctx context.Context, id string) (*entity.JWTKey, error) {
	var encryptedKey entity.JWTKey
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&encryptedKey).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}

	decryptedSecret, err := r.decryptKey(encryptedKey.Key)
	if err != nil {
		// Критическая ошибка, если не можем расшифровать ключ из БД
		log.Printf("CRITICAL: Failed to decrypt JWT key ID %s from DB: %v", encryptedKey.ID, err)
		return nil, fmt.Errorf("failed to decrypt JWT key secret for ID %s: %w", encryptedKey.ID, err)
	}
	encryptedKey.Key = decryptedSecret
	return &encryptedKey, nil
}

// GetActiveKey извлекает текущий активный ключ для подписи токенов.
func (r *PostgresJWTKeyRepository) GetActiveKey(ctx context.Context) (*entity.JWTKey, error) {
	var encryptedKey entity.JWTKey
	// Ищем ключ, который активен и еще не истек (ExpiresAt > now)
	// И сортируем по CreatedAt DESC, чтобы взять самый новый активный, если их несколько (хотя должен быть один)
	err := r.db.WithContext(ctx).
		Where("is_active = ? AND expires_at > ?", true, time.Now()).
		Order("created_at DESC").
		First(&encryptedKey).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound // Нет активных ключей
		}
		return nil, fmt.Errorf("failed to get active JWT key: %w", err)
	}

	decryptedSecret, err := r.decryptKey(encryptedKey.Key)
	if err != nil {
		log.Printf("CRITICAL: Failed to decrypt active JWT key ID %s from DB: %v", encryptedKey.ID, err)
		return nil, fmt.Errorf("failed to decrypt active JWT key secret for ID %s: %w", encryptedKey.ID, err)
	}
	encryptedKey.Key = decryptedSecret
	return &encryptedKey, nil
}

// GetValidationKeys извлекает все ключи, которые могут быть использованы для проверки подписи.
func (r *PostgresJWTKeyRepository) GetValidationKeys(ctx context.Context) ([]*entity.JWTKey, error) {
	var encryptedKeys []*entity.JWTKey
	// Выбираем активные ключи ИЛИ неактивные, но у которых RotatedAt не слишком давно
	// (например, в течение последних N дней, чтобы старые токены еще могли быть проверены)
	// И ExpiresAt еще не наступило.
	validationWindow := time.Now().Add(-7 * 24 * time.Hour) // Пример: 7 дней для проверки старых токенов

	err := r.db.WithContext(ctx).
		Where("(is_active = ? AND expires_at > ?) OR (is_active = ? AND rotated_at > ? AND expires_at > ?)",
			true, time.Now(), // Активные и не истекшие
			false, validationWindow, time.Now(), // Неактивные, но недавно ротированные и не истекшие
		).
		Order("created_at DESC").
		Find(&encryptedKeys).Error

	if err != nil {
		return nil, fmt.Errorf("failed to get JWT validation keys: %w", err)
	}

	if len(encryptedKeys) == 0 {
		return []*entity.JWTKey{}, nil // Нет ключей для валидации (например, при первом запуске)
	}

	decryptedKeys := make([]*entity.JWTKey, 0, len(encryptedKeys))
	for _, ek := range encryptedKeys {
		decryptedSecret, decErr := r.decryptKey(ek.Key)
		if decErr != nil {
			log.Printf("CRITICAL: Failed to decrypt JWT validation key ID %s from DB: %v. Skipping key.", ek.ID, decErr)
			continue // Пропускаем ключ, если не можем расшифровать
		}
		keyCopy := *ek
		keyCopy.Key = decryptedSecret
		decryptedKeys = append(decryptedKeys, &keyCopy)
	}
	return decryptedKeys, nil
}

// DeactivateKey помечает ключ как неактивный.
func (r *PostgresJWTKeyRepository) DeactivateKey(ctx context.Context, id string, rotatedAtTime time.Time) error {
	result := r.db.WithContext(ctx).Model(&entity.JWTKey{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{"is_active": false, "rotated_at": rotatedAtTime})

	if result.Error != nil {
		return fmt.Errorf("failed to deactivate JWT key ID %s: %w", id, result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("JWT key ID %s not found for deactivation: %w", id, apperrors.ErrNotFound)
	}
	return nil
}

// ListAllKeys извлекает все ключи из хранилища.
func (r *PostgresJWTKeyRepository) ListAllKeys(ctx context.Context) ([]*entity.JWTKey, error) {
	var encryptedKeys []*entity.JWTKey
	err := r.db.WithContext(ctx).Order("created_at DESC").Find(&encryptedKeys).Error
	if err != nil {
		return nil, fmt.Errorf("failed to list all JWT keys: %w", err)
	}

	decryptedKeys := make([]*entity.JWTKey, 0, len(encryptedKeys))
	for _, ek := range encryptedKeys {
		decryptedSecret, decErr := r.decryptKey(ek.Key)
		if decErr != nil {
			log.Printf("CRITICAL: Failed to decrypt JWT key ID %s from DB during ListAllKeys: %v. Skipping key.", ek.ID, decErr)
			continue
		}
		keyCopy := *ek
		keyCopy.Key = decryptedSecret
		decryptedKeys = append(decryptedKeys, &keyCopy)
	}
	return decryptedKeys, nil
}

// PruneExpiredKeys удаляет из хранилища ключи, которые истекли и больше не нужны для валидации.
func (r *PostgresJWTKeyRepository) PruneExpiredKeys(ctx context.Context, gracePeriod time.Duration) (int64, error) {
	// Удаляем ключи, если (ExpiresAt < now) И ( (RotatedAt < now - gracePeriod) ИЛИ (IsActive = false И RotatedAt IS NULL И CreatedAt < now - gracePeriod) )
	// То есть, ключ истек И (он был ротирован давно ИЛИ он неактивен, никогда не ротировался и создан давно)
	cutoffTime := time.Now().Add(-gracePeriod)

	result := r.db.WithContext(ctx).
		Where("expires_at < ? AND ((rotated_at IS NOT NULL AND rotated_at < ?) OR (is_active = ? AND rotated_at IS NULL AND created_at < ?))",
			time.Now(), cutoffTime, false, cutoffTime).
		Delete(&entity.JWTKey{})

	if result.Error != nil {
		return 0, fmt.Errorf("failed to prune expired JWT keys: %w", result.Error)
	}
	return result.RowsAffected, nil
}

// --- Вспомогательные функции шифрования/дешифрования ---

// encryptKey шифрует секрет ключа JWT с использованием AES-GCM.
// Возвращает hex-строку зашифрованных данных (nonce + ciphertext).
func (r *PostgresJWTKeyRepository) encryptKey(plaintextKey string) (string, error) {
	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, []byte(plaintextKey), nil)
	// Сохраняем nonce вместе с ciphertext: nonce || ciphertext
	encryptedData := append(nonce, ciphertext...)
	return hex.EncodeToString(encryptedData), nil
}

// decryptKey дешифрует секрет ключа JWT из hex-строки.
func (r *PostgresJWTKeyRepository) decryptKey(encryptedKeyHex string) (string, error) {
	encryptedData, err := hex.DecodeString(encryptedKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted key from hex: %w", err)
	}

	block, err := aes.NewCipher(r.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher for decryption: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM for decryption: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return "", errors.New("encrypted data is too short to contain nonce")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt key with GCM: %w", err)
	}

	return string(plaintext), nil
}
