package entity

import (
	"time"
)

// JWTKey представляет ключ подписи JWT и его метаданные.
type JWTKey struct {
	ID          string    `gorm:"primaryKey;type:varchar(100)" json:"id"`          // Уникальный идентификатор ключа (например, UUID или хеш)
	Key         string    `gorm:"type:text;not null" json:"-"`                      // Зашифрованный секретный ключ
	Algorithm   string    `gorm:"type:varchar(50);not null" json:"algorithm"`       // Алгоритм подписи (например, "HS256", "RS256")
	IsActive    bool      `gorm:"index;not null" json:"is_active"`                  // Является ли ключ текущим активным для подписи
	CreatedAt   time.Time `gorm:"not null" json:"created_at"`                       // Время создания ключа
	ExpiresAt   time.Time `gorm:"not null" json:"expires_at"`                       // Время, после которого ключ не должен использоваться для подписи (но может быть валиден для проверки)
	RotatedAt   *time.Time `gorm:"index" json:"rotated_at,omitempty"`               // Время, когда ключ был заменен новым активным ключом (стал неактивным)
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`                          // Время последнего использования ключа (для статистики, опционально)
}

// TableName определяет имя таблицы для GORM.
func (JWTKey) TableName() string {
	return "jwt_keys"
} 