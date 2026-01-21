package entity

import (
	"time"
)

// JWTKey представляет ключ подписи JWT и его метаданные.
type JWTKey struct {
	ID         string     `gorm:"primaryKey;type:varchar(100)" json:"id"`
	Key        string     `gorm:"type:text;not null" json:"-"`
	Algorithm  string     `gorm:"type:varchar(50);not null" json:"algorithm"`
	IsActive   bool       `gorm:"index;not null" json:"is_active"`
	CreatedAt  time.Time  `gorm:"not null" json:"created_at"`
	ExpiresAt  time.Time  `gorm:"not null;index" json:"expires_at"`
	RotatedAt  *time.Time `gorm:"index" json:"rotated_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// TableName определяет имя таблицы для GORM.
func (JWTKey) TableName() string {
	return "jwt_keys"
}

// IsExpired проверяет, истёк ли срок действия ключа
func (k *JWTKey) IsExpired() bool {
	return time.Now().After(k.ExpiresAt)
}

// CanBeUsedForSigning проверяет, может ли ключ использоваться для подписи
// Ключ должен быть активным и не истёкшим
func (k *JWTKey) CanBeUsedForSigning() bool {
	return k.IsActive && !k.IsExpired()
}

// CanBeUsedForVerification проверяет, может ли ключ использоваться для проверки подписи
// Ключ может использоваться для проверки, даже если он неактивен (но не истёк)
func (k *JWTKey) CanBeUsedForVerification() bool {
	return !k.IsExpired()
}
