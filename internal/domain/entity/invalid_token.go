package entity

import (
	"time"
)

// InvalidToken представляет запись об инвалидированном токене пользователя
type InvalidToken struct {
	UserID           uint      `gorm:"primaryKey" json:"user_id"`
	InvalidationTime time.Time `gorm:"not null" json:"invalidation_time"`
}

// TableName задает имя таблицы для GORM
func (InvalidToken) TableName() string {
	return "invalid_tokens"
}

// IsTokenInvalidAt проверяет, был ли токен инвалидирован к моменту его выпуска
// Токен считается невалидным, если он был выпущен до времени InvalidationTime
func (it *InvalidToken) IsTokenInvalidAt(issuedAt time.Time) bool {
	return issuedAt.Before(it.InvalidationTime)
}
