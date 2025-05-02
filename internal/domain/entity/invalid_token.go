package entity

import (
	"time"
)

// InvalidToken представляет запись об инвалидированном токене пользователя
type InvalidToken struct {
	UserID           uint      `gorm:"primaryKey" json:"user_id"`
	InvalidationTime time.Time `json:"invalidation_time"`
}

// TableName задает имя таблицы для GORM
func (InvalidToken) TableName() string {
	return "invalid_tokens"
}
