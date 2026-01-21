package entity

import (
	"time"
)

// UserAnswer представляет ответ пользователя на вопрос
type UserAnswer struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	UserID            uint      `gorm:"not null;index" json:"user_id"`
	QuizID            uint      `gorm:"not null;index" json:"quiz_id"`
	QuestionID        uint      `gorm:"not null;index" json:"question_id"`
	SelectedOption    int       `gorm:"not null;default:-1" json:"selected_option"`
	IsCorrect         bool      `gorm:"not null" json:"is_correct"`
	ResponseTimeMs    int64     `gorm:"not null" json:"response_time_ms"`
	Score             int       `gorm:"not null;default:0" json:"score"`
	IsEliminated      bool      `gorm:"not null;default:false" json:"is_eliminated"`
	EliminationReason string    `gorm:"size:255" json:"elimination_reason,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

// TableName определяет имя таблицы для GORM
func (UserAnswer) TableName() string {
	return "user_answers"
}
