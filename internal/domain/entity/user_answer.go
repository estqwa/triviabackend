package entity

import (
	"time"
)

// UserAnswer представляет ответ пользователя на вопрос
type UserAnswer struct {
	ID                uint      `gorm:"primaryKey" json:"id"`
	UserID            uint      `gorm:"not null" json:"user_id"`
	QuizID            uint      `gorm:"not null" json:"quiz_id"`
	QuestionID        uint      `gorm:"not null" json:"question_id"`
	SelectedOption    int       `json:"selected_option"`
	IsCorrect         bool      `json:"is_correct"`
	ResponseTimeMs    int64     `json:"response_time_ms"`
	Score             int       `json:"score"`
	IsEliminated      bool      `json:"is_eliminated"`
	EliminationReason string    `json:"elimination_reason,omitempty"` // Причина выбывания
	CreatedAt         time.Time `json:"created_at"`
}
