package entity

import (
	"time"
)

// Quiz представляет викторину
type Quiz struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Title         string     `gorm:"size:100;not null" json:"title"`
	Description   string     `gorm:"size:500" json:"description"`
	ScheduledTime time.Time  `gorm:"not null" json:"scheduled_time"`
	Status        string     `gorm:"size:20;not null" json:"status"` // scheduled, in_progress, completed
	QuestionCount int64      `json:"question_count"`
	Questions     []Question `gorm:"foreignKey:QuizID" json:"questions,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// IsActive проверяет, активна ли викторина
func (q *Quiz) IsActive() bool {
	return q.Status == "in_progress"
}

// IsScheduled проверяет, запланирована ли викторина
func (q *Quiz) IsScheduled() bool {
	return q.Status == "scheduled"
}

// IsCompleted проверяет, завершена ли викторина
func (q *Quiz) IsCompleted() bool {
	return q.Status == "completed"
}
