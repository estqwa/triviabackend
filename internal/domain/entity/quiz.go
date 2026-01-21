package entity

import (
	"time"
)

// Константы статусов викторины
const (
	QuizStatusScheduled  = "scheduled"
	QuizStatusInProgress = "in_progress"
	QuizStatusCompleted  = "completed"
	QuizStatusCancelled  = "cancelled"
)

// Quiz представляет викторину
type Quiz struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	Title         string     `gorm:"size:100;not null" json:"title"`
	Description   string     `gorm:"size:500;not null;default:''" json:"description"`
	ScheduledTime time.Time  `gorm:"not null;index" json:"scheduled_time"`
	Status        string     `gorm:"size:20;not null;default:'scheduled';index" json:"status"`
	QuestionCount int        `gorm:"not null;default:0" json:"question_count"`
	Questions     []Question `gorm:"foreignKey:QuizID" json:"questions,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// TableName определяет имя таблицы для GORM
func (Quiz) TableName() string {
	return "quizzes"
}

// IsActive проверяет, активна ли викторина
func (q *Quiz) IsActive() bool {
	return q.Status == QuizStatusInProgress
}

// IsScheduled проверяет, запланирована ли викторина
func (q *Quiz) IsScheduled() bool {
	return q.Status == QuizStatusScheduled
}

// IsCompleted проверяет, завершена ли викторина
func (q *Quiz) IsCompleted() bool {
	return q.Status == QuizStatusCompleted
}
