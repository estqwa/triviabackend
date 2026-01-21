package entity

import (
	"time"
)

// Result представляет итоговый результат участия в викторине
type Result struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	UserID         uint      `gorm:"not null;index;uniqueIndex:idx_user_quiz" json:"user_id"`
	QuizID         uint      `gorm:"not null;index;uniqueIndex:idx_user_quiz" json:"quiz_id"`
	Username       string    `gorm:"size:50;not null" json:"username"`
	ProfilePicture string    `gorm:"size:255;not null;default:''" json:"profile_picture"`
	Score          int       `gorm:"not null;default:0" json:"score"`
	CorrectAnswers int       `gorm:"not null;default:0" json:"correct_answers"`
	TotalQuestions int       `gorm:"not null;default:0" json:"total_questions"`
	Rank           int       `gorm:"not null;default:0;index:idx_quiz_rank" json:"rank"`
	IsWinner       bool      `gorm:"not null;default:false" json:"is_winner"`
	PrizeFund      int       `gorm:"not null;default:0" json:"prize_fund"`
	IsEliminated   bool      `gorm:"not null;default:false" json:"is_eliminated"`
	CompletedAt    time.Time `gorm:"not null" json:"completed_at"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TableName определяет имя таблицы для GORM
func (Result) TableName() string {
	return "results"
}
