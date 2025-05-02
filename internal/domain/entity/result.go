package entity

import (
	"time"
)

// Result представляет итоговый результат участия в викторине
type Result struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	UserID         uint      `gorm:"not null" json:"user_id"`
	QuizID         uint      `gorm:"not null" json:"quiz_id"`
	Username       string    `json:"username"`        // Денормализованное поле для оптимизации
	ProfilePicture string    `json:"profile_picture"` // Денормализованное поле для оптимизации
	Score          int       `gorm:"not null" json:"score"`
	CorrectAnswers int       `json:"correct_answers"`
	TotalQuestions int       `json:"total_questions"`
	Rank           int       `json:"rank"`
	IsWinner       bool      `json:"is_winner"`     // Флаг, указывающий, является ли пользователь победителем
	PrizeFund      int       `json:"prize_fund"`    // Размер доли призового фонда для этого игрока
	IsEliminated   bool      `json:"is_eliminated"` // Добавленное поле: выбыл ли пользователь во время игры
	CompletedAt    time.Time `json:"completed_at"`
	CreatedAt      time.Time `json:"created_at"`
}
