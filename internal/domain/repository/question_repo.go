package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// QuestionRepository определяет методы для работы с вопросами
type QuestionRepository interface {
	Create(question *entity.Question) error
	CreateBatch(questions []entity.Question) error
	GetByID(id uint) (*entity.Question, error)
	GetByQuizID(quizID uint) ([]entity.Question, error)
	Update(question *entity.Question) error
	Delete(id uint) error
	GetRandomQuestions(limit int) ([]entity.Question, error)
}
