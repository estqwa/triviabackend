package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// QuizRepository определяет методы для работы с викторинами
type QuizRepository interface {
	Create(quiz *entity.Quiz) error
	GetByID(id uint) (*entity.Quiz, error)
	GetActive() (*entity.Quiz, error)
	GetScheduled() ([]entity.Quiz, error)
	GetWithQuestions(id uint) (*entity.Quiz, error)
	UpdateStatus(quizID uint, status string) error
	Update(quiz *entity.Quiz) error
	List(limit, offset int) ([]entity.Quiz, error)
	Delete(id uint) error
}
