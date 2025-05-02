package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"gorm.io/gorm"
)

// ResultRepository определяет методы для работы с результатами
type ResultRepository interface {
	SaveUserAnswer(answer *entity.UserAnswer) error
	GetUserAnswers(userID uint, quizID uint) ([]entity.UserAnswer, error)
	GetQuizUserAnswers(quizID uint) ([]entity.UserAnswer, error)
	SaveResult(result *entity.Result) error
	GetQuizResults(quizID uint, limit, offset int) ([]entity.Result, int64, error)
	GetAllQuizResults(quizID uint) ([]entity.Result, error)
	GetUserResult(userID uint, quizID uint) (*entity.Result, error)
	GetUserResults(userID uint, limit, offset int) ([]entity.Result, error)
	CalculateRanks(tx *gorm.DB, quizID uint) error
	GetQuizWinners(quizID uint) ([]entity.Result, error)
	FindAndUpdateWinners(tx *gorm.DB, quizID uint, questionCount int, totalPrizeFund int) ([]uint, int, error)
}
