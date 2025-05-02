package postgres

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
)

// QuizRepo реализует repository.QuizRepository
type QuizRepo struct {
	db *gorm.DB
}

// NewQuizRepo создает новый репозиторий викторин
func NewQuizRepo(db *gorm.DB) *QuizRepo {
	return &QuizRepo{db: db}
}

// Create создает новую викторину
func (r *QuizRepo) Create(quiz *entity.Quiz) error {
	return r.db.Create(quiz).Error
}

// GetByID возвращает викторину по ID
func (r *QuizRepo) GetByID(id uint) (*entity.Quiz, error) {
	var quiz entity.Quiz
	err := r.db.First(&quiz, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &quiz, nil
}

// GetActive возвращает активную викторину
func (r *QuizRepo) GetActive() (*entity.Quiz, error) {
	var quiz entity.Quiz
	err := r.db.Where("status = ?", "in_progress").First(&quiz).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &quiz, nil
}

// GetScheduled возвращает все запланированные викторины
func (r *QuizRepo) GetScheduled() ([]entity.Quiz, error) {
	var quizzes []entity.Quiz
	err := r.db.Where("status = ? AND scheduled_time > ?", "scheduled", time.Now()).
		Order("scheduled_time").
		Find(&quizzes).Error
	if err != nil {
		return nil, err
	}
	return quizzes, nil
}

// GetWithQuestions возвращает викторину вместе с вопросами
func (r *QuizRepo) GetWithQuestions(id uint) (*entity.Quiz, error) {
	var quiz entity.Quiz
	err := r.db.Preload("Questions").First(&quiz, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &quiz, nil
}

// UpdateStatus обновляет статус викторины
func (r *QuizRepo) UpdateStatus(quizID uint, status string) error {
	return r.db.Model(&entity.Quiz{}).
		Where("id = ?", quizID).
		Update("status", status).
		Error
}

// Update обновляет информацию о викторине
func (r *QuizRepo) Update(quiz *entity.Quiz) error {
	return r.db.Save(quiz).Error
}

// List возвращает список викторин с пагинацией
func (r *QuizRepo) List(limit, offset int) ([]entity.Quiz, error) {
	var quizzes []entity.Quiz
	err := r.db.Limit(limit).Offset(offset).Order("id DESC").Find(&quizzes).Error
	return quizzes, err
}

// Delete удаляет викторину
func (r *QuizRepo) Delete(id uint) error {
	return r.db.Delete(&entity.Quiz{}, id).Error
}
