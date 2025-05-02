package postgres

import (
	"errors"

	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
)

// QuestionRepo реализует repository.QuestionRepository
type QuestionRepo struct {
	db *gorm.DB
}

// NewQuestionRepo создает новый репозиторий вопросов
func NewQuestionRepo(db *gorm.DB) *QuestionRepo {
	return &QuestionRepo{db: db}
}

// Create создает новый вопрос
func (r *QuestionRepo) Create(question *entity.Question) error {
	return r.db.Create(question).Error
}

// CreateBatch создает пакет вопросов
func (r *QuestionRepo) CreateBatch(questions []entity.Question) error {
	// Принудительно указываем кодировку UTF-8 для операции
	tx := r.db.Exec("SET CLIENT_ENCODING TO 'UTF8'").Begin()
	if tx.Error != nil {
		return tx.Error
	}

	err := tx.Create(&questions).Error
	if err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit().Error
}

// GetByID возвращает вопрос по ID
func (r *QuestionRepo) GetByID(id uint) (*entity.Question, error) {
	var question entity.Question
	err := r.db.First(&question, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &question, nil
}

// GetByQuizID возвращает все вопросы для викторины
func (r *QuestionRepo) GetByQuizID(quizID uint) ([]entity.Question, error) {
	var questions []entity.Question
	err := r.db.Where("quiz_id = ?", quizID).Order("id").Find(&questions).Error
	if err != nil {
		return nil, err
	}
	return questions, nil
}

// GetRandomQuestions возвращает случайные вопросы из базы данных
func (r *QuestionRepo) GetRandomQuestions(limit int) ([]entity.Question, error) {
	var questions []entity.Question
	err := r.db.Order("RANDOM()").Limit(limit).Find(&questions).Error
	if err != nil {
		return nil, err
	}
	return questions, nil
}

// Update обновляет информацию о вопросе
func (r *QuestionRepo) Update(question *entity.Question) error {
	return r.db.Save(question).Error
}

// Delete удаляет вопрос
func (r *QuestionRepo) Delete(id uint) error {
	return r.db.Delete(&entity.Question{}, id).Error
}
