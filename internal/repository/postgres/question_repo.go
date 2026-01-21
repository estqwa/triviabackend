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
	return r.db.Transaction(func(tx *gorm.DB) error {
		// Устанавливаем кодировку UTF-8 внутри транзакции
		if err := tx.Exec("SET CLIENT_ENCODING TO 'UTF8'").Error; err != nil {
			return err
		}
		return tx.Create(&questions).Error
	})
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
// Оптимизировано для производительности при больших объёмах данных
func (r *QuestionRepo) GetRandomQuestions(limit int) ([]entity.Question, error) {
	var questions []entity.Question

	// Используем TABLESAMPLE для O(1) производительности вместо ORDER BY RANDOM()
	// SYSTEM выбирает случайные страницы данных, что намного быстрее при большом количестве записей
	// Берём больше записей, чем нужно (limit*3), затем перемешиваем и обрезаем,
	// т.к. TABLESAMPLE может вернуть меньше записей, чем ожидается
	sql := `
		SELECT * FROM questions 
		TABLESAMPLE SYSTEM_ROWS(?)
		ORDER BY RANDOM()
		LIMIT ?
	`

	// Запрашиваем с запасом, чтобы гарантировать достаточное количество
	sampleSize := limit * 3
	if sampleSize < 100 {
		sampleSize = 100 // Минимальный размер выборки
	}

	err := r.db.Raw(sql, sampleSize, limit).Scan(&questions).Error
	if err != nil {
		// Fallback на старый метод, если TABLESAMPLE не поддерживается или пустой результат
		err = r.db.Order("RANDOM()").Limit(limit).Find(&questions).Error
		if err != nil {
			return nil, err
		}
	}

	// Если TABLESAMPLE вернул пустой результат (маленькая таблица), используем fallback
	if len(questions) == 0 {
		err = r.db.Order("RANDOM()").Limit(limit).Find(&questions).Error
		if err != nil {
			return nil, err
		}
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
