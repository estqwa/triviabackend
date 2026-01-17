package service

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"github.com/yourusername/trivia-api/internal/service/quizmanager"
	"gorm.io/gorm"
)

// QuizService предоставляет методы для работы с викторинами
type QuizService struct {
	quizRepo     repository.QuizRepository
	questionRepo repository.QuestionRepository
	cacheRepo    repository.CacheRepository
	config       *quizmanager.Config
	db           *gorm.DB
}

// NewQuizService создает новый сервис викторин
func NewQuizService(
	quizRepo repository.QuizRepository,
	questionRepo repository.QuestionRepository,
	cacheRepo repository.CacheRepository,
	config *quizmanager.Config,
	db *gorm.DB,
) *QuizService {
	return &QuizService{
		quizRepo:     quizRepo,
		questionRepo: questionRepo,
		cacheRepo:    cacheRepo,
		config:       config,
		db:           db,
	}
}

// CreateQuiz создает новую викторину
func (s *QuizService) CreateQuiz(title, description string, scheduledTime time.Time) (*entity.Quiz, error) {
	// Проверяем, что время проведения в будущем
	if scheduledTime.Before(time.Now()) {
		return nil, errors.New("scheduled time must be in the future")
	}

	// Создаем новую викторину
	quiz := &entity.Quiz{
		Title:         title,
		Description:   description,
		ScheduledTime: scheduledTime,
		Status:        "scheduled",
		QuestionCount: 0,
	}

	// Сохраняем викторину в БД
	if err := s.quizRepo.Create(quiz); err != nil {
		return nil, fmt.Errorf("failed to create quiz: %w", err)
	}

	return quiz, nil
}

// GetQuizByID возвращает викторину по ID
func (s *QuizService) GetQuizByID(quizID uint) (*entity.Quiz, error) {
	return s.quizRepo.GetByID(quizID)
}

// GetActiveQuiz возвращает активную викторину
func (s *QuizService) GetActiveQuiz() (*entity.Quiz, error) {
	return s.quizRepo.GetActive()
}

// GetScheduledQuizzes возвращает список запланированных викторин
func (s *QuizService) GetScheduledQuizzes() ([]entity.Quiz, error) {
	return s.quizRepo.GetScheduled()
}

// AddQuestions добавляет вопросы к викторине
func (s *QuizService) AddQuestions(quizID uint, questions []entity.Question) error {
	// Получаем викторину, чтобы убедиться, что она существует
	quiz, err := s.quizRepo.GetByID(quizID)
	if err != nil {
		return err
	}

	// Проверяем, что викторина находится в состоянии "scheduled"
	if !quiz.IsScheduled() {
		return errors.New("can only add questions to a scheduled quiz")
	}

	// Получаем существующие вопросы
	existingQuestions, err := s.questionRepo.GetByQuizID(quizID)
	if err != nil {
		return fmt.Errorf("failed to get existing questions: %w", err)
	}

	// Проверяем, не превышает ли общее количество вопросов максимально допустимое
	maxQuestions := s.config.MaxQuestionsPerQuiz
	totalQuestions := len(existingQuestions) + len(questions)
	if totalQuestions > maxQuestions {
		return fmt.Errorf("максимальное количество вопросов – %d", maxQuestions)
	}

	// Устанавливаем quizID для всех вопросов
	for i := range questions {
		questions[i].QuizID = quizID
	}

	// Сохраняем вопросы в БД
	if err := s.questionRepo.CreateBatch(questions); err != nil {
		return fmt.Errorf("failed to create questions: %w", err)
	}

	// Обновляем количество вопросов в викторине
	quiz.QuestionCount += int64(len(questions))
	return s.quizRepo.Update(quiz)
}

// ScheduleQuiz планирует время проведения викторины
func (s *QuizService) ScheduleQuiz(quizID uint, scheduledTime time.Time) error {
	// Получаем викторину
	quiz, err := s.quizRepo.GetByID(quizID)
	if err != nil {
		return err
	}

	// Проверяем, что время проведения в будущем
	if scheduledTime.Before(time.Now()) {
		return errors.New("scheduled time must be in the future")
	}

	// Обновляем время проведения
	quiz.ScheduledTime = scheduledTime

	// Если викторина завершена, меняем статус на "scheduled"
	if quiz.IsCompleted() {
		fmt.Printf("[QuizService] Изменение статуса викторины ID=%d с 'completed' на 'scheduled'\n", quizID)
		quiz.Status = "scheduled"
	}

	return s.quizRepo.Update(quiz)
}

// GetQuizWithQuestions возвращает викторину с вопросами
func (s *QuizService) GetQuizWithQuestions(quizID uint) (*entity.Quiz, error) {
	return s.quizRepo.GetWithQuestions(quizID)
}

// ListQuizzes возвращает список викторин с пагинацией
func (s *QuizService) ListQuizzes(page, pageSize int) ([]entity.Quiz, error) {
	offset := (page - 1) * pageSize
	return s.quizRepo.List(pageSize, offset)
}

// DeleteQuiz удаляет викторину
func (s *QuizService) DeleteQuiz(quizID uint) error {
	// Получаем викторину, чтобы убедиться, что она существует
	quiz, err := s.quizRepo.GetByID(quizID)
	if err != nil {
		return err
	}

	// Проверяем, что викторина не активна
	if quiz.IsActive() {
		return errors.New("cannot delete an active quiz")
	}

	return s.quizRepo.Delete(quizID)
}

// GetQuestionsByQuizID возвращает все вопросы для викторины
func (s *QuizService) GetQuestionsByQuizID(quizID uint) ([]entity.Question, error) {
	return s.questionRepo.GetByQuizID(quizID)
}

// DuplicateQuiz создает копию существующей викторины с новым временем начала.
// Викторина-дубликат получает статус "scheduled" и копии всех вопросов оригинала.
func (s *QuizService) DuplicateQuiz(originalQuizID uint, newScheduledTime time.Time) (*entity.Quiz, error) {
	log.Printf("[QuizService] Запрос на дублирование викторины ID=%d на время %v", originalQuizID, newScheduledTime)

	// 1. Получить Оригинал с вопросами
	originalQuiz, err := s.quizRepo.GetWithQuestions(originalQuizID)
	if err != nil {
		log.Printf("[QuizService] Ошибка получения оригинала викторины ID=%d для дублирования: %v", originalQuizID, err)
		// Оборачиваем ошибку для корректной обработки в хендлере
		if errors.Is(err, apperrors.ErrNotFound) {
			return nil, fmt.Errorf("оригинальная викторина с ID %d не найдена: %w", originalQuizID, apperrors.ErrNotFound)
		}
		return nil, fmt.Errorf("ошибка получения оригинальной викторины: %w", err)
	}

	// 2. Проверить наличие вопросов
	if len(originalQuiz.Questions) == 0 {
		log.Printf("[QuizService] Попытка дублирования викторины ID=%d без вопросов.", originalQuizID)
		return nil, fmt.Errorf("нельзя дублировать викторину без вопросов: %w", apperrors.ErrValidation)
	}

	// 3. Проверить время
	if newScheduledTime.Before(time.Now()) {
		log.Printf("[QuizService] Ошибка дублирования: новое время %v уже в прошлом.", newScheduledTime)
		return nil, fmt.Errorf("новое запланированное время должно быть в будущем: %w", apperrors.ErrValidation)
	}

	// 4. Создать Новую Сущность Викторины
	newQuiz := &entity.Quiz{
		Title:         originalQuiz.Title + " (Копия)", // Добавляем пометку к названию
		Description:   originalQuiz.Description,
		ScheduledTime: newScheduledTime,
		Status:        "scheduled", // Новая викторина всегда запланирована
		QuestionCount: int64(len(originalQuiz.Questions)),
		// ID, CreatedAt, UpdatedAt будут установлены GORM
	}

	// 5. Начать Транзакцию для атомарного создания викторины и вопросов
	err = s.db.Transaction(func(tx *gorm.DB) error {
		// 5а. Сохранить Новую Викторину
		if err := tx.Create(newQuiz).Error; err != nil {
			log.Printf("[QuizService] Ошибка сохранения новой викторины (дубликат ID=%d) в транзакции: %v", originalQuizID, err)
			return fmt.Errorf("ошибка сохранения дубликата викторины: %w", err)
		}
		log.Printf("[QuizService] Дубликат викторины успешно сохранен с ID=%d в транзакции", newQuiz.ID)

		// 5б. Подготовить Новые Вопросы
		newQuestions := make([]entity.Question, 0, len(originalQuiz.Questions))
		for _, origQuestion := range originalQuiz.Questions {
			newQuestion := entity.Question{
				QuizID:        newQuiz.ID, // *** Привязка к НОВОЙ викторине ***
				Text:          origQuestion.Text,
				Options:       origQuestion.Options, // Тип StringArray должен копироваться по значению
				CorrectOption: origQuestion.CorrectOption,
				TimeLimitSec:  origQuestion.TimeLimitSec,
				PointValue:    origQuestion.PointValue,
				// ID, CreatedAt, UpdatedAt будут установлены GORM
			}
			newQuestions = append(newQuestions, newQuestion)
		}

		// 5в. Сохранить Новые Вопросы батчем
		if len(newQuestions) > 0 {
			if err := tx.Create(&newQuestions).Error; err != nil {
				log.Printf("[QuizService] Ошибка сохранения дубликатов вопросов для викторины ID=%d (оригинал ID=%d) в транзакции: %v", newQuiz.ID, originalQuizID, err)
				return fmt.Errorf("ошибка сохранения дубликатов вопросов: %w", err)
			}
			log.Printf("[QuizService] %d дубликатов вопросов успешно сохранены для викторины ID=%d в транзакции", len(newQuestions), newQuiz.ID)
		}

		// Если все успешно, транзакция автоматически коммитится
		return nil
	})

	// 6. Проверить ошибку транзакции и вернуть результат
	if err != nil {
		// Ошибка уже залогирована внутри транзакции
		return nil, err // Возвращаем ошибку транзакции
	}

	log.Printf("[QuizService] Викторина ID=%d успешно дублирована с новым ID=%d на время %v", originalQuizID, newQuiz.ID, newScheduledTime)
	// Возвращаем новую викторину (без вопросов, т.к. GetWithQuestions не вызывался для нее)
	return newQuiz, nil
}
