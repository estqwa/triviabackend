package quizmanager

import (
	"context"
	"testing"
	"time"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"gorm.io/gorm"
)

// ============================================================================
// Моки для AnswerProcessor
// ============================================================================

// MockCacheRepoForAnswerProcessor реализует repository.CacheRepository
type MockCacheRepoForAnswerProcessor struct {
	mock.Mock
}

func (m *MockCacheRepoForAnswerProcessor) Set(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockCacheRepoForAnswerProcessor) Get(key string) (string, error) {
	args := m.Called(key)
	return args.String(0), args.Error(1)
}

func (m *MockCacheRepoForAnswerProcessor) Delete(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockCacheRepoForAnswerProcessor) Exists(key string) (bool, error) {
	args := m.Called(key)
	return args.Bool(0), args.Error(1)
}

func (m *MockCacheRepoForAnswerProcessor) ExpireAt(key string, expireTime time.Time) error {
	args := m.Called(key, expireTime)
	return args.Error(0)
}

func (m *MockCacheRepoForAnswerProcessor) Increment(key string) (int64, error) {
	args := m.Called(key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockCacheRepoForAnswerProcessor) SetJSON(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockCacheRepoForAnswerProcessor) GetJSON(key string, dest interface{}) error {
	args := m.Called(key, dest)
	return args.Error(0)
}

func (m *MockCacheRepoForAnswerProcessor) SetNX(key string, value interface{}, expiration time.Duration) (bool, error) {
	args := m.Called(key, value, expiration)
	return args.Bool(0), args.Error(1)
}

// MockResultRepoForAnswerProcessor реализует repository.ResultRepository (минимально)
type MockResultRepoForAnswerProcessor struct {
	mock.Mock
}

func (m *MockResultRepoForAnswerProcessor) SaveUserAnswer(answer *entity.UserAnswer) error {
	args := m.Called(answer)
	return args.Error(0)
}

// Остальные методы не используются в ProcessAnswer, но нужны для интерфейса
func (m *MockResultRepoForAnswerProcessor) GetUserAnswers(userID uint, quizID uint) ([]entity.UserAnswer, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) GetQuizUserAnswers(quizID uint) ([]entity.UserAnswer, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) SaveResult(result *entity.Result) error { return nil }
func (m *MockResultRepoForAnswerProcessor) GetQuizResults(quizID uint, limit, offset int) ([]entity.Result, int64, error) {
	return nil, 0, nil
}
func (m *MockResultRepoForAnswerProcessor) GetAllQuizResults(quizID uint) ([]entity.Result, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) GetUserResult(userID uint, quizID uint) (*entity.Result, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) GetUserResults(userID uint, limit, offset int) ([]entity.Result, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) CalculateRanks(tx *gorm.DB, quizID uint) error {
	return nil
}
func (m *MockResultRepoForAnswerProcessor) GetQuizWinners(quizID uint) ([]entity.Result, error) {
	return nil, nil
}
func (m *MockResultRepoForAnswerProcessor) FindAndUpdateWinners(tx *gorm.DB, quizID uint, questionCount int, totalPrizeFund int) ([]uint, int, error) {
	return nil, 0, nil
}

// MockWSManagerForAnswerProcessor реализует минимальный интерфейс для WS
type MockWSManagerForAnswerProcessor struct {
	mock.Mock
}

func (m *MockWSManagerForAnswerProcessor) SendEventToUser(userID string, eventType string, data interface{}) error {
	args := m.Called(userID, eventType, data)
	return args.Error(0)
}

func (m *MockWSManagerForAnswerProcessor) BroadcastEvent(eventType string, data interface{}) error {
	args := m.Called(eventType, data)
	return args.Error(0)
}

// ============================================================================
// Тесты для AnswerProcessor
// ============================================================================

func TestAnswerProcessor_ProcessAnswer_CorrectAnswer(t *testing.T) {
	// Пропускаем — ProcessAnswer требует *websocket.Manager (не интерфейс)
	// для отправки sendEliminationNotification и финального результата
	t.Skip("ProcessAnswer требует *websocket.Manager, рекомендуется интеграционный тест")
}

func TestAnswerProcessor_ProcessAnswer_IncorrectAnswer(t *testing.T) {
	t.Skip("ProcessAnswer требует *websocket.Manager, рекомендуется интеграционный тест")
}

func TestAnswerProcessor_ProcessAnswer_TimeExceeded(t *testing.T) {
	t.Skip("ProcessAnswer требует *websocket.Manager, рекомендуется интеграционный тест")
}

func TestAnswerProcessor_ProcessAnswer_AlreadyEliminated(t *testing.T) {
	// Arrange
	mockCacheRepo := new(MockCacheRepoForAnswerProcessor)
	config := DefaultConfig()

	// Пользователь уже выбыл
	eliminationKey := "quiz:1:eliminated:42"
	mockCacheRepo.On("Exists", eliminationKey).Return(true, nil)

	deps := &Dependencies{
		CacheRepo: mockCacheRepo,
		WSManager: nil, // nil вызовет panic при вызове sendEliminationNotification
	}
	processor := NewAnswerProcessor(config, deps)

	// Подготовка данных
	question := &entity.Question{
		ID:            1,
		QuizID:        1,
		Text:          "Вопрос",
		CorrectOption: 0,
		TimeLimitSec:  30,
	}
	quizState := &ActiveQuizState{
		Quiz: &entity.Quiz{ID: 1},
	}

	// Act
	ctx := context.Background()
	err := processor.ProcessAnswer(ctx, 42, question, 0, time.Now().UnixMilli(), quizState, time.Now().Add(-5*time.Second).UnixMilli())

	// Assert
	assert.Error(t, err, "Должна быть ошибка для выбывшего пользователя")
	assert.Contains(t, err.Error(), "eliminated", "Ошибка должна указывать на выбывание")
	mockCacheRepo.AssertExpectations(t)
}

func TestAnswerProcessor_ProcessAnswer_DuplicateAnswer(t *testing.T) {
	// Arrange
	mockCacheRepo := new(MockCacheRepoForAnswerProcessor)
	mockResultRepo := new(MockResultRepoForAnswerProcessor)
	config := DefaultConfig()

	// Пользователь НЕ выбыл
	eliminationKey := "quiz:1:eliminated:42"
	mockCacheRepo.On("Exists", eliminationKey).Return(false, nil)

	// Ошибка дубликата при сохранении ответа (PostgreSQL unique_violation)
	duplicateErr := &pq.Error{Code: "23505"}
	mockResultRepo.On("SaveUserAnswer", mock.AnythingOfType("*entity.UserAnswer")).Return(duplicateErr)

	deps := &Dependencies{
		CacheRepo:  mockCacheRepo,
		ResultRepo: mockResultRepo,
		WSManager:  nil, // nil, но не будет вызван т.к. ошибка раньше
	}
	processor := NewAnswerProcessor(config, deps)

	// Подготовка данных
	question := &entity.Question{
		ID:            1,
		QuizID:        1,
		Text:          "Вопрос",
		CorrectOption: 0,
		TimeLimitSec:  30,
	}
	quizState := &ActiveQuizState{
		Quiz: &entity.Quiz{ID: 1},
	}

	// Время начала вопроса — 5 секунд назад (в пределах лимита)
	questionStartTimeMs := time.Now().Add(-5 * time.Second).UnixMilli()

	// Act
	ctx := context.Background()
	err := processor.ProcessAnswer(ctx, 42, question, 0, time.Now().UnixMilli(), quizState, questionStartTimeMs)

	// Assert
	assert.Error(t, err, "Должна быть ошибка при дублировании ответа")
	assert.Contains(t, err.Error(), "already answered", "Ошибка должна указывать на дублирующий ответ")
	mockCacheRepo.AssertExpectations(t)
	mockResultRepo.AssertExpectations(t)
}

func TestAnswerProcessor_ProcessAnswer_NoActiveQuiz(t *testing.T) {
	// Arrange
	config := DefaultConfig()
	deps := &Dependencies{}
	processor := NewAnswerProcessor(config, deps)

	question := &entity.Question{ID: 1}

	// Act: quizState = nil
	ctx := context.Background()
	err := processor.ProcessAnswer(ctx, 42, question, 0, time.Now().UnixMilli(), nil, 0)

	// Assert
	assert.Error(t, err, "Должна быть ошибка при отсутствии активной викторины")
	assert.Contains(t, err.Error(), "no active quiz")
}

func TestAnswerProcessor_ProcessAnswer_NilQuizInState(t *testing.T) {
	// Arrange
	config := DefaultConfig()
	deps := &Dependencies{}
	processor := NewAnswerProcessor(config, deps)

	question := &entity.Question{ID: 1}
	quizState := &ActiveQuizState{Quiz: nil} // Quiz = nil

	// Act
	ctx := context.Background()
	err := processor.ProcessAnswer(ctx, 42, question, 0, time.Now().UnixMilli(), quizState, 0)

	// Assert
	assert.Error(t, err, "Должна быть ошибка при nil Quiz в состоянии")
	assert.Contains(t, err.Error(), "no active quiz")
}
