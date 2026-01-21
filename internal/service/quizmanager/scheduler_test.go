package quizmanager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// ============================================================================
// Моки для Scheduler
// ============================================================================

// MockQuizRepoForScheduler реализует repository.QuizRepository
type MockQuizRepoForScheduler struct {
	mock.Mock
}

func (m *MockQuizRepoForScheduler) GetByID(id uint) (*entity.Quiz, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

func (m *MockQuizRepoForScheduler) GetWithQuestions(id uint) (*entity.Quiz, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

func (m *MockQuizRepoForScheduler) UpdateStatus(id uint, status string) error {
	args := m.Called(id, status)
	return args.Error(0)
}

func (m *MockQuizRepoForScheduler) Update(quiz *entity.Quiz) error {
	args := m.Called(quiz)
	return args.Error(0)
}

func (m *MockQuizRepoForScheduler) Create(quiz *entity.Quiz) error {
	args := m.Called(quiz)
	return args.Error(0)
}

func (m *MockQuizRepoForScheduler) GetActive() (*entity.Quiz, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

func (m *MockQuizRepoForScheduler) GetScheduled() ([]entity.Quiz, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Quiz), args.Error(1)
}

func (m *MockQuizRepoForScheduler) List(limit, offset int) ([]entity.Quiz, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Quiz), args.Error(1)
}

func (m *MockQuizRepoForScheduler) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

// MockWSManagerForScheduler реализует минимальный интерфейс WebSocket Manager
type MockWSManagerForScheduler struct {
	mock.Mock
}

func (m *MockWSManagerForScheduler) BroadcastEvent(eventType string, data interface{}) error {
	args := m.Called(eventType, data)
	return args.Error(0)
}

// ============================================================================
// createTestScheduler создаёт Scheduler для тестирования
// ============================================================================

// createTestSchedulerDeps создаёт Dependencies с моками
func createTestSchedulerDeps(
	quizRepo *MockQuizRepoForScheduler,
	wsManager *MockWSManagerForScheduler,
) *Dependencies {
	return &Dependencies{
		QuizRepo:  quizRepo,
		WSManager: nil, // Будет установлен отдельно для тестов
	}
}

// ============================================================================
// Тесты для Scheduler
// ============================================================================

func TestScheduler_ScheduleQuiz_Success(t *testing.T) {
	// Arrange
	mockQuizRepo := new(MockQuizRepoForScheduler)
	config := DefaultConfig()

	// Викторина с вопросами
	scheduledTime := time.Now().Add(1 * time.Hour)
	quiz := &entity.Quiz{
		ID:            1,
		Title:         "Тестовая викторина",
		Status:        entity.QuizStatusScheduled,
		ScheduledTime: scheduledTime,
		Questions: []entity.Question{
			{ID: 1, Text: "Вопрос 1"},
			{ID: 2, Text: "Вопрос 2"},
		},
	}

	mockQuizRepo.On("GetWithQuestions", uint(1)).Return(quiz, nil)
	mockQuizRepo.On("Update", mock.AnythingOfType("*entity.Quiz")).Return(nil)

	// Создаём Scheduler напрямую (без wsManager для этого теста)
	deps := &Dependencies{
		QuizRepo: mockQuizRepo,
	}
	scheduler := NewScheduler(config, deps)

	// Act
	ctx := context.Background()
	err := scheduler.ScheduleQuiz(ctx, 1, scheduledTime)

	// Assert
	require.NoError(t, err, "Планирование викторины должно быть успешным")
	mockQuizRepo.AssertExpectations(t)
}

func TestScheduler_ScheduleQuiz_PastTime(t *testing.T) {
	// Arrange
	mockQuizRepo := new(MockQuizRepoForScheduler)
	config := DefaultConfig()

	deps := &Dependencies{
		QuizRepo: mockQuizRepo,
	}
	scheduler := NewScheduler(config, deps)

	// Время в прошлом
	pastTime := time.Now().Add(-1 * time.Hour)

	// Act
	ctx := context.Background()
	err := scheduler.ScheduleQuiz(ctx, 1, pastTime)

	// Assert
	assert.Error(t, err, "Должна быть ошибка при времени в прошлом")
	assert.Contains(t, err.Error(), "past", "Ошибка должна указывать на время в прошлом")
	// GetWithQuestions не должен быть вызван
	mockQuizRepo.AssertNotCalled(t, "GetWithQuestions")
}

func TestScheduler_ScheduleQuiz_NoQuestions(t *testing.T) {
	// Arrange
	mockQuizRepo := new(MockQuizRepoForScheduler)
	config := DefaultConfig()

	// Викторина БЕЗ вопросов
	scheduledTime := time.Now().Add(1 * time.Hour)
	quiz := &entity.Quiz{
		ID:            1,
		Title:         "Пустая викторина",
		Status:        entity.QuizStatusScheduled,
		ScheduledTime: scheduledTime,
		Questions:     []entity.Question{}, // Пусто!
	}

	mockQuizRepo.On("GetWithQuestions", uint(1)).Return(quiz, nil)

	deps := &Dependencies{
		QuizRepo: mockQuizRepo,
	}
	scheduler := NewScheduler(config, deps)

	// Act
	ctx := context.Background()
	err := scheduler.ScheduleQuiz(ctx, 1, scheduledTime)

	// Assert
	assert.Error(t, err, "Должна быть ошибка при отсутствии вопросов")
	assert.Contains(t, err.Error(), "no questions", "Ошибка должна указывать на отсутствие вопросов")
	// Update не должен быть вызван
	mockQuizRepo.AssertNotCalled(t, "Update")
}

func TestScheduler_CancelQuiz_Success(t *testing.T) {
	// Arrange
	mockQuizRepo := new(MockQuizRepoForScheduler)
	config := DefaultConfig()

	// Викторина в статусе scheduled
	quiz := &entity.Quiz{
		ID:     1,
		Title:  "Викторина",
		Status: entity.QuizStatusScheduled,
	}

	mockQuizRepo.On("GetByID", uint(1)).Return(quiz, nil)
	mockQuizRepo.On("UpdateStatus", uint(1), entity.QuizStatusCancelled).Return(nil)

	// Создаём mock для WSManager
	mockWSManager := new(MockWSManagerForScheduler)
	mockWSManager.On("BroadcastEvent", "quiz:cancelled", mock.Anything).Return(nil)

	// Для теста создаём Scheduler с WSManager через обёртку
	// Но WSManager в Dependencies — это *websocket.Manager, не интерфейс
	// Поэтому создаём Scheduler без WSManager и проверяем только репозиторий

	deps := &Dependencies{
		QuizRepo:  mockQuizRepo,
		WSManager: nil, // nil — WS вызов вызовет panic
	}
	_ = NewScheduler(config, deps) // Создаём, но не используем — тест пропущен

	// Для полного теста потребуется интеграционный тест с настоящим WSManager
	// или рефакторинг Dependencies для использования интерфейса вместо *websocket.Manager

	t.Skip("CancelQuiz требует *websocket.Manager, рекомендуется интеграционный тест")
}
