package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"gorm.io/gorm"
)

// ============================================================================
// Моки для ResultService
// ============================================================================

// MockResultRepository реализует repository.ResultRepository
type MockResultRepoForResultService struct {
	mock.Mock
}

func (m *MockResultRepoForResultService) SaveUserAnswer(answer *entity.UserAnswer) error {
	args := m.Called(answer)
	return args.Error(0)
}

func (m *MockResultRepoForResultService) GetUserAnswers(userID uint, quizID uint) ([]entity.UserAnswer, error) {
	args := m.Called(userID, quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.UserAnswer), args.Error(1)
}

func (m *MockResultRepoForResultService) GetQuizUserAnswers(quizID uint) ([]entity.UserAnswer, error) {
	args := m.Called(quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.UserAnswer), args.Error(1)
}

func (m *MockResultRepoForResultService) SaveResult(result *entity.Result) error {
	args := m.Called(result)
	return args.Error(0)
}

func (m *MockResultRepoForResultService) GetQuizResults(quizID uint, limit, offset int) ([]entity.Result, int64, error) {
	args := m.Called(quizID, limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]entity.Result), args.Get(1).(int64), args.Error(2)
}

func (m *MockResultRepoForResultService) GetAllQuizResults(quizID uint) ([]entity.Result, error) {
	args := m.Called(quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Result), args.Error(1)
}

func (m *MockResultRepoForResultService) GetUserResult(userID uint, quizID uint) (*entity.Result, error) {
	args := m.Called(userID, quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Result), args.Error(1)
}

func (m *MockResultRepoForResultService) GetUserResults(userID uint, limit, offset int) ([]entity.Result, error) {
	args := m.Called(userID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Result), args.Error(1)
}

func (m *MockResultRepoForResultService) CalculateRanks(tx *gorm.DB, quizID uint) error {
	args := m.Called(tx, quizID)
	return args.Error(0)
}

func (m *MockResultRepoForResultService) GetQuizWinners(quizID uint) ([]entity.Result, error) {
	args := m.Called(quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Result), args.Error(1)
}

func (m *MockResultRepoForResultService) FindAndUpdateWinners(tx *gorm.DB, quizID uint, questionCount int, totalPrizeFund int) ([]uint, int, error) {
	args := m.Called(tx, quizID, questionCount, totalPrizeFund)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]uint), args.Int(1), args.Error(2)
}

// ============================================================================
// createTestResultService создаёт ResultService для тестирования
// ============================================================================

func createTestResultService(
	resultRepo *MockResultRepoForResultService,
) *ResultService {
	return &ResultService{
		resultRepo:   resultRepo,
		userRepo:     nil, // nil для этих тестов
		quizRepo:     nil,
		questionRepo: nil,
		cacheRepo:    nil,
		db:           nil,
		wsManager:    nil,
		config:       nil,
	}
}

// ============================================================================
// Тесты для ResultService
// ============================================================================

func TestResultService_GetQuizResults_Pagination(t *testing.T) {
	// Arrange
	mockResultRepo := new(MockResultRepoForResultService)

	expectedResults := []entity.Result{
		{ID: 1, UserID: 1, QuizID: 1, Score: 100, Rank: 1},
		{ID: 2, UserID: 2, QuizID: 1, Score: 80, Rank: 2},
		{ID: 3, UserID: 3, QuizID: 1, Score: 60, Rank: 3},
	}
	expectedTotal := int64(10)

	// page=1, pageSize=3 -> offset=0, limit=3
	mockResultRepo.On("GetQuizResults", uint(1), 3, 0).Return(expectedResults, expectedTotal, nil)

	resultService := createTestResultService(mockResultRepo)

	// Act
	results, total, err := resultService.GetQuizResults(1, 1, 3)

	// Assert
	require.NoError(t, err, "Получение результатов должно быть успешным")
	assert.Equal(t, 3, len(results), "Должно быть 3 результата")
	assert.Equal(t, int64(10), total, "Общее количество должно быть 10")
	assert.Equal(t, 100, results[0].Score, "Первый результат должен иметь Score=100")
	mockResultRepo.AssertExpectations(t)
}

func TestResultService_GetQuizResults_PageValidation(t *testing.T) {
	// Тест: невалидные параметры пагинации корректируются
	mockResultRepo := new(MockResultRepoForResultService)

	expectedResults := []entity.Result{
		{ID: 1, UserID: 1, QuizID: 1, Score: 100},
	}

	// page < 1 корректируется до 1, pageSize < 1 корректируется до 10
	// offset = (1-1)*10 = 0
	mockResultRepo.On("GetQuizResults", uint(1), 10, 0).Return(expectedResults, int64(1), nil)

	resultService := createTestResultService(mockResultRepo)

	// Act: передаём невалидные параметры
	results, _, err := resultService.GetQuizResults(1, 0, 0)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, results)
	mockResultRepo.AssertExpectations(t)
}

func TestResultService_GetQuizResults_MaxPageSize(t *testing.T) {
	// Тест: pageSize > 100 корректируется до 100
	mockResultRepo := new(MockResultRepoForResultService)

	expectedResults := []entity.Result{
		{ID: 1, UserID: 1, QuizID: 1, Score: 100},
	}

	// pageSize=500 корректируется до 100
	mockResultRepo.On("GetQuizResults", uint(1), 100, 0).Return(expectedResults, int64(1), nil)

	resultService := createTestResultService(mockResultRepo)

	// Act: передаём слишком большой pageSize
	results, _, err := resultService.GetQuizResults(1, 1, 500)

	// Assert
	require.NoError(t, err)
	assert.NotEmpty(t, results)
	mockResultRepo.AssertExpectations(t)
}

func TestResultService_GetUserResult_Success(t *testing.T) {
	// Arrange
	mockResultRepo := new(MockResultRepoForResultService)

	expectedResult := &entity.Result{
		ID:             1,
		UserID:         42,
		QuizID:         1,
		Score:          150,
		CorrectAnswers: 8,
		TotalQuestions: 10,
		Rank:           3,
	}

	mockResultRepo.On("GetUserResult", uint(42), uint(1)).Return(expectedResult, nil)

	resultService := createTestResultService(mockResultRepo)

	// Act
	result, err := resultService.GetUserResult(42, 1)

	// Assert
	require.NoError(t, err, "Получение результата пользователя должно быть успешным")
	assert.NotNil(t, result)
	assert.Equal(t, uint(42), result.UserID)
	assert.Equal(t, 150, result.Score)
	assert.Equal(t, 3, result.Rank)
	mockResultRepo.AssertExpectations(t)
}

func TestResultService_GetUserResults_Pagination(t *testing.T) {
	// Arrange
	mockResultRepo := new(MockResultRepoForResultService)

	expectedResults := []entity.Result{
		{ID: 1, UserID: 42, QuizID: 1, Score: 100},
		{ID: 2, UserID: 42, QuizID: 2, Score: 80},
	}

	// page=2, pageSize=2 -> offset=2, limit=2
	mockResultRepo.On("GetUserResults", uint(42), 2, 2).Return(expectedResults, nil)

	resultService := createTestResultService(mockResultRepo)

	// Act
	results, err := resultService.GetUserResults(42, 2, 2)

	// Assert
	require.NoError(t, err, "Получение результатов пользователя должно быть успешным")
	assert.Equal(t, 2, len(results))
	mockResultRepo.AssertExpectations(t)
}

// ============================================================================
// Тесты для сложных методов (CalculateQuizResult, DetermineWinnersAndAllocatePrizes)
// требуют интеграционных тестов с реальной базой данных, так как используют
// транзакции gorm.DB напрямую. Рекомендуется использовать testcontainers или
// in-memory SQLite для таких тестов.
// ============================================================================
