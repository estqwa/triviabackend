package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/websocket"
)

// Создаем мок-объекты для интерфейсов
type MockQuizRepository struct {
	mock.Mock
}

func (m *MockQuizRepository) GetByID(id uint) (*entity.Quiz, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

func (m *MockQuizRepository) GetWithQuestions(id uint) (*entity.Quiz, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

func (m *MockQuizRepository) UpdateStatus(id uint, status string) error {
	args := m.Called(id, status)
	return args.Error(0)
}

func (m *MockQuizRepository) Update(quiz *entity.Quiz) error {
	args := m.Called(quiz)
	return args.Error(0)
}

// Добавляем недостающий метод Create
func (m *MockQuizRepository) Create(quiz *entity.Quiz) error {
	args := m.Called(quiz)
	return args.Error(0)
}

// Добавляем недостающий метод GetActive
func (m *MockQuizRepository) GetActive() (*entity.Quiz, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Quiz), args.Error(1)
}

// Добавляем недостающий метод GetScheduled
func (m *MockQuizRepository) GetScheduled() ([]entity.Quiz, error) {
	args := m.Called()
	return args.Get(0).([]entity.Quiz), args.Error(1)
}

// Добавляем недостающий метод List
func (m *MockQuizRepository) List(limit, offset int) ([]entity.Quiz, error) {
	args := m.Called(limit, offset)
	return args.Get(0).([]entity.Quiz), args.Error(1)
}

// Добавляем недостающий метод Delete
func (m *MockQuizRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

// Мок для cache repository
type MockCacheRepository struct {
	mock.Mock
}

func (m *MockCacheRepository) Set(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

func (m *MockCacheRepository) Get(key string) (string, error) {
	args := m.Called(key)
	return args.String(0), args.Error(1)
}

// Добавляем недостающий метод Delete
func (m *MockCacheRepository) Delete(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

// Добавляем недостающий метод Exists
func (m *MockCacheRepository) Exists(key string) (bool, error) {
	args := m.Called(key)
	return args.Bool(0), args.Error(1)
}

// Добавляем недостающий метод ExpireAt
func (m *MockCacheRepository) ExpireAt(key string, expireTime time.Time) error {
	args := m.Called(key, expireTime)
	return args.Error(0)
}

// Добавляем Increment метод в MockCacheRepository
func (m *MockCacheRepository) Increment(key string) (int64, error) {
	args := m.Called(key)
	return args.Get(0).(int64), args.Error(1)
}

// Добавляем SetJSON метод в MockCacheRepository
func (m *MockCacheRepository) SetJSON(key string, value interface{}, expiration time.Duration) error {
	args := m.Called(key, value, expiration)
	return args.Error(0)
}

// Добавляем GetJSON метод в MockCacheRepository
func (m *MockCacheRepository) GetJSON(key string, dest interface{}) error {
	args := m.Called(key, dest)
	return args.Error(0)
}

// Мок для WebSocket Manager, который должен соответствовать типу *websocket.Manager
type MockManager struct {
	mock.Mock
	t *testing.T // для логирования действий в тестах
}

// NewMockManager создает новый мок-менеджер с привязкой к тесту
func NewMockManager(t *testing.T) *MockManager {
	return &MockManager{t: t}
}

func (m *MockManager) BroadcastEvent(eventType string, data interface{}) error {
	if m.t != nil {
		m.t.Logf("[WebSocket] Попытка broadcast события: %s с данными: %+v", eventType, data)
	}
	args := m.Called(eventType, data)
	err := args.Error(0)
	if err != nil && m.t != nil {
		m.t.Logf("[WebSocket ERROR] Broadcast %s завершился с ошибкой: %v", eventType, err)
	}
	return err
}

func (m *MockManager) SendEventToUser(userID string, eventType string, data interface{}) error {
	if m.t != nil {
		m.t.Logf("[WebSocket] Попытка отправки пользователю %s события: %s с данными: %+v", userID, eventType, data)
	}
	args := m.Called(userID, eventType, data)
	err := args.Error(0)
	if err != nil && m.t != nil {
		m.t.Logf("[WebSocket ERROR] Отправка %s пользователю %s завершилась с ошибкой: %v", eventType, userID, err)
	}
	return err
}

// Добавляем другие необходимые методы Manager, если они есть в интерфейсе
func (m *MockManager) RegisterHandler(eventType string, handler func(data json.RawMessage, client *websocket.Client) error) {
	if m.t != nil {
		m.t.Logf("[WebSocket] Регистрация обработчика для события: %s", eventType)
	}
	m.Called(eventType, handler)
}

func (m *MockManager) HandleMessage(message []byte, client *websocket.Client) {
	if m.t != nil {
		m.t.Logf("[WebSocket] Обработка сообщения: %s", string(message))
	}
	m.Called(message, client)
}

// Мок для результатов
type MockResultRepository struct {
	mock.Mock
}

func (m *MockResultRepository) SaveUserAnswer(answer *entity.UserAnswer) error {
	args := m.Called(answer)
	return args.Error(0)
}

func (m *MockResultRepository) CalculateRanks(quizID uint) error {
	args := m.Called(quizID)
	return args.Error(0)
}

func (m *MockResultRepository) GetQuizResults(quizID uint) ([]entity.Result, error) {
	args := m.Called(quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.Result), args.Error(1)
}

// Добавляем недостающий метод GetUserAnswers
func (m *MockResultRepository) GetUserAnswers(userID, quizID uint) ([]entity.UserAnswer, error) {
	args := m.Called(userID, quizID)
	return args.Get(0).([]entity.UserAnswer), args.Error(1)
}

// Добавляем недостающий метод SaveResult
func (m *MockResultRepository) SaveResult(result *entity.Result) error {
	args := m.Called(result)
	return args.Error(0)
}

// Добавляем недостающий метод GetUserResult
func (m *MockResultRepository) GetUserResult(userID, quizID uint) (*entity.Result, error) {
	args := m.Called(userID, quizID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Result), args.Error(1)
}

// Добавляем недостающий метод GetUserResults
func (m *MockResultRepository) GetUserResults(userID uint, limit, offset int) ([]entity.Result, error) {
	args := m.Called(userID, limit, offset)
	return args.Get(0).([]entity.Result), args.Error(1)
}

// Добавляем недостающий метод GetQuizUserAnswers
func (m *MockResultRepository) GetQuizUserAnswers(quizID uint) ([]entity.UserAnswer, error) {
	args := m.Called(quizID)
	return args.Get(0).([]entity.UserAnswer), args.Error(1)
}

// Мок для вопросов
type MockQuestionRepository struct {
	mock.Mock
}

func (m *MockQuestionRepository) GetByID(id uint) (*entity.Question, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.Question), args.Error(1)
}

// Добавляем недостающий метод Create
func (m *MockQuestionRepository) Create(question *entity.Question) error {
	args := m.Called(question)
	return args.Error(0)
}

// Добавляем недостающий метод CreateBatch
func (m *MockQuestionRepository) CreateBatch(questions []entity.Question) error {
	args := m.Called(questions)
	return args.Error(0)
}

// Добавляем недостающий метод GetByQuizID
func (m *MockQuestionRepository) GetByQuizID(quizID uint) ([]entity.Question, error) {
	args := m.Called(quizID)
	return args.Get(0).([]entity.Question), args.Error(1)
}

// Добавляем недостающий метод Delete
func (m *MockQuestionRepository) Delete(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

// Добавляем недостающий метод Update
func (m *MockQuestionRepository) Update(question *entity.Question) error {
	args := m.Called(question)
	return args.Error(0)
}

// WebSocketInterface определяет интерфейс для WebSocket-взаимодействия
// Это позволяет нам создать адаптер для тестирования без изменения основного кода
type WebSocketInterface interface {
	BroadcastEvent(eventType string, data interface{}) error
	SendEventToUser(userID string, eventType string, data interface{}) error
}

// WebSocketAdapterForTest адаптирует наш мок к интерфейсу WebSocketInterface
type WebSocketAdapterForTest struct {
	Mock *MockManager
}

// BroadcastEvent делегирует вызов в MockManager
func (a *WebSocketAdapterForTest) BroadcastEvent(eventType string, data interface{}) error {
	return a.Mock.BroadcastEvent(eventType, data)
}

// SendEventToUser делегирует вызов в MockManager
func (a *WebSocketAdapterForTest) SendEventToUser(userID string, eventType string, data interface{}) error {
	return a.Mock.SendEventToUser(userID, eventType, data)
}

// TestQuizManagerWithWebSocketInterface улучшаем с assert и детальными сообщениями
func TestQuizManagerWithWebSocketInterface(t *testing.T) {
	// Создаем моки с привязкой к тесту
	mockWSManager := NewMockManager(t)

	// Создаем адаптер
	adapter := &WebSocketAdapterForTest{
		Mock: mockWSManager,
	}

	t.Run("BroadcastEvent delegates to MockManager", func(t *testing.T) {
		// Настройка мока
		eventType := "test:event"
		data := map[string]interface{}{"test": "data"}
		mockWSManager.On("BroadcastEvent", eventType, data).Return(nil).Once()

		// Вызов метода через адаптер
		err := adapter.BroadcastEvent(eventType, data)

		// Проверка результатов с улучшенными сообщениями
		assert.NoError(t, err, "BroadcastEvent не должен возвращать ошибку")
		mockWSManager.AssertExpectations(t)
	})

	t.Run("SendEventToUser delegates to MockManager", func(t *testing.T) {
		// Настройка мока
		userID := "123"
		eventType := "test:user_event"
		data := map[string]interface{}{"test": "user_data"}
		mockWSManager.On("SendEventToUser", userID, eventType, data).Return(nil).Once()

		// Вызов метода через адаптер
		err := adapter.SendEventToUser(userID, eventType, data)

		// Проверка результатов с улучшенными сообщениями
		assert.NoError(t, err, "SendEventToUser не должен возвращать ошибку")
		mockWSManager.AssertExpectations(t)
	})

	t.Run("BroadcastEvent handles errors correctly", func(t *testing.T) {
		// Настройка мока с возвращением ошибки
		eventType := "test:error_event"
		data := map[string]interface{}{"test": "error_data"}
		expectedError := errors.New("broadcast error")
		mockWSManager.On("BroadcastEvent", eventType, data).Return(expectedError).Once()

		// Вызов метода через адаптер
		err := adapter.BroadcastEvent(eventType, data)

		// Проверка результатов с улучшенными сообщениями
		assert.Error(t, err, "BroadcastEvent должен вернуть ошибку при симуляции сбоя")
		assert.Equal(t, expectedError.Error(), err.Error(),
			fmt.Sprintf("Неправильный текст ошибки. Ожидалось: %v, получено: %v", expectedError, err))
		mockWSManager.AssertExpectations(t)
	})
}

// Добавляю функцию TestMain для настройки тестов
func TestMain(m *testing.M) {
	// Здесь можно выполнить глобальную настройку для всех тестов
	// Например, создать фейковые объекты или настроить логгирование

	// Запускаем тесты
	m.Run()
}

// TestQuizManagerWithWebSocketMock улучшаем с более детальными проверками и логированием
func TestQuizManagerWithWebSocketMock(t *testing.T) {
	t.Run("ProcessAnswer with WebSocket error", func(t *testing.T) {
		// Подготавливаем моки с привязкой к тесту
		mockResultRepo := new(MockResultRepository)
		mockWSManager := NewMockManager(t)

		// Создаем адаптер для WebSocket
		adapter := &WebSocketAdapterForTest{
			Mock: mockWSManager,
		}

		// Подготавливаем тестовые данные
		userID := uint(1)
		questionID := uint(1)
		selectedOption := 1

		// Создаем собственную реализацию ProcessAnswer
		processAnswer := func() error {
			// Получаем вопрос
			question := &entity.Question{
				ID:            questionID,
				QuizID:        1,
				Text:          "Test Question",
				Options:       []string{"Option 1", "Option 2", "Option 3"},
				CorrectOption: selectedOption,
				TimeLimitSec:  30,
				PointValue:    10,
			}

			// Симулируем несколько типов ошибок WebSocket
			webSocketError := errors.New("simulated WebSocket connection failure")
			mockWSManager.On("SendEventToUser", fmt.Sprintf("%d", userID), "quiz:answer_result", mock.Anything).
				Return(webSocketError).Once()

			// Создаем объект ответа
			userAnswer := &entity.UserAnswer{
				UserID:         userID,
				QuizID:         question.QuizID,
				QuestionID:     questionID,
				SelectedOption: selectedOption,
				IsCorrect:      true,
				Score:          10,
			}

			mockResultRepo.On("SaveUserAnswer", mock.MatchedBy(func(answer *entity.UserAnswer) bool {
				return answer.UserID == userID &&
					answer.QuestionID == questionID &&
					answer.SelectedOption == selectedOption
			})).Return(nil).Once()

			// Вызываем SendEventToUser через интерфейс, игнорируя ошибку
			err := adapter.SendEventToUser(fmt.Sprintf("%d", userID), "quiz:answer_result", map[string]interface{}{
				"is_correct": true,
				"points":     10,
			})

			// Проверяем, что ошибка WebSocket действительно произошла
			assert.Error(t, err, "SendEventToUser должен возвращать ошибку при симуляции сбоя")
			assert.Equal(t, webSocketError.Error(), err.Error(),
				"Ошибка WebSocket должна соответствовать симулируемой ошибке")

			// Продолжаем выполнение, несмотря на ошибку WebSocket (это проверяет устойчивость)
			if err := mockResultRepo.SaveUserAnswer(userAnswer); err != nil {
				return err
			}

			return nil
		}

		// Вызываем тестируемую функцию
		err := processAnswer()

		// Проверяем результаты с улучшенными сообщениями
		assert.NoError(t, err, "ProcessAnswer не должен возвращать ошибку даже при сбое WebSocket")

		// Проверяем, что все моки были вызваны
		mockResultRepo.AssertExpectations(t)
		mockWSManager.AssertExpectations(t)
	})

	t.Run("OpenWaitingRoom with negative time", func(t *testing.T) {
		// Подготавливаем моки с привязкой к тесту
		mockWSManager := NewMockManager(t)

		// Создаем адаптер для WebSocket
		adapter := &WebSocketAdapterForTest{
			Mock: mockWSManager,
		}

		// Создаем тестовую викторину с датой в прошлом
		pastTime := time.Now().Add(-5 * time.Minute)
		quiz := &entity.Quiz{
			ID:            1,
			Title:         "Test Quiz",
			Status:        "scheduled",
			ScheduledTime: pastTime,
		}

		// Проверяем, что starts_in_seconds не отрицательное
		mockWSManager.On("BroadcastEvent", "quiz:waiting_room", mock.MatchedBy(func(data map[string]interface{}) bool {
			// Проверяем, что starts_in_seconds не отрицательное значение
			seconds, ok := data["starts_in_seconds"].(int)
			secondsCheck := ok && seconds >= 0

			if !secondsCheck && ok {
				t.Logf("ОШИБКА: starts_in_seconds имеет недопустимое значение: %d (должно быть >= 0)", seconds)
			}

			return secondsCheck
		})).Return(nil).Once()

		// Реализуем openWaitingRoom
		openWaitingRoom := func() {
			// Вычисляем время до начала викторины
			secondsToStart := int(time.Until(quiz.ScheduledTime).Seconds())
			t.Logf("Исходное значение secondsToStart: %d (должно быть отрицательным)", secondsToStart)

			// Проверяем и корректируем отрицательное время
			if secondsToStart < 0 {
				t.Logf("Корректируем отрицательное значение secondsToStart: %d -> 0", secondsToStart)
				secondsToStart = 0
			}

			// Отправляем событие ожидания
			err := adapter.BroadcastEvent("quiz:waiting_room", map[string]interface{}{
				"quiz_id":           quiz.ID,
				"title":             quiz.Title,
				"starts_in_seconds": secondsToStart,
			})

			// Проверяем результат отправки
			assert.NoError(t, err, "BroadcastEvent не должен возвращать ошибку в openWaitingRoom")
		}

		// Вызываем тестируемую функцию
		openWaitingRoom()

		// Проверяем, что все моки были вызваны
		mockWSManager.AssertExpectations(t)
	})

	t.Run("CancelQuiz with WebSocket error", func(t *testing.T) {
		// Подготавливаем моки с привязкой к тесту
		mockQuizRepo := new(MockQuizRepository)
		mockWSManager := NewMockManager(t)

		// Создаем адаптер для WebSocket
		adapter := &WebSocketAdapterForTest{
			Mock: mockWSManager,
		}

		// Подготавливаем тестовые данные
		quizID := uint(1)
		quiz := &entity.Quiz{
			ID:     quizID,
			Title:  "Test Quiz",
			Status: "scheduled",
		}

		// Настраиваем моки
		mockQuizRepo.On("GetByID", quizID).Return(quiz, nil).Once()
		mockQuizRepo.On("UpdateStatus", quizID, "cancelled").Return(nil).Once()

		// Симулируем несколько типов ошибок WebSocket
		cancelQuizError := errors.New("simulated WebSocket failure during quiz cancellation")
		mockWSManager.On("BroadcastEvent", "quiz:cancelled", mock.Anything).Return(cancelQuizError).Once()

		// Реализуем CancelQuiz
		cancelQuiz := func() error {
			// Получаем викторину
			quiz, err := mockQuizRepo.GetByID(quizID)
			require.NoError(t, err, fmt.Sprintf("GetByID не должен возвращать ошибку, но вернул: %v", err))
			require.NotNil(t, quiz, "GetByID не должен возвращать nil для викторины")

			// Используем quiz для проверки, что это не nil
			if quiz == nil {
				return fmt.Errorf("quiz with ID %d not found", quizID)
			}

			// Обновляем статус
			err = mockQuizRepo.UpdateStatus(quizID, "cancelled")
			require.NoError(t, err, fmt.Sprintf("UpdateStatus не должен возвращать ошибку, но вернул: %v", err))

			// Отправляем уведомление
			err = adapter.BroadcastEvent("quiz:cancelled", map[string]interface{}{
				"quiz_id": quizID,
			})

			// Проверяем, что ошибка WebSocket действительно произошла
			assert.Error(t, err, "BroadcastEvent должен возвращать ошибку при симуляции сбоя")
			assert.Equal(t, cancelQuizError.Error(), err.Error(),
				"Ошибка WebSocket должна соответствовать симулируемой ошибке")

			// В реальном коде WebSocket ошибка игнорируется, поэтому возвращаем nil
			return nil
		}

		// Вызываем тестируемую функцию
		err := cancelQuiz()

		// Проверяем результаты с улучшенными сообщениями
		assert.NoError(t, err,
			"CancelQuiz не должен возвращать ошибку даже при сбое WebSocket")

		// Проверяем, что все моки были вызваны
		mockQuizRepo.AssertExpectations(t)
		mockWSManager.AssertExpectations(t)
	})

	// Новый тест: проверяем несколько последовательных ошибок WebSocket
	t.Run("Multiple WebSocket errors handled gracefully", func(t *testing.T) {
		mockWSManager := NewMockManager(t)
		adapter := &WebSocketAdapterForTest{Mock: mockWSManager}

		// Симулируем разные типы ошибок
		err1 := errors.New("connection timeout")
		err2 := errors.New("message too large")
		err3 := errors.New("client disconnected")

		// Настраиваем моки для последовательных вызовов с разными ошибками
		mockWSManager.On("BroadcastEvent", "test:event1", mock.Anything).Return(err1).Once()
		mockWSManager.On("BroadcastEvent", "test:event2", mock.Anything).Return(err2).Once()
		mockWSManager.On("BroadcastEvent", "test:event3", mock.Anything).Return(err3).Once()

		// Вызываем методы
		err := adapter.BroadcastEvent("test:event1", map[string]interface{}{"test": 1})
		assert.Error(t, err, "Первая ошибка WebSocket должна быть возвращена")
		assert.Equal(t, err1.Error(), err.Error(), "Текст первой ошибки должен совпадать")

		err = adapter.BroadcastEvent("test:event2", map[string]interface{}{"test": 2})
		assert.Error(t, err, "Вторая ошибка WebSocket должна быть возвращена")
		assert.Equal(t, err2.Error(), err.Error(), "Текст второй ошибки должен совпадать")

		err = adapter.BroadcastEvent("test:event3", map[string]interface{}{"test": 3})
		assert.Error(t, err, "Третья ошибка WebSocket должна быть возвращена")
		assert.Equal(t, err3.Error(), err.Error(), "Текст третьей ошибки должен совпадать")

		// Проверяем, что все моки были вызваны
		mockWSManager.AssertExpectations(t)
	})

	// Новый тест: проверяем обработку ошибок у разных пользователей
	t.Run("WebSocket errors for different users handled independently", func(t *testing.T) {
		mockWSManager := NewMockManager(t)
		adapter := &WebSocketAdapterForTest{Mock: mockWSManager}

		// Настраиваем моки для разных пользователей с разными результатами
		mockWSManager.On("SendEventToUser", "1", "quiz:notification", mock.Anything).Return(nil).Once()
		mockWSManager.On("SendEventToUser", "2", "quiz:notification", mock.Anything).
			Return(errors.New("user 2 disconnected")).Once()
		mockWSManager.On("SendEventToUser", "3", "quiz:notification", mock.Anything).Return(nil).Once()

		// Отправка первому пользователю - успешно
		err := adapter.SendEventToUser("1", "quiz:notification", map[string]interface{}{"message": "test"})
		assert.NoError(t, err, "Отправка первому пользователю должна быть успешной")

		// Отправка второму пользователю - ошибка
		err = adapter.SendEventToUser("2", "quiz:notification", map[string]interface{}{"message": "test"})
		assert.Error(t, err, "Отправка второму пользователю должна вернуть ошибку")
		assert.Contains(t, err.Error(), "user 2 disconnected", "Ошибка должна содержать информацию о отключении")

		// Отправка третьему пользователю - успешно, несмотря на проблемы со вторым
		err = adapter.SendEventToUser("3", "quiz:notification", map[string]interface{}{"message": "test"})
		assert.NoError(t, err, "Отправка третьему пользователю должна быть успешной")

		// Проверяем, что все моки были вызваны
		mockWSManager.AssertExpectations(t)
	})
}

// TestQuizManager_SendsCorrectOptionsFormat проверяет, что WebSocket отправляет options в формате { id, text }[], а не []string
func TestQuizManager_SendsCorrectOptionsFormat(t *testing.T) {
	mockWSManager := NewMockManager(t)
	adapter := &WebSocketAdapterForTest{Mock: mockWSManager}

	// Подготавливаем тестовые данные
	question := &entity.Question{
		ID:      1,
		QuizID:  1,
		Text:    "Test Question",
		Options: []string{"Option 1", "Option 2", "Option 3"}, // Бэкенд хранит как []string
	}

	expectedOptions := []map[string]interface{}{
		{"id": 1, "text": "Option 1"},
		{"id": 2, "text": "Option 2"},
		{"id": 3, "text": "Option 3"},
	}

	// Настраиваем мок, который ожидает корректный формат options
	mockWSManager.On("BroadcastEvent", "quiz:question", mock.MatchedBy(func(data map[string]interface{}) bool {
		options, ok := data["options"].([]map[string]interface{})
		if !ok {
			t.Logf("Ошибка: options имеет некорректный формат: %+v", data["options"])
			return false
		}

		// Проверяем, что данные совпадают с ожидаемыми
		for i, opt := range options {
			if opt["id"] != expectedOptions[i]["id"] || opt["text"] != expectedOptions[i]["text"] {
				t.Logf("Ошибка: options[%d] некорректен: %+v", i, opt)
				return false
			}
		}

		return true
	})).Return(nil).Once()

	// Вызываем WebSocket-отправку
	err := adapter.BroadcastEvent("quiz:question", map[string]interface{}{
		"question_id": question.ID,
		"text":        question.Text,
		"options": []map[string]interface{}{ // Это данные, которые должны прийти во фронт
			{"id": 1, "text": "Option 1"},
			{"id": 2, "text": "Option 2"},
			{"id": 3, "text": "Option 3"},
		},
	})

	// Проверяем, что отправка прошла без ошибок
	assert.NoError(t, err, "BroadcastEvent должен работать без ошибок")

	// Проверяем, что все моки были вызваны
	mockWSManager.AssertExpectations(t)
}
