package quizmanager

import (
	"context"
	"sync"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
	"github.com/yourusername/trivia-api/internal/websocket"
)

// Constants for default values
const (
	DefaultMaxQuizQuestions = 10
	DefaultTotalPrizeFund   = 1000000 // Пример призового фонда
)

// Config содержит настройки для всех компонентов QuizManager
type Config struct {
	// Таймауты и интервалы
	AnnouncementMinutes  int           // За сколько минут отправлять анонс викторины
	WaitingRoomMinutes   int           // За сколько минут открывать зал ожидания
	CountdownSeconds     int           // Продолжительность обратного отсчета в секундах
	QuestionDelayMs      int           // Задержка перед отправкой вопроса
	AnswerRevealDelayMs  int           // Задержка перед отправкой правильного ответа
	InterQuestionDelayMs int           // Задержка между вопросами
	RetryInterval        time.Duration // Интервал между повторными попытками отправки

	// Настройки автозаполнения вопросов
	AutoFillThreshold   int // За сколько минут до начала выполнять автозаполнение
	MaxQuestionsPerQuiz int // Максимальное количество вопросов в викторине

	// Настройки ответов
	MaxResponseTimeMs int64 // Максимальное время ответа в мс
	EliminationTimeMs int64 // Время ответа, после которого пользователь выбывает

	// Максимальное количество попыток отправки сообщений
	MaxRetries int

	// Настройки призового фонда
	TotalPrizeFund int // Общий призовой фонд
}

// DefaultConfig возвращает конфигурацию по умолчанию
func DefaultConfig() *Config {
	return &Config{
		AnnouncementMinutes:  30,
		WaitingRoomMinutes:   5,
		CountdownSeconds:     60,
		QuestionDelayMs:      500,
		AnswerRevealDelayMs:  200,
		InterQuestionDelayMs: 500,
		RetryInterval:        500 * time.Millisecond,
		AutoFillThreshold:    2,
		MaxQuestionsPerQuiz:  DefaultMaxQuizQuestions, // Используем константу
		MaxResponseTimeMs:    30000,                   // 30 секунд
		EliminationTimeMs:    10000,                   // 10 секунд
		MaxRetries:           3,
		TotalPrizeFund:       DefaultTotalPrizeFund, // Используем константу
	}
}

// ResultService определяет интерфейс для методов сервиса результатов,
// необходимых QuizManager.
type ResultService interface {
	DetermineWinnersAndAllocatePrizes(ctx context.Context, quizID uint) error
	// Добавьте другие методы ResultService, если они вызываются из QuizManager
}

// Dependencies содержит зависимости для QuizManager
type Dependencies struct {
	QuizRepo      repository.QuizRepository
	QuestionRepo  repository.QuestionRepository
	ResultRepo    repository.ResultRepository
	ResultService ResultService // Используем интерфейс
	CacheRepo     repository.CacheRepository
	WSManager     *websocket.Manager
	Config        *Config // Добавляем конфиг в зависимости
}

// ActiveQuizState хранит состояние активной викторины
type ActiveQuizState struct {
	Quiz                       *entity.Quiz
	CurrentQuestion            *entity.Question
	CurrentQuestionNumber      int
	CurrentQuestionStartTimeMs int64 // Добавляем время старта текущего вопроса (Unix ms)
	Mu                         sync.RWMutex
}

// NewActiveQuizState создает новое состояние активной викторины
func NewActiveQuizState(quiz *entity.Quiz) *ActiveQuizState {
	return &ActiveQuizState{
		Quiz: quiz,
	}
}

// SetCurrentQuestion устанавливает текущий вопрос
func (s *ActiveQuizState) SetCurrentQuestion(question *entity.Question, number int) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.CurrentQuestion = question
	s.CurrentQuestionNumber = number
}

// GetCurrentQuestion возвращает текущий вопрос
func (s *ActiveQuizState) GetCurrentQuestion() (*entity.Question, int) {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.CurrentQuestion, s.CurrentQuestionNumber
}

// SetCurrentQuestionStartTime устанавливает время начала текущего вопроса
func (s *ActiveQuizState) SetCurrentQuestionStartTime(startTimeMs int64) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.CurrentQuestionStartTimeMs = startTimeMs
}

// GetCurrentQuestionStartTime возвращает время начала текущего вопроса
func (s *ActiveQuizState) GetCurrentQuestionStartTime() int64 {
	s.Mu.RLock()
	defer s.Mu.RUnlock()
	return s.CurrentQuestionStartTimeMs
}

// ClearCurrentQuestion очищает текущий вопрос и время его старта
func (s *ActiveQuizState) ClearCurrentQuestion() {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.CurrentQuestion = nil
	s.CurrentQuestionNumber = 0
	s.CurrentQuestionStartTimeMs = 0
}
