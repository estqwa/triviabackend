package dto

import (
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity" // Используем правильный путь модуля
	"github.com/yourusername/trivia-api/internal/handler/helper"
)

// QuestionResponse представляет вопрос в формате для ответа клиенту
type QuestionResponse struct {
	ID           uint                    `json:"id"`
	QuizID       uint                    `json:"quiz_id"`
	Text         string                  `json:"text"`
	Options      []helper.QuestionOption `json:"options"`
	TimeLimitSec int64                   `json:"time_limit_sec"`
	PointValue   int64                   `json:"point_value"`
	CreatedAt    time.Time               `json:"created_at"`
	UpdatedAt    time.Time               `json:"updated_at"`
}

// QuizResponse представляет викторину в формате для ответа клиенту
type QuizResponse struct {
	ID            uint               `json:"id"`
	Title         string             `json:"title"`
	Description   string             `json:"description,omitempty"`
	ScheduledTime time.Time          `json:"scheduled_time"`
	Status        string             `json:"status"`
	QuestionCount int64              `json:"question_count"`
	Questions     []QuestionResponse `json:"questions,omitempty"` // Слайс DTO вопросов
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// ResultResponse представляет результат викторины в формате для ответа клиенту
type ResultResponse struct {
	ID             uint      `json:"id"`
	UserID         uint      `json:"user_id"`
	QuizID         uint      `json:"quiz_id"`
	Username       string    `json:"username"`
	ProfilePicture string    `json:"profile_picture,omitempty"`
	Score          int64     `json:"score"`
	CorrectAnswers int64     `json:"correct_answers"`
	TotalQuestions int64     `json:"total_questions"`
	Rank           int64     `json:"rank"`
	IsWinner       bool      `json:"is_winner"`
	PrizeFund      int64     `json:"prize_fund"`
	IsEliminated   bool      `json:"is_eliminated"`
	CompletedAt    time.Time `json:"completed_at"`
}

// PaginatedResultResponse представляет пагинированный список результатов
type PaginatedResultResponse struct {
	Results []*ResultResponse `json:"results"`
	Total   int64             `json:"total"`
	Page    int               `json:"page"`
	PerPage int               `json:"per_page"`
}

// NewQuestionResponse создает DTO для вопроса
// Примечание: Эта функция используется внутри NewQuizResponse
func NewQuestionResponse(q *entity.Question) QuestionResponse {
	// Используем хелпер для преобразования опций
	optionsDTO := helper.ConvertOptionsToObjects(q.Options)

	// Логика скрытия CorrectOption остается в вызывающем коде (хэндлере).
	return QuestionResponse{
		ID:           q.ID,
		QuizID:       q.QuizID,
		Text:         q.Text,
		Options:      optionsDTO, // Используем результат хелпера
		TimeLimitSec: q.TimeLimitSec,
		PointValue:   q.PointValue,
		CreatedAt:    q.CreatedAt,
		UpdatedAt:    q.UpdatedAt,
	}
}

// NewQuizResponse создает DTO для викторины
func NewQuizResponse(quiz *entity.Quiz, includeQuestions bool) *QuizResponse {
	if quiz == nil {
		return nil
	}

	var questionsDTO []QuestionResponse
	if includeQuestions {
		questionsDTO = make([]QuestionResponse, len(quiz.Questions))
		for i, q := range quiz.Questions {
			// Важно: передаем указатель на элемент слайса
			// Логика скрытия правильного ответа должна быть здесь или в хендлере
			questionCopy := q // Копируем, чтобы не изменять оригинал
			if !quiz.IsCompleted() {
				questionCopy.CorrectOption = -1 // Скрываем для не завершенных
			}
			questionsDTO[i] = NewQuestionResponse(&questionCopy)
		}
	}

	return &QuizResponse{
		ID:            quiz.ID,
		Title:         quiz.Title,
		Description:   quiz.Description,
		ScheduledTime: quiz.ScheduledTime,
		Status:        string(quiz.Status), // Преобразуем статус в строку
		QuestionCount: quiz.QuestionCount,  // Добавляем поле
		Questions:     questionsDTO,
		CreatedAt:     quiz.CreatedAt,
		UpdatedAt:     quiz.UpdatedAt,
	}
}

// NewResultResponse создает DTO для результата
func NewResultResponse(result *entity.Result) *ResultResponse {
	if result == nil {
		return nil
	}
	return &ResultResponse{
		ID:             result.ID,
		UserID:         result.UserID,
		QuizID:         result.QuizID,
		Username:       result.Username,
		ProfilePicture: result.ProfilePicture,
		Score:          result.Score,
		CorrectAnswers: result.CorrectAnswers,
		TotalQuestions: result.TotalQuestions,
		Rank:           result.Rank,
		IsWinner:       result.IsWinner,
		PrizeFund:      result.PrizeFund,
		IsEliminated:   result.IsEliminated,
		CompletedAt:    result.CompletedAt,
	}
}

// NewListQuizResponse создает слайс DTO для списка викторин
func NewListQuizResponse(quizzes []entity.Quiz) []*QuizResponse {
	list := make([]*QuizResponse, len(quizzes))
	for i, quiz := range quizzes {
		// Передаем false, чтобы не включать вопросы в список
		list[i] = NewQuizResponse(&quiz, false)
	}
	return list
}

// NewListResultResponse создает слайс DTO для списка результатов
func NewListResultResponse(results []entity.Result) []*ResultResponse {
	list := make([]*ResultResponse, len(results))
	for i, result := range results {
		list[i] = NewResultResponse(&result)
	}
	return list
}

// NewPaginatedResultResponse создает DTO для пагинированного списка результатов
func NewPaginatedResultResponse(results []entity.Result, total int64, page, perPage int) *PaginatedResultResponse {
	return &PaginatedResultResponse{
		Results: NewListResultResponse(results),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}
}
