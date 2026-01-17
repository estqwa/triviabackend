package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/handler/dto"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"github.com/yourusername/trivia-api/internal/service"
)

// QuizHandler обрабатывает запросы, связанные с викторинами
type QuizHandler struct {
	quizService   *service.QuizService
	resultService *service.ResultService
	quizManager   *service.QuizManager
}

// NewQuizHandler создает новый обработчик викторин
func NewQuizHandler(
	quizService *service.QuizService,
	resultService *service.ResultService,
	quizManager *service.QuizManager,
) *QuizHandler {
	return &QuizHandler{
		quizService:   quizService,
		resultService: resultService,
		quizManager:   quizManager,
	}
}

// CreateQuizRequest представляет запрос на создание викторины
type CreateQuizRequest struct {
	Title         string    `json:"title" binding:"required,min=3,max=100"`
	Description   string    `json:"description" binding:"omitempty,max=500"`
	ScheduledTime time.Time `json:"scheduled_time" binding:"required"`
}

// CreateQuiz обрабатывает запрос на создание викторины
func (h *QuizHandler) CreateQuiz(c *gin.Context) {
	var req CreateQuizRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	quiz, err := h.quizService.CreateQuiz(req.Title, req.Description, req.ScheduledTime)
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dto.NewQuizResponse(quiz, false))
}

// GetQuiz возвращает информацию о викторине
func (h *QuizHandler) GetQuiz(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	quiz, err := h.quizService.GetQuizByID(quizID)
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.NewQuizResponse(quiz, false))
}

// GetActiveQuiz возвращает информацию об активной викторине
func (h *QuizHandler) GetActiveQuiz(c *gin.Context) {
	// Проверяем сначала в QuizManager
	activeQuiz := h.quizManager.GetActiveQuiz()
	if activeQuiz != nil {
		c.JSON(http.StatusOK, dto.NewQuizResponse(activeQuiz, false))
		return
	}

	// Если не найдена активная викторина у менеджера, ищем в БД
	quiz, err := h.quizService.GetActiveQuiz()
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.NewQuizResponse(quiz, false))
}

// GetScheduledQuizzes возвращает список запланированных викторин
func (h *QuizHandler) GetScheduledQuizzes(c *gin.Context) {
	quizzes, err := h.quizService.GetScheduledQuizzes()
	if err != nil {
		log.Printf("[QuizHandler] Ошибка при получении запланированных викторин: %v", err)
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.NewListQuizResponse(quizzes))
}

// AddQuestionsRequest представляет запрос на добавление вопросов
type AddQuestionsRequest struct {
	Questions []struct {
		Text          string   `json:"text" binding:"required,min=3,max=500"`
		Options       []string `json:"options" binding:"required,min=2,max=5"`
		CorrectOption int64    `json:"correct_option" binding:"required,min=0"`
		TimeLimitSec  int64    `json:"time_limit_sec" binding:"required,min=5,max=60"`
		PointValue    int64    `json:"point_value" binding:"required,min=1,max=100"`
	} `json:"questions" binding:"required,min=1"`
}

// AddQuestions обрабатывает запрос на добавление вопросов к викторине
func (h *QuizHandler) AddQuestions(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	var req AddQuestionsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Преобразуем данные в формат для сервиса
	questions := make([]entity.Question, 0, len(req.Questions))
	for _, q := range req.Questions {
		if q.CorrectOption < 0 || q.CorrectOption >= int64(len(q.Options)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid correct_option index %d for question '%s'", q.CorrectOption, q.Text)})
			return
		}
		questions = append(questions, entity.Question{
			Text:          q.Text,
			Options:       entity.StringArray(q.Options),
			CorrectOption: q.CorrectOption,
			TimeLimitSec:  q.TimeLimitSec,
			PointValue:    q.PointValue,
		})
	}

	if err := h.quizService.AddQuestions(quizID, questions); err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Questions added successfully"})
}

// ScheduleQuizRequest представляет запрос на планирование викторины
type ScheduleQuizRequest struct {
	ScheduledTime time.Time `json:"scheduled_time" binding:"required"`
}

// ScheduleQuiz обрабатывает запрос на планирование времени викторины
func (h *QuizHandler) ScheduleQuiz(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	var req ScheduleQuizRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Сначала обновляем время в базе данных
	if err := h.quizService.ScheduleQuiz(quizID, req.ScheduledTime); err != nil {
		h.handleQuizError(c, err)
		return
	}

	// Затем планируем викторину через QuizManager
	if err := h.quizManager.ScheduleQuiz(quizID, req.ScheduledTime); err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Quiz scheduled successfully"})
}

// CancelQuiz обрабатывает запрос на отмену викторины
func (h *QuizHandler) CancelQuiz(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	if err := h.quizManager.CancelQuiz(quizID); err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Quiz cancelled successfully"})
}

// GetQuizWithQuestions возвращает викторину вместе с вопросами
func (h *QuizHandler) GetQuizWithQuestions(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	quiz, err := h.quizService.GetQuizWithQuestions(quizID)
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	response := dto.NewQuizResponse(quiz, true)

	c.JSON(http.StatusOK, response)
}

// GetQuizResults возвращает пагинированные результаты викторины
func (h *QuizHandler) GetQuizResults(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	// Получаем параметры пагинации из query
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10 // Можно взять из конфига
	}

	// Вызываем сервис с пагинацией
	results, total, err := h.resultService.GetQuizResults(quizID, page, pageSize)
	if err != nil {
		h.handleQuizError(c, err) // Используем стандартизированный обработчик
		return
	}

	// Возвращаем пагинированный DTO
	c.JSON(http.StatusOK, dto.NewPaginatedResultResponse(results, total, page, pageSize))
}

// GetUserQuizResult возвращает результат пользователя для конкретной викторины
func (h *QuizHandler) GetUserQuizResult(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем из контекста

	// Получаем ID пользователя из контекста
	userIDRaw, exists := c.Get("user_id")
	if !exists {
		h.handleQuizError(c, apperrors.ErrUnauthorized)
		return
	}
	userID, ok := userIDRaw.(uint)
	if !ok {
		h.handleQuizError(c, errors.New("invalid user ID in context"))
		return
	}

	result, err := h.resultService.GetUserResult(userID, quizID)
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.NewResultResponse(result))
}

// ListQuizzes возвращает список викторин с пагинацией
func (h *QuizHandler) ListQuizzes(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}

	quizzes, err := h.quizService.ListQuizzes(page, pageSize)
	if err != nil {
		h.handleQuizError(c, err)
		return
	}

	c.JSON(http.StatusOK, dto.NewListQuizResponse(quizzes))
}

// DuplicateQuizRequest представляет запрос на дублирование викторины
type DuplicateQuizRequest struct {
	ScheduledTime time.Time `json:"scheduled_time" binding:"required"`
}

// DuplicateQuiz обрабатывает запрос на дублирование существующей викторины.
func (h *QuizHandler) DuplicateQuiz(c *gin.Context) {
	quizID := c.MustGet("quizID").(uint) // Получаем ID оригинальной викторины из контекста

	var req DuplicateQuizRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Неверный формат запроса: %v", err)})
		return
	}

	// Вызываем сервис для дублирования
	newQuiz, err := h.quizService.DuplicateQuiz(quizID, req.ScheduledTime)
	if err != nil {
		// Используем стандартизированный обработчик ошибок
		h.handleQuizError(c, err)
		return
	}

	// !!! ВАЖНО: После успешного создания дубликата, его нужно запланировать в QuizManager !!!
	if err := h.quizManager.ScheduleQuiz(newQuiz.ID, newQuiz.ScheduledTime); err != nil {
		// Логируем ошибку планирования, но не отменяем создание
		// Викторина создана в БД, но может не запуститься автоматически без перезапуска
		log.Printf("[QuizHandler] ВНИМАНИЕ: Не удалось автоматически запланировать дубликат викторины #%d: %v", newQuiz.ID, err)
		// Можно опционально вернуть предупреждение клиенту, но основной результат - создание
		// h.handleQuizError(c, err) // Не возвращаем ошибку клиенту, т.к. викторина создана
	}

	// Отправляем ответ с данными новой викторины
	// Указываем false, чтобы не включать вопросы в ответ (они только что созданы)
	c.JSON(http.StatusCreated, dto.NewQuizResponse(newQuiz, false))
}

// handleQuizError обрабатывает ошибки от сервисов викторин и отправляет соответствующий HTTP ответ
func (h *QuizHandler) handleQuizError(c *gin.Context, err error) {
	if errors.Is(err, apperrors.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	} else if errors.Is(err, apperrors.ErrConflict) {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
	} else if errors.Is(err, apperrors.ErrValidation) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
	} else if errors.Is(err, apperrors.ErrUnauthorized) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
	} else if errors.Is(err, apperrors.ErrForbidden) {
		c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
	} else {
		log.Printf("ERROR: Internal server error in QuizHandler: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
	}
}
