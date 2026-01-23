package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	gorillaws "github.com/gorilla/websocket"
	"github.com/yourusername/trivia-api/internal/service"
	"github.com/yourusername/trivia-api/internal/websocket"
	"github.com/yourusername/trivia-api/pkg/auth"
)

// WSHandler обрабатывает WebSocket соединения
type WSHandler struct {
	wsHub       websocket.HubInterface
	wsManager   *websocket.Manager
	quizManager *service.QuizManager
	jwtService  *auth.JWTService
}

// NewWSHandler создает новый обработчик WebSocket
func NewWSHandler(
	wsHub websocket.HubInterface,
	wsManager *websocket.Manager,
	quizManager *service.QuizManager,
	jwtService *auth.JWTService,
) *WSHandler {
	handler := &WSHandler{
		wsHub:       wsHub,
		wsManager:   wsManager,
		quizManager: quizManager,
		jwtService:  jwtService,
	}

	// Регистрируем обработчики сообщений один раз при создании обработчика
	handler.registerMessageHandlers()

	return handler
}

var upgrader = gorillaws.Upgrader{
	ReadBufferSize:  4096, // Увеличено с 1024 для лучшей производительности при 10k+ пользователей
	WriteBufferSize: 4096, // Увеличено с 1024 для лучшей производительности при 10k+ пользователей
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")

		// Если Origin пустой - это не браузерный клиент (мобильное приложение, curl и т.д.)
		// Разрешаем такие подключения
		if origin == "" {
			return true
		}

		// Список разрешенных origin (синхронизирован с CORS в main.go)
		// При добавлении новых доменов - добавьте их также в CORS config
		allowedOrigins := []string{
			"https://triviafront.vercel.app",
			"https://triviafrontadmin.vercel.app",
			"http://localhost:5173",
			"http://localhost:8000",
			"http://localhost:3000",
		}

		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}

		log.Printf("WebSocket: rejected unauthorized origin: %s", origin)
		return false
	},
	// Добавляем заголовки для CORS
	EnableCompression: true,
}

// HandleConnection обрабатывает входящее WebSocket соединение
func (h *WSHandler) HandleConnection(c *gin.Context) {
	// Получаем тикет из запроса (?ticket=... а не ?token=...)
	ticket := c.Query("ticket")
	// НЕ логируем тикет - это секретные данные аутентификации

	if ticket == "" {
		// Попробуем также проверить параметр 'token' для обратной совместимости, если нужно
		// ticket = c.Query("token")
		// if ticket == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing authentication ticket parameter"})
		return
		// }
	}

	// Проверяем тикет с использованием специальной функции ParseWSTicket
	claims, err := h.jwtService.ParseWSTicket(ticket)
	if err != nil {
		log.Printf("WebSocket: Invalid or expired ticket - %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired ticket"})
		return
	}

	// Логируем все заголовки запроса
	log.Printf("WebSocket: Request headers:")
	for name, values := range c.Request.Header {
		for _, value := range values {
			log.Printf("  %s: %s", name, value)
		}
	}

	// Устанавливаем соединение
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("Error upgrading connection: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to upgrade: %v", err)})
		return
	}

	log.Printf("WebSocket: Connection upgraded for UserID: %d", claims.UserID)

	// Создаем нового клиента
	client := websocket.NewClient(h.wsHub, conn, fmt.Sprintf("%d", claims.UserID))

	// Запускаем прослушивание сообщений
	client.StartPumps(h.wsManager.HandleMessage)
}

// registerMessageHandlers регистрирует обработчики для различных типов сообщений
func (h *WSHandler) registerMessageHandlers() {
	// Обработчик для события готовности пользователя
	h.wsManager.RegisterHandler("user:ready", func(data json.RawMessage, client *websocket.Client) error {
		var readyEvent struct {
			QuizID uint `json:"quiz_id"`
		}
		// Ошибка парсинга - фатальна для этого сообщения
		if err := json.Unmarshal(data, &readyEvent); err != nil {
			log.Printf("[WSHandler] Ошибка парсинга user:ready: %v, Data: %s", err, string(data))
			// Отправляем ошибку клиенту перед закрытием
			h.wsManager.SendErrorToClient(client, "invalid_format", "Failed to parse user:ready event")
			return fmt.Errorf("failed to parse user:ready event: %w", err)
		}

		// Устанавливаем QuizID у клиента
		client.SetQuizID(readyEvent.QuizID)
		log.Printf("[WSHandler] User %s set QuizID to %d", client.UserID, readyEvent.QuizID)

		// ===>>> ДОБАВИТЬ ВЫЗОВ ПОДПИСКИ <<<===
		if err := h.wsManager.SubscribeClientToQuiz(client, readyEvent.QuizID); err != nil {
			// Логируем ошибку подписки, но не обязательно закрывать соединение
			log.Printf("[WSHandler] Ошибка при подписке User %s на Quiz %d: %v", client.UserID, readyEvent.QuizID, err)
			// Можно отправить ошибку клиенту
			h.wsManager.SendErrorToClient(client, "subscribe_error", fmt.Sprintf("Failed to subscribe to quiz %d", readyEvent.QuizID))
			// return err // Не возвращаем ошибку, чтобы не закрывать соединение сразу
		}
		// ===>>> КОНЕЦ ИЗМЕНЕНИЯ <<<===

		// Получаем UserID клиента
		userID, err := h.parseUserID(client)
		if err != nil {
			return err // Ошибка парсинга ID фатальна
		}

		// Вызываем QuizManager, логируем ошибку, но не закрываем соединение
		if err := h.quizManager.HandleReadyEvent(userID, readyEvent.QuizID); err != nil {
			log.Printf("[WSHandler] Ошибка при обработке HandleReadyEvent для пользователя %d, викторины %d: %v", userID, readyEvent.QuizID, err)
			// Опционально: отправить ошибку клиенту
			h.wsManager.SendErrorToClient(client, "ready_error", err.Error())
		}
		return nil // Возвращаем nil, чтобы не закрывать соединение
	})

	// Обработчик для события ответа на вопрос
	h.wsManager.RegisterHandler("user:answer", func(data json.RawMessage, client *websocket.Client) error {
		var answerEvent struct {
			QuestionID     uint  `json:"question_id"`
			SelectedOption int   `json:"selected_option"`
			Timestamp      int64 `json:"timestamp"`
		}
		// Ошибка парсинга - фатальна
		if err := json.Unmarshal(data, &answerEvent); err != nil {
			log.Printf("[WSHandler] Ошибка парсинга user:answer: %v, Data: %s", err, string(data))
			h.wsManager.SendErrorToClient(client, "invalid_format", "Failed to parse user:answer event")
			return err
		}

		// Получаем UserID
		userID, err := h.parseUserID(client)
		if err != nil {
			return err // Ошибка парсинга ID фатальна
		}

		// Вызываем QuizManager, логируем ошибку, но не закрываем соединение
		if err := h.quizManager.ProcessAnswer(
			userID,
			answerEvent.QuestionID,
			answerEvent.SelectedOption,
			answerEvent.Timestamp,
		); err != nil {
			log.Printf("[WSHandler] Ошибка при обработке ProcessAnswer для пользователя %d, вопроса %d: %v", userID, answerEvent.QuestionID, err)
			// Отправляем специфичную ошибку клиенту
			h.wsManager.SendErrorToClient(client, "answer_error", err.Error())
		}
		return nil // Возвращаем nil, чтобы не закрывать соединение
	})

	// Обработчик для проверки соединения
	h.wsManager.RegisterHandler("user:heartbeat", func(data json.RawMessage, client *websocket.Client) error {
		// Отправляем ответ клиенту
		heartbeatResponse := map[string]interface{}{
			"timestamp": time.Now().UnixNano() / int64(time.Millisecond),
		}
		// Ошибка отправки здесь может быть проигнорирована или залогирована
		if err := h.wsManager.SendEventToUser(client.UserID, "server:heartbeat", heartbeatResponse); err != nil {
			log.Printf("[WSHandler] WARNING: Ошибка при отправке server:heartbeat пользователю %s: %v", client.UserID, err)
		}
		return nil // Никогда не закрываем соединение из-за heartbeat
	})
}

// --- Вспомогательные методы ---

// parseUserID извлекает и парсит UserID из клиента
func (h *WSHandler) parseUserID(client *websocket.Client) (uint, error) {
	userIDUint64, err := strconv.ParseUint(client.UserID, 10, 32)
	if err != nil {
		log.Printf("[WSHandler] CRITICAL: Ошибка конвертации UserID '%s' в uint: %v", client.UserID, err)
		h.wsManager.SendErrorToClient(client, "internal_error", "Invalid user ID format")
		return 0, fmt.Errorf("failed to parse user ID: %w", err) // Фатальная ошибка
	}
	return uint(userIDUint64), nil
}
