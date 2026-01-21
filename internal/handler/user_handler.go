package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/trivia-api/internal/service"
)

// UserHandler обрабатывает запросы, связанные с пользователями
type UserHandler struct {
	userService *service.UserService
}

// NewUserHandler создает новый обработчик пользователей
func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{
		userService: userService,
	}
}

// GetLeaderboard обрабатывает запрос на получение лидерборда
func (h *UserHandler) GetLeaderboard(c *gin.Context) {
	// Получаем параметры пагинации из query
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	pageSize, err := strconv.Atoi(pageSizeStr)
	if err != nil || pageSize < 1 {
		pageSize = 10 // Значение по умолчанию
	} else if pageSize > 100 {
		pageSize = 100 // Максимальный лимит
	}

	// Вызываем сервис
	leaderboard, err := h.userService.GetLeaderboard(page, pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error getting leaderboard"})
		return
	}

	c.JSON(http.StatusOK, leaderboard)
}
