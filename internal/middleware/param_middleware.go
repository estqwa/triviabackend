package middleware

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// ExtractUintParam создает middleware для извлечения и валидации числового параметра URL.
// paramName - имя параметра в URL (например, "id").
// contextKey - ключ, под которым значение будет сохранено в контексте Gin.
func ExtractUintParam(paramName, contextKey string) gin.HandlerFunc {
	return func(c *gin.Context) {
		idStr := c.Param(paramName)
		id, err := strconv.ParseUint(idStr, 10, 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid %s", paramName)})
			c.Abort()
			return
		}
		// Сохраняем как uint для единообразия
		c.Set(contextKey, uint(id))
		c.Next()
	}
}
