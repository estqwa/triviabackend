package helper

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
	// "github.com/yourusername/trivia-api/internal/handler/dto" // Убираем импорт DTO
)

// QuestionOption представляет вариант ответа для фронтенда (перенесено из DTO)
type QuestionOption struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
}

// ConvertOptionsToObjects преобразует массив строк в массив объектов с id и text
func ConvertOptionsToObjects(options entity.StringArray) []QuestionOption {
	converted := make([]QuestionOption, len(options))
	for i, opt := range options {
		// Добавляем дополнительную проверку на пустые строки
		if opt == "" {
			opt = "(пустой вариант)"
		}
		converted[i] = QuestionOption{ID: i + 1, Text: opt}
	}
	return converted
}
