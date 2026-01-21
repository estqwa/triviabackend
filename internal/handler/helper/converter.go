package helper

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// QuestionOption представляет вариант ответа для фронтенда (перенесено из DTO)
type QuestionOption struct {
	ID   int    `json:"id"`
	Text string `json:"text"`
}

// ConvertOptionsToObjects преобразует массив строк в массив объектов с id и text
// ID использует 0-based индексацию для совместимости с CorrectOption в базе данных
func ConvertOptionsToObjects(options entity.StringArray) []QuestionOption {
	converted := make([]QuestionOption, len(options))
	for i, opt := range options {
		// Добавляем дополнительную проверку на пустые строки
		if opt == "" {
			opt = "(пустой вариант)"
		}
		converted[i] = QuestionOption{ID: i, Text: opt} // 0-based ID для совместимости с CorrectOption
	}
	return converted
}
