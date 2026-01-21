package entity

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"
)

// StringArray - пользовательский тип для работы с JSONB
type StringArray []string

// Scan реализует интерфейс sql.Scanner для StringArray
// Используется GORM для чтения JSONB данных из базы
func (o *StringArray) Scan(value interface{}) error {
	// Обработка NULL значений из базы данных
	if value == nil {
		*o = StringArray{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSONB value: expected []byte")
	}

	// Обработка пустого массива байтов
	if len(bytes) == 0 {
		*o = StringArray{}
		return nil
	}

	return json.Unmarshal(bytes, o)
}

// Value реализует интерфейс driver.Valuer для StringArray
// Используется GORM для записи StringArray в JSONB в базе
func (o StringArray) Value() (driver.Value, error) {
	if o == nil || len(o) == 0 {
		return []byte("[]"), nil // Возвращаем пустой JSON массив вместо null
	}
	return json.Marshal(o)
}

// Question представляет вопрос в викторине
type Question struct {
	ID            uint        `gorm:"primaryKey" json:"id"`
	QuizID        uint        `gorm:"not null;index" json:"quiz_id"`
	Text          string      `gorm:"size:500;not null" json:"text"`
	Options       StringArray `gorm:"type:jsonb;not null" json:"options"`
	CorrectOption int         `gorm:"not null" json:"-"` // Скрыто от клиента
	TimeLimitSec  int         `gorm:"not null;default:10" json:"time_limit_sec"`
	PointValue    int         `gorm:"not null;default:10" json:"point_value"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// TableName определяет имя таблицы для GORM
func (Question) TableName() string {
	return "questions"
}

// IsCorrect проверяет, является ли выбранный вариант правильным
func (q *Question) IsCorrect(selectedOption int) bool {
	return selectedOption == q.CorrectOption
}

// CalculatePoints рассчитывает очки за ответ на вопрос.
// Возвращает 1 за правильный ответ, 0 за неправильный.
// responseTimeMs сохранён для совместимости API (может использоваться в будущем для бонусов за скорость)
func (q *Question) CalculatePoints(isCorrect bool, responseTimeMs int64) int {
	if !isCorrect {
		return 0
	}
	return 1
}

// OptionsCount возвращает количество вариантов ответа
func (q *Question) OptionsCount() int {
	return len(q.Options)
}

// IsValidOption проверяет, является ли выбранный вариант допустимым
func (q *Question) IsValidOption(selectedOption int) bool {
	return selectedOption >= 0 && selectedOption < len(q.Options)
}
