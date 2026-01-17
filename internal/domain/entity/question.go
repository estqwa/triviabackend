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
	bytes, ok := value.([]byte)
	if !ok {
		return errors.New("failed to unmarshal JSONB value")
	}

	return json.Unmarshal(bytes, o)
}

// Value реализует интерфейс driver.Valuer для StringArray
// Используется GORM для записи StringArray в JSONB в базе
func (o StringArray) Value() (driver.Value, error) {
	if o == nil {
		return nil, nil
	}
	return json.Marshal(o)
}

// Question представляет вопрос в викторине
type Question struct {
	ID            uint        `gorm:"primaryKey" json:"id"`
	QuizID        uint        `gorm:"not null" json:"quiz_id"`
	Text          string      `gorm:"size:500;not null" json:"text"`
	Options       StringArray `gorm:"type:jsonb;not null" json:"options"`
	CorrectOption int64       `gorm:"not null" json:"-"` // Скрыто от клиента
	TimeLimitSec  int64       `gorm:"not null" json:"time_limit_sec"`
	PointValue    int64       `gorm:"not null" json:"point_value"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
}

// IsCorrect проверяет, является ли выбранный вариант правильным
func (q *Question) IsCorrect(selectedOption int64) bool {
	return selectedOption == q.CorrectOption
}

// CalculatePoints рассчитывает очки за ответ на вопрос.
// ИЗМЕНЕНО: Всегда возвращает 1 за правильный ответ, 0 за неправильный.
func (q *Question) CalculatePoints(isCorrect bool, responseTimeMs int64) int64 {
	if !isCorrect {
		return 0 // Неправильный ответ - 0 очков
	}
	return 1 // Правильный ответ - всегда 1 очко

	/* Старая логика с бонусом за скорость:
	// Защита от деления на ноль и невалидного лимита времени
	if q.TimeLimitSec <= 0 {
		log.Printf("Warning: Question ID %d has invalid TimeLimitSec (%d). Using default 10s.", q.ID, q.TimeLimitSec)
		q.TimeLimitSec = 10 // Устанавливаем значение по умолчанию, чтобы избежать паники
	}

	// Защита от отрицательного времени ответа
	if responseTimeMs < 0 {
		responseTimeMs = 0
	}

	// Максимальные очки, если ответ был дан менее чем за 20% от доступного времени
	maxTime := q.TimeLimitSec * 1000
	timePercent := float64(responseTimeMs) / float64(maxTime)

	if timePercent < 0.2 {
		return q.PointValue
	} else if timePercent < 0.5 {
		return int(float64(q.PointValue) * 0.8)
	} else if timePercent < 0.8 {
		return int(float64(q.PointValue) * 0.6)
	}
	return int(float64(q.PointValue) * 0.4)
	*/
}
