package websocket

import (
	"net/http"
)

// MetricsProvider определяет метод для получения метрик хаба.
type MetricsProvider interface {
	GetMetrics() map[string]interface{}
	ClientCount() int
}

// DetailedInfoProvider определяет метод для получения детальной информации о хабе (для ShardedHub).
type DetailedInfoProvider interface {
	MetricsProvider                             // Включает базовые метрики
	GetDetailedMetrics() map[string]interface{} // Пример расширенного метода
	// Добавить другие методы, если необходимо
}

// HubInterface объединяет возможности для Manager.
// Это каноническое определение интерфейса хаба.
type HubInterface interface {
	// BroadcastJSON отправляет структуру JSON всем клиентам
	BroadcastJSON(v interface{}) error

	// SendJSONToUser отправляет структуру JSON конкретному пользователю
	SendJSONToUser(userID string, v interface{}) error

	// SendToUser отправляет байтовое сообщение конкретному пользователю
	SendToUser(userID string, message []byte) bool

	// GetMetrics возвращает метрики хаба
	GetMetrics() map[string]interface{}

	// ClientCount возвращает количество подключенных клиентов
	ClientCount() int

	// Новый метод для получения активных подписчиков викторины
	GetActiveSubscribers(quizID uint) ([]uint, error)

	// Методы, необходимые для работы Manager (если Manager вызывает их напрямую)
	// RegisterClient(client *Client) // Пример: если Manager отвечает за регистрацию
	// UnregisterClient(client *Client) // Пример
}

// HttpHandlerProvider определяет метод для предоставления HTTP обработчиков.
type HttpHandlerProvider interface {
	GetHttpHandlers() map[string]http.HandlerFunc
}
