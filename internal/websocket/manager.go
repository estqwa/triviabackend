package websocket

import (
	"encoding/json"
	"fmt"
	"log"
)

// Event представляет структуру WebSocket-сообщения
type Event struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Manager обрабатывает WebSocket сообщения
type Manager struct {
	hub            HubInterface
	messageHandler map[string]func(data json.RawMessage, client *Client) error
}

// NewManager создает новый менеджер WebSocket
func NewManager(hub HubInterface) *Manager {
	m := &Manager{
		hub:            hub,
		messageHandler: make(map[string]func(data json.RawMessage, client *Client) error),
	}
	return m
}

// RegisterHandler регистрирует обработчик для определенного типа сообщений
func (m *Manager) RegisterHandler(eventType string, handler func(data json.RawMessage, client *Client) error) {
	m.messageHandler[eventType] = handler
	log.Printf("[WebSocketManager] Зарегистрирован обработчик для сообщений типа: %s", eventType)
}

// HandleMessage обрабатывает входящее сообщение от клиента.
// Возвращает error, если обработка не удалась и соединение нужно закрыть.
func (m *Manager) HandleMessage(message []byte, client *Client) error {
	var event Event
	if err := json.Unmarshal(message, &event); err != nil {
		log.Printf("Failed to unmarshal message from %s: %v, Message: %s", client.UserID, err, string(message))
		m.SendErrorToClient(client, "invalid_message_format", "Invalid JSON format")
		return err // Ошибка парсинга - закрываем соединение
	}

	handler, ok := m.messageHandler[event.Type]
	if !ok {
		log.Printf("No handler registered for message type '%s' from client %s", event.Type, client.UserID)
		m.SendErrorToClient(client, "unknown_message_type", fmt.Sprintf("Unknown message type: %s", event.Type))
		return nil // Неизвестный тип - не закрываем соединение
	}

	// Вызываем зарегистрированный обработчик
	rawMessage, _ := json.Marshal(event.Data)
	if err := handler(rawMessage, client); err != nil {
		// Если обработчик вернул ошибку, передаем ее дальше для закрытия соединения
		log.Printf("Handler for type '%s' returned error for client %s: %v", event.Type, client.UserID, err)
		return err
	}

	return nil // Обработка успешна или ошибка не фатальна
}

// SendErrorToClient отправляет стандартизированное сообщение об ошибке клиенту.
// Этот метод НЕ закрывает соединение.
func (m *Manager) SendErrorToClient(client *Client, code string, message string) {
	errorEvent := Event{
		Type: "server:error",
		Data: map[string]string{
			"code":    code,
			"message": message,
		},
	}
	if err := m.hub.SendJSONToUser(client.UserID, errorEvent); err != nil {
		log.Printf("ERROR sending error to client %s: %v", client.UserID, err)
	}
}

// BroadcastEvent отправляет событие всем клиентам
func (m *Manager) BroadcastEvent(eventType string, data interface{}) error {
	event := Event{
		Type: eventType,
		Data: data,
	}

	return m.hub.BroadcastJSON(event)
}

// SendEventToUser отправляет событие конкретному пользователю
func (m *Manager) SendEventToUser(userID string, eventType string, data interface{}) error {
	event := Event{
		Type: eventType,
		Data: data,
	}

	return m.hub.SendJSONToUser(userID, event)
}

// SendTokenExpirationWarning отправляет пользователю предупреждение о скором истечении срока действия токена
func (m *Manager) SendTokenExpirationWarning(userID string, expiresIn int) {
	// Создаем сообщение
	message := map[string]interface{}{
		"type": TOKEN_EXPIRE_SOON,
		"data": map[string]interface{}{
			"expires_in": expiresIn,
			"unit":       "seconds",
		},
	}

	// Отправляем пользователю
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		log.Printf("[WebSocketManager] Ошибка при сериализации предупреждения о токене: %v", err)
		return
	}

	sent := m.hub.SendToUser(userID, jsonMessage)
	if sent {
		log.Printf("[WebSocketManager] Отправлено предупреждение о истечении токена пользователю ID=%s", userID)
	} else {
		log.Printf("[WebSocketManager] Не удалось отправить предупреждение о истечении токена пользователю ID=%s", userID)
	}
}

// SendTokenExpiredNotification отправляет пользователю уведомление о истечении срока действия токена
func (m *Manager) SendTokenExpiredNotification(userID string) {
	// Создаем сообщение
	message := map[string]interface{}{
		"type": TOKEN_EXPIRED,
		"data": map[string]interface{}{
			"message": "Срок действия токена истек. Необходимо выполнить повторный вход.",
		},
	}

	// Отправляем пользователю
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		log.Printf("[WebSocketManager] Ошибка при сериализации уведомления о истечении токена: %v", err)
		return
	}

	sent := m.hub.SendToUser(userID, jsonMessage)
	if sent {
		log.Printf("[WebSocketManager] Отправлено уведомление о истечении токена пользователю ID=%s", userID)
	} else {
		log.Printf("[WebSocketManager] Не удалось отправить уведомление о истечении токена пользователю ID=%s", userID)
	}
}

// GetMetrics возвращает текущие метрики WebSocket-системы
func (m *Manager) GetMetrics() map[string]interface{} {
	return map[string]interface{}{
		"client_count": m.hub.ClientCount(),
	}
}

// BroadcastEventToQuiz отправляет событие всем клиентам, подключенным к указанной викторине
func (m *Manager) BroadcastEventToQuiz(quizID uint, event interface{}) error {
	jsonBytes, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event for quiz %d: %w", quizID, err)
	}

	// Проверяем, является ли хаб шардированным
	if shardedHub, ok := m.hub.(*ShardedHub); ok {
		// Если да, используем его метод для отправки в конкретный квиз
		shardedHub.BroadcastToQuiz(quizID, jsonBytes)
		return nil
	} else {
		// Если это не ShardedHub, то специфичная для квиза рассылка не поддерживается.
		// НЕЛЬЗЯ просто вызывать m.hub.BroadcastJSON(event), т.к. это отправит ВСЕМ.
		log.Printf("Warning: BroadcastEventToQuiz called on a non-sharded hub type %T. Quiz-specific broadcast is not supported. Event dropped for quiz %d.", m.hub, quizID)
		return nil // Возвращаем nil, т.к. это ограничение типа, а не ошибка выполнения.
	}
}

// SubscribeClientToTypes подписывает клиента на указанные типы сообщений
func (m *Manager) SubscribeClientToTypes(client *Client, messageTypes []string) {
	for _, msgType := range messageTypes {
		client.Subscribe(msgType)
	}
}

// SubscribeClientToQuiz подписывает клиента на все сообщения указанной викторины
// Теперь принимает quizID
func (m *Manager) SubscribeClientToQuiz(client *Client, quizID uint) error {
	// Проверяем, что наш hub - это ShardedHub
	shardedHub, ok := m.hub.(*ShardedHub)
	if !ok {
		log.Printf("[WebSocketManager] ОШИБКА: SubscribeClientToQuiz вызван, но используется не ShardedHub. Тип хаба: %T", m.hub)
		return fmt.Errorf("тип хаба %T не поддерживает подписку на викторины", m.hub)
	}

	// Находим шард клиента
	shard := shardedHub.getShard(client.UserID)
	if shard == nil {
		log.Printf("[WebSocketManager] ОШИБКА: Не удалось найти шард для клиента %s при подписке на викторину %d", client.UserID, quizID)
		return fmt.Errorf("не удалось найти шард для клиента %s", client.UserID)
	}

	// Вызываем метод подписки на уровне шарда
	shard.SubscribeToQuiz(client, quizID)
	log.Printf("[WebSocketManager] Клиент %s подписан на викторину %d в шарде %d", client.UserID, quizID, shard.id)
	return nil
}

// UnsubscribeClientFromTypes отменяет подписку клиента на указанные типы сообщений
func (m *Manager) UnsubscribeClientFromTypes(client *Client, messageTypes []string) {
	for _, msgType := range messageTypes {
		client.Unsubscribe(msgType)
	}
}

// UnsubscribeClientFromQuiz отписывает клиента от текущей викторины
func (m *Manager) UnsubscribeClientFromQuiz(client *Client) error {
	// Проверяем, что наш hub - это ShardedHub
	shardedHub, ok := m.hub.(*ShardedHub)
	if !ok {
		log.Printf("[WebSocketManager] ОШИБКА: UnsubscribeClientFromQuiz вызван, но используется не ShardedHub. Тип хаба: %T", m.hub)
		return fmt.Errorf("тип хаба %T не поддерживает отписку от викторин", m.hub)
	}

	// Находим шард клиента
	shard := shardedHub.getShard(client.UserID)
	if shard == nil {
		// Клиент мог уже отключиться, или UserID изменился (маловероятно)
		log.Printf("[WebSocketManager] ПРЕДУПРЕЖДЕНИЕ: Не удалось найти шард для клиента %s при отписке от викторины", client.UserID)
		// Не возвращаем ошибку, так как клиент, вероятно, уже не в системе
		return nil
	}

	// Вызываем метод отписки на уровне шарда
	shard.UnsubscribeFromQuiz(client)
	// Лог об успешной отписке находится внутри shard.UnsubscribeFromQuiz
	return nil
}

// BroadcastEventToSubscribers отправляет событие только подписанным клиентам
func (m *Manager) BroadcastEventToSubscribers(eventType string, data interface{}) error {
	event := Event{
		Type: eventType,
		Data: data,
	}

	log.Printf("[WebSocket] Отправка события <%s> подписанным клиентам", eventType)

	return m.hub.BroadcastJSON(event)
}

// BroadcastQuizStart рассылает сообщение о начале викторины
func (m *Manager) BroadcastQuizStart(quizID string, data interface{}) error {
	log.Printf("[WebSocket] Рассылка уведомления о начале викторины %s", quizID)
	return m.BroadcastEventToSubscribers(QUIZ_START, data)
}

// BroadcastQuizEnd рассылает сообщение о завершении викторины
func (m *Manager) BroadcastQuizEnd(quizID string, data interface{}) error {
	log.Printf("[WebSocket] Рассылка уведомления о завершении викторины %s", quizID)
	return m.BroadcastEventToSubscribers(QUIZ_END, data)
}

// BroadcastQuestionStart рассылает сообщение о начале вопроса
func (m *Manager) BroadcastQuestionStart(quizID string, questionNumber int, data interface{}) error {
	log.Printf("[WebSocket] Рассылка уведомления о начале вопроса %d в викторине %s",
		questionNumber, quizID)
	return m.BroadcastEventToSubscribers(QUESTION_START, data)
}

// BroadcastQuestionEnd рассылает сообщение о завершении вопроса
func (m *Manager) BroadcastQuestionEnd(quizID string, questionNumber int, data interface{}) error {
	log.Printf("[WebSocket] Рассылка уведомления о завершении вопроса %d в викторине %s",
		questionNumber, quizID)
	return m.BroadcastEventToSubscribers(QUESTION_END, data)
}

// BroadcastResults рассылает обновление результатов
func (m *Manager) BroadcastResults(quizID string, data interface{}) error {
	log.Printf("[WebSocket] Рассылка обновления результатов викторины %s", quizID)
	return m.BroadcastEventToSubscribers(RESULT_UPDATE, data)
}

// GetActiveSubscribers возвращает список ID активных пользователей для викторины.
// Делегирует вызов нижележащему хабу (HubInterface).
func (m *Manager) GetActiveSubscribers(quizID uint) ([]uint, error) {
	// Проверяем, что hub не nil и реализует метод
	if m.hub == nil {
		return nil, fmt.Errorf("websocket manager has no underlying hub")
	}
	// HubInterface гарантирует наличие этого метода
	return m.hub.GetActiveSubscribers(quizID)
}
