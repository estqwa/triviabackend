package websocket

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Время, которое разрешено писать сообщение клиенту.
	writeWait = 10 * time.Second

	// Время, которое разрешено клиенту читать следующее сообщение.
	// Уменьшено с 90 до 30 секунд для быстрого обнаружения отключений
	pongWait = 30 * time.Second

	// Периодичность отправки ping-сообщений клиенту.
	pingPeriod = (pongWait * 9) / 10

	// Максимальный размер сообщения
	maxMessageSize = 512

	// Размер буфера по умолчанию для каналов отправки сообщений клиенту
	// Увеличено с 64 до 128 для большей устойчивости к пикам
	defaultClientBufferSize = 128
)

var (
	newline = []byte{'\n'}
	space   = []byte{' '}
)

// ClientConfig содержит настройки для клиента
type ClientConfig struct {
	// BufferSize определяет размер буфера канала отправки сообщений
	BufferSize int

	// PingInterval определяет интервал между ping-сообщениями
	PingInterval time.Duration

	// PongWait определяет время ожидания pong-ответа
	PongWait time.Duration

	// WriteWait определяет тайм-аут для записи сообщений
	WriteWait time.Duration

	// MaxMessageSize определяет максимальный размер сообщения
	MaxMessageSize int64
}

// DefaultClientConfig возвращает конфигурацию клиента по умолчанию
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		BufferSize:     defaultClientBufferSize,
		PingInterval:   pingPeriod,
		PongWait:       pongWait,
		WriteWait:      writeWait,
		MaxMessageSize: maxMessageSize,
	}
}

// Client является посредником между WebSocket соединением и hub.
type Client struct {
	// ID пользователя
	UserID string

	// Уникальный ID для каждого соединения
	ConnectionID string

	// Hub, к которому подключен клиент (может быть nil после миграции)
	hub interface{} // Изменено с *Hub на interface{} для поддержки ShardedHub

	// WebSocket соединение
	conn *websocket.Conn

	// Буферизованный канал для исходящих сообщений
	// Уменьшен размер буфера с 256 до 64 для экономии памяти
	send chan []byte

	// Время последней активности клиента
	lastActivity time.Time

	// Канал для ожидания завершения регистрации
	registrationComplete chan struct{}

	// Карта подписок на типы сообщений
	subscriptions sync.Map

	// Мьютекс для синхронизации доступа к подпискам
	subMutex sync.RWMutex

	// Роли клиента (например, "admin", "player", "spectator")
	roles map[string]bool

	// ID викторины, к которой подключен клиент (0 если не подключен)
	// Используем атомарный тип для потокобезопасности
	currentQuizID atomic.Uint32

	// Счетчик предупреждений о переполнении буфера
	bufferWarningCount int32
	bufferWarningMutex sync.Mutex // Мьютекс для защиты счетчика
}

// NewClient создает нового клиента
func NewClient(hub interface{}, conn *websocket.Conn, userID string) *Client {
	connectionID := uuid.New().String()
	return &Client{
		hub:                  hub,
		conn:                 conn,
		send:                 make(chan []byte, defaultClientBufferSize), // Используем увеличенный буфер
		UserID:               userID,
		ConnectionID:         connectionID,
		lastActivity:         time.Now(),
		registrationComplete: make(chan struct{}, 1),
		roles:                make(map[string]bool),
	}
}

// NewClientWithConfig создает нового клиента с указанной конфигурацией
func NewClientWithConfig(hub interface{}, conn *websocket.Conn, userID string, config ClientConfig) *Client {
	connectionID := uuid.New().String()

	// Проверяем и исправляем недопустимые значения
	if config.BufferSize <= 0 {
		config.BufferSize = defaultClientBufferSize
	}

	return &Client{
		hub:                  hub,
		conn:                 conn,
		send:                 make(chan []byte, config.BufferSize),
		UserID:               userID,
		ConnectionID:         connectionID,
		lastActivity:         time.Now(),
		registrationComplete: make(chan struct{}, 1),
		roles:                make(map[string]bool),
	}
}

// SetQuizID устанавливает ID текущей викторины для клиента
func (c *Client) SetQuizID(quizID uint) {
	c.currentQuizID.Store(uint32(quizID))
	log.Printf("Client %s (Conn: %s) set QuizID to %d", c.UserID, c.ConnectionID, quizID)
}

// GetQuizID возвращает ID текущей викторины клиента
func (c *Client) GetQuizID() uint {
	return uint(c.currentQuizID.Load())
}

// ClearQuizID сбрасывает ID текущей викторины (например, при выходе)
func (c *Client) ClearQuizID() {
	c.currentQuizID.Store(0)
	log.Printf("Client %s (Conn: %s) cleared QuizID", c.UserID, c.ConnectionID)
}

// readPump читает сообщения от клиента и передает их обработчику
func (c *Client) readPump(messageHandler func(message []byte, client *Client) error) {
	defer func() {
		log.Printf("WebSocket Client Read Pump STOPPED for UserID: %s, ConnID: %s", c.UserID, c.ConnectionID)
		// Сообщаем хабу об отписке клиента
		// Проверяем, к какому типу хаба подключен клиент
		switch hub := c.hub.(type) {
		case *Shard:
			hub.unregister <- c
		case *ShardedHub: // Добавлено для поддержки прямого подключения к ShardedHub (хотя обычно через Shard)
			hub.UnregisterClient(c)
		default:
			log.Printf("Warning: Unknown hub type for client %s during unregister", c.UserID)
		}
		// Закрываем соединение
		c.conn.Close()
	}()

	// Настройка чтения сообщений
	c.conn.SetReadLimit(maxMessageSize) // Используем значение из defaultConfig
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		c.lastActivity = time.Now() // Обновляем время активности при получении pong
		return nil
	})

	log.Printf("WebSocket Client Read Pump STARTED for UserID: %s, ConnID: %s", c.UserID, c.ConnectionID)

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				log.Printf("WebSocket Client Read Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
			} else if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("WebSocket Client Connection Closed Normally (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
			} else {
				log.Printf("WebSocket Client Read Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
			}
			break // Выходим из цикла при любой ошибке чтения
		}
		// Логируем получение сообщения (можно сделать опциональным)
		// log.Printf("Received message from %s: %s", c.UserID, string(message))

		// Обновляем время активности при получении сообщения
		c.lastActivity = time.Now()

		// Безопасный вызов обработчика с recover
		if handlerErr := safeHandleMessage(message, c, messageHandler); handlerErr != nil {
			// Если обработчик вернул ошибку, считаем ее фатальной для соединения
			log.Printf("WebSocket Client Handler Error (UserID: %s, ConnID: %s): %v. Closing connection.", c.UserID, c.ConnectionID, handlerErr)
			break // Закрываем соединение
		}

		// Сбрасываем счетчик предупреждений при получении любого сообщения от клиента
		c.resetBufferWarningCount()
	}
}

// safeHandleMessage - обертка для вызова обработчика с recover
// Возвращает ошибку, если обработчик вернул ошибку.
func safeHandleMessage(message []byte, client *Client, messageHandler func(message []byte, client *Client) error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("PANIC recovered in message handler for UserID: %s, ConnID: %s. Panic: %v\nStack trace:\n%s",
				client.UserID, client.ConnectionID, r, string(debug.Stack()))
			// Паника считается фатальной ошибкой для обработчика
			err = fmt.Errorf("panic recovered: %v", r)
			// Можно отправить сообщение об ошибке клиенту, если это уместно
			// client.sendError("internal_error", "Failed to process message due to an internal error")
		}
	}()
	// Вызов оригинального обработчика
	message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
	if messageHandler != nil {
		err = messageHandler(message, client) // Сохраняем возвращенную ошибку
	} else {
		log.Printf("Warning: No message handler registered for client %s", client.UserID)
	}
	return err // Возвращаем ошибку (или nil)
}

// writePump отправляет сообщения клиенту из канала send
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		// Закрываем соединение при завершении writePump
		c.conn.Close()
		log.Printf("WebSocket Client Write Pump STOPPED for UserID: %s, ConnID: %s", c.UserID, c.ConnectionID)
	}()

	log.Printf("WebSocket Client Write Pump STARTED for UserID: %s, ConnID: %s", c.UserID, c.ConnectionID)

	for {
		select {
		case message, ok := <-c.send:
			// Сразу после чтения из c.send
			log.Printf("[Client %s][Conn %s] Dequeued message for writing. Type: %s. Current send buffer len: %d", c.UserID, c.ConnectionID, messageTypeFromBytes(message), len(c.send))

			// Устанавливаем таймаут для записи
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Printf("WebSocket Client SetWriteDeadline Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				// Ошибку установки дедлайна можно считать фатальной для записи
				return // Завершаем горутину записи
			}

			if !ok {
				// Канал send закрыт (хаб или шард закрыли канал клиента)
				log.Printf("WebSocket Client Send Channel Closed (UserID: %s, ConnID: %s)", c.UserID, c.ConnectionID)
				// Отправляем сообщение о закрытии клиенту, если соединение еще открыто
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return // Завершаем горутину записи
			}

			// Получаем writer для отправки сообщения
			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				log.Printf("WebSocket Client NextWriter Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				return // Завершаем горутину записи
			}

			// Пишем сообщение
			log.Printf("[Client %s][Conn %s] Attempting WriteMessage. Type: %s", c.UserID, c.ConnectionID, messageTypeFromBytes(message)) // Лог перед записью
			if _, err := w.Write(message); err != nil {
				log.Printf("WebSocket Client Write Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				// Не выходим сразу, пытаемся закрыть writer
			}

			// --- НАЧАЛО КОММЕНТИРОВАНИЯ БЛОКА ОПТИМИЗАЦИИ ---
			// // Добавляем оставшиеся сообщения в очереди в текущее сообщение WebSocket (оптимизация)
			// n := len(c.send)
			// for i := 0; i < n; i++ {
			// 	w.Write(newline)
			// 	w.Write(<-c.send)
			// }
			// --- КОНЕЦ КОММЕНТИРОВАНИЯ БЛОКА ОПТИМИЗАЦИИ ---

			// Закрываем writer, чтобы отправить сообщение
			if err := w.Close(); err != nil {
				log.Printf("WebSocket Client Writer Close Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				return // Завершаем горутину записи
			}
			// Лог после успешной записи
			log.Printf("[Client %s][Conn %s] Successfully wrote message. Type: %s", c.UserID, c.ConnectionID, messageTypeFromBytes(message))

		case <-ticker.C:
			// Отправляем ping клиенту
			if err := c.conn.SetWriteDeadline(time.Now().Add(writeWait)); err != nil {
				log.Printf("WebSocket Client SetWriteDeadline (Ping) Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				return // Завершаем горутину записи
			}
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket Client Ping Error (UserID: %s, ConnID: %s): %v", c.UserID, c.ConnectionID, err)
				return // Завершаем горутину записи при ошибке пинга
			}
			// Логируем отправку пинга (можно сделать реже или убрать)
			// log.Printf("Sent ping to client %s", c.UserID)
		}
	}
}

// StartPumps запускает горутины для чтения и записи сообщений
func (c *Client) StartPumps(messageHandler func(message []byte, client *Client) error) {
	if c.UserID == "" {
		log.Printf("WebSocket: client has no UserID, skipping registration")
		c.conn.Close()
		return
	}

	// Регистрируем клиента в хабе в зависимости от его типа
	if sh, ok := c.hub.(*ShardedHub); ok {
		log.Printf("WebSocket: registering client %s in ShardedHub", c.UserID)
		sh.RegisterSync(c, c.registrationComplete)
	} else if sh, ok := c.hub.(*Shard); ok { // Добавлено: регистрация через Shard
		log.Printf("WebSocket: registering client %s in Shard %d", c.UserID, sh.id)
		sh.register <- c // Используем канал шарда
	} else {
		log.Printf("WebSocket: unknown or nil hub type (%T) for client %s, skipping registration", c.hub, c.UserID)
		c.conn.Close()
		return
	}

	// Ожидаем завершения регистрации
	select {
	case <-c.registrationComplete:
		log.Printf("WebSocket: client %s fully registered, starting pumps", c.UserID)
	case <-time.After(5 * time.Second):
		log.Printf("WebSocket: timeout waiting for client %s registration", c.UserID)
		c.conn.Close()
		return
	}

	// Проверяем, что клиент все еще зарегистрирован
	clientExists := false

	if sh, ok := c.hub.(*ShardedHub); ok && sh != nil {
		// Для ShardedHub проверка не требуется, так как шард сам управляет клиентами
		clientExists = true
	} else if sh, ok := c.hub.(*Shard); ok && sh != nil { // Добавлено: проверка в Shard
		_, clientExists = sh.clients.Load(c)
	}

	if !clientExists {
		log.Printf("WebSocket: client %s was unregistered or hub is nil before pumps started, skipping pumps", c.UserID)
		return
	}

	go c.writePump()
	go c.readPump(messageHandler)
}

// IsSubscribed проверяет, подписан ли клиент на указанный тип сообщений
func (c *Client) IsSubscribed(messageType string) bool {
	c.subMutex.RLock()
	defer c.subMutex.RUnlock()

	if messageType == "" {
		return true // Пустой тип означает все сообщения
	}

	// Проверяем, есть ли у клиента подписка на этот тип сообщений
	_, ok := c.subscriptions.Load(messageType)
	return ok
}

// Subscribe подписывает клиента на указанный тип сообщений
func (c *Client) Subscribe(messageType string) {
	if messageType == "" {
		return // Игнорируем пустые типы
	}

	c.subMutex.Lock()
	defer c.subMutex.Unlock()

	c.subscriptions.Store(messageType, true)
	log.Printf("WebSocket: клиент %s подписался на сообщения типа %s", c.UserID, messageType)
}

// Unsubscribe отменяет подписку клиента на указанный тип сообщений
func (c *Client) Unsubscribe(messageType string) {
	if messageType == "" {
		return // Игнорируем пустые типы
	}

	c.subMutex.Lock()
	defer c.subMutex.Unlock()

	c.subscriptions.Delete(messageType)
	log.Printf("WebSocket: клиент %s отписался от сообщений типа %s", c.UserID, messageType)
}

// GetSubscriptions возвращает список типов сообщений, на которые подписан клиент
func (c *Client) GetSubscriptions() []string {
	c.subMutex.RLock()
	defer c.subMutex.RUnlock()

	var subscriptions []string

	c.subscriptions.Range(func(key, value interface{}) bool {
		if messageType, ok := key.(string); ok {
			subscriptions = append(subscriptions, messageType)
		}
		return true
	})

	return subscriptions
}

// SubscribeToQuiz подписывает клиента на все типы сообщений викторины
func (c *Client) SubscribeToQuiz() {
	c.Subscribe(QUIZ_START)
	c.Subscribe(QUIZ_END)
	c.Subscribe(QUESTION_START)
	c.Subscribe(QUESTION_END)
	c.Subscribe(RESULT_UPDATE)
	log.Printf("WebSocket: клиент %s подписался на все сообщения викторины", c.UserID)
}

// HasRole проверяет, есть ли у клиента указанная роль
func (c *Client) HasRole(role string) bool {
	c.subMutex.RLock()
	defer c.subMutex.RUnlock()
	return c.roles[role]
}

// AddRole добавляет клиенту указанную роль
func (c *Client) AddRole(role string) {
	c.subMutex.Lock()
	defer c.subMutex.Unlock()
	c.roles[role] = true
	log.Printf("WebSocket: клиенту %s добавлена роль %s", c.UserID, role)
}

// RemoveRole удаляет у клиента указанную роль
func (c *Client) RemoveRole(role string) {
	c.subMutex.Lock()
	defer c.subMutex.Unlock()
	delete(c.roles, role)
	log.Printf("WebSocket: у клиента %s удалена роль %s", c.UserID, role)
}

// --- Новые методы для управления счетчиком предупреждений ---

// incrementBufferWarningCount увеличивает счетчик предупреждений и возвращает новое значение
func (c *Client) incrementBufferWarningCount() int32 {
	c.bufferWarningMutex.Lock()
	defer c.bufferWarningMutex.Unlock()
	c.bufferWarningCount++
	return c.bufferWarningCount
}

// resetBufferWarningCount сбрасывает счетчик предупреждений
func (c *Client) resetBufferWarningCount() {
	c.bufferWarningMutex.Lock()
	defer c.bufferWarningMutex.Unlock()
	if c.bufferWarningCount > 0 {
		c.bufferWarningCount = 0
		log.Printf("[Client %s][Conn %s] Buffer warning count reset.", c.UserID, c.ConnectionID)
	}
}

// GetBufferWarningCount возвращает текущее значение счетчика предупреждений
func (c *Client) getBufferWarningCount() int32 {
	c.bufferWarningMutex.Lock()
	defer c.bufferWarningMutex.Unlock()
	return c.bufferWarningCount
}

// --- Конец новых методов ---

// --- Вспомогательные функции ---

// messageTypeFromBytes пытается извлечь тип сообщения из JSON байтов
func messageTypeFromBytes(message []byte) string {
	// Добавляем импорт encoding/json локально, если его нет вверху файла
	// import "encoding/json"
	var event struct {
		Type string `json:"type"`
	}
	// Используем json.Unmarshal вместо json.NewDecoder().Decode(), чтобы не требовать io.Reader
	if json.Unmarshal(message, &event) == nil && event.Type != "" {
		return event.Type
	}
	// Возвращаем строку, указывающую на возможный бинарный формат или ошибку парсинга
	return "unknown/binary"
}

// GetUserIDUint преобразует строковый UserID в uint.
// Возвращает 0 при ошибке преобразования.
func (c *Client) GetUserIDUint() uint {
	var userIDUint uint
	// Используем fmt.Sscan для безопасного преобразования
	_, err := fmt.Sscan(c.UserID, &userIDUint)
	if err != nil {
		log.Printf("[Client %s] Ошибка преобразования UserID в uint: %v", c.UserID, err)
		return 0 // Возвращаем 0 при ошибке
	}
	return userIDUint
}
