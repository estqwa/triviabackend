package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/repository"
)

// ClientStore - определяем интерфейс здесь, если файл interfaces.go не создался
type ClientStore interface {
	RegisterClient(client *Client)
	UnregisterClient(client *Client)
	Broadcast(message []byte)
	ClientCount() int
}

// Shard представляет подмножество клиентов Hub
// Каждый шард обрабатывает свою группу клиентов независимо,
// что значительно улучшает производительность при большом числе соединений
type Shard struct {
	id         int           // Уникальный ID шарда
	clients    sync.Map      // Ключ: *Client, Значение: bool (или struct{})
	userMap    sync.Map      // Карта UserID -> *Client
	broadcast  chan []byte   // Канал для широковещательных сообщений шарда
	register   chan *Client  // Канал для регистрации клиентов в шарде
	unregister chan *Client  // Канал для отмены регистрации клиентов из шарда
	done       chan struct{} // Сигнал для завершения работы шарда
	metrics    *ShardMetrics // Метрики производительности шарда
	parent     interface{}   // Ссылка на родительский хаб (ShardedHub)
	maxClients int           // Максимальное рекомендуемое количество клиентов в шарде

	// Настройки для очистки
	cleanupInterval   time.Duration
	inactivityTimeout time.Duration

	// Добавляем индекс для быстрой рассылки по викторинам
	// Ключ: quizID (uint), Значение: map[*Client]struct{}
	quizSubscriptions sync.Map

	// Добавляем зависимость для проверки Redis
	cacheRepo repository.CacheRepository
}

// ShardMetrics содержит метрики для отдельного шарда
type ShardMetrics struct {
	id                     int
	activeConnections      int64
	messagesSent           int64
	messagesReceived       int64
	connectionErrors       int64
	inactiveClientsRemoved int64
	lastCleanupTime        time.Time
	mu                     sync.RWMutex
}

// NewShard создает новый шард
func NewShard(id int, parent interface{}, maxClients int, cleanupInterval time.Duration, inactivityTimeout time.Duration, cacheRepo repository.CacheRepository) *Shard {
	if maxClients <= 0 {
		maxClients = 2000 // Значение по умолчанию
	}

	shard := &Shard{
		id:         id,
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client, 100),
		unregister: make(chan *Client, 100),
		done:       make(chan struct{}),
		metrics: &ShardMetrics{
			id:              id,
			lastCleanupTime: time.Now(),
		},
		parent:     parent,
		maxClients: maxClients,
		// Сохраняем настройки очистки и репозиторий кэша
		cleanupInterval:   cleanupInterval,
		inactivityTimeout: inactivityTimeout,
		cacheRepo:         cacheRepo, // Сохраняем репозиторий кэша
	}

	// Запускаем горутину для периодической очистки
	go shard.runCleanupTicker()

	log.Printf("[Шард %d] Создан с максимальным количеством клиентов %d", id, maxClients)
	return shard
}

// Run запускает цикл обработки сообщений шарда
func (s *Shard) Run() {
	for {
		select {
		case client := <-s.register:
			s.handleRegister(client)
		case client := <-s.unregister:
			s.handleUnregister(client)
		case message := <-s.broadcast:
			s.handleBroadcast(message)
		case <-s.done:
			log.Printf("[Шард %d] Получен сигнал завершения работы, останавливаемся", s.id)
			s.cleanupAllClients()
			return
		}
	}
}

// handleRegister регистрирует клиента в шарде
func (s *Shard) handleRegister(client *Client) {
	// Проверяем существующего клиента с тем же UserID
	if existingClient, loaded := s.userMap.LoadOrStore(client.UserID, client); loaded {
		oldClient, ok := existingClient.(*Client)
		if ok && oldClient != client {
			log.Printf("Shard %d: replacing client %s with new connection", s.id, client.UserID)

			// Создаем отложенное закрытие старого соединения
			go func() {
				time.Sleep(500 * time.Millisecond)
				s.clients.Delete(oldClient)
				s.userMap.CompareAndDelete(client.UserID, oldClient)

				if oldClient.conn != nil {
					oldClient.conn.Close()
				}
				close(oldClient.send)

				s.metrics.mu.Lock()
				s.metrics.activeConnections--
				s.metrics.mu.Unlock()
			}()
		}
	}

	// Регистрируем нового клиента
	s.clients.Store(client, true)
	client.lastActivity = time.Now()

	// Обновляем метрики
	s.metrics.mu.Lock()
	s.metrics.activeConnections++
	s.metrics.mu.Unlock()

	log.Printf("Shard %d: client %s registered", s.id, client.UserID)

	// Сигнал о завершении регистрации
	if client.registrationComplete != nil {
		select {
		case client.registrationComplete <- struct{}{}:
		default:
		}
	}
}

// handleUnregister удаляет клиента из шарда
func (s *Shard) handleUnregister(client *Client) {
	// В самом начале функции
	log.Printf("[Shard %d][User %s][Conn %s] handleUnregister called", s.id, client.UserID, client.ConnectionID)

	// Отписываем клиента от викторины перед удалением
	s.UnsubscribeFromQuiz(client)

	if _, ok := s.clients.LoadAndDelete(client); ok {
		// Удаляем из userMap, только если это тот же экземпляр
		if existingClient, loaded := s.userMap.Load(client.UserID); loaded {
			if existingClient == client {
				s.userMap.Delete(client.UserID)
			}
		}

		// Закрываем соединение
		if client.conn != nil {
			client.conn.Close()
		}
		// Закрываем канал отправки только после завершения всех операций
		// чтобы избежать паники при отправке в закрытый канал
		close(client.send)

		// Обновляем метрики
		s.metrics.mu.Lock()
		s.metrics.activeConnections--
		s.metrics.mu.Unlock()

		log.Printf("Shard %d: client %s unregistered", s.id, client.UserID)
	}
}

// handleBroadcast отправляет сообщение всем клиентам в шарде
func (s *Shard) handleBroadcast(message []byte) {
	var clientCount int

	// Проверяем, есть ли в сообщении тип для фильтрации по подпискам
	var messageType string
	if len(message) > 2 { // Минимальная длина для JSON с полем type
		// Пытаемся распарсить JSON, чтобы получить тип сообщения
		var event struct {
			Type string `json:"type"`
		}
		// Используем UnmarshalJSON, который не модифицирует исходное сообщение
		if err := json.Unmarshal(message, &event); err == nil {
			messageType = event.Type
		}
	}

	// Флаг для проверки, является ли сообщение системным (отправляется всем)
	isSystemMessage := messageType == "system" || messageType == TOKEN_EXPIRED

	// Рассылаем сообщение всем клиентам
	s.clients.Range(func(key, value interface{}) bool {
		client, ok := key.(*Client)
		if !ok {
			return true // Пропускаем некорректные записи
		}

		// Если у сообщения есть тип и это не системное сообщение,
		// проверяем, подписан ли клиент на данный тип
		if messageType != "" && !isSystemMessage && !client.IsSubscribed(messageType) {
			return true // Клиент не подписан, пропускаем
		}

		clientCount++
		select {
		case client.send <- message:
			// Сообщение успешно отправлено в буфер клиента
			// При успешной отправке сбрасываем счетчик предупреждений
			client.resetBufferWarningCount()
		default:
			// Буфер клиента переполнен
			log.Printf("[Shard %d] Client %s (Conn: %s) buffer full during broadcast. Current warning count: %d", s.id, client.UserID, client.ConnectionID, client.getBufferWarningCount())

			// Увеличиваем счетчик и проверяем порог
			newCount := client.incrementBufferWarningCount()
			const maxWarnings = 3 // Порог отключения

			if newCount >= maxWarnings {
				log.Printf("[Shard %d] Client %s (Conn: %s) exceeded max buffer warnings (%d). Unregistering.", s.id, client.UserID, client.ConnectionID, maxWarnings)
				// Отключаем клиента, если превышен порог
				s.clients.Delete(client)

				if existingClient, loaded := s.userMap.Load(client.UserID); loaded && existingClient == client {
					s.userMap.Delete(client.UserID)
				}

				// Отписываем от викторины перед закрытием
				s.UnsubscribeFromQuiz(client)

				if client.conn != nil {
					client.conn.Close()
				}
				close(client.send)

				// Обновляем метрики
				s.metrics.mu.Lock()
				if s.metrics.activeConnections > 0 {
					s.metrics.activeConnections--
				}
				s.metrics.connectionErrors++
				s.metrics.mu.Unlock()
			} else {
				// Отправляем предупреждение клиенту
				log.Printf("[Shard %d] Sending buffer warning %d/%d to client %s (Conn: %s)", s.id, newCount, maxWarnings, client.UserID, client.ConnectionID)
				warningMsg := map[string]interface{}{
					"type": "server:buffer_warning",
					"data": map[string]interface{}{
						"warning_count": newCount,
						"max_warnings":  maxWarnings,
						"message":       "Your connection is slow or buffer is full. You may be disconnected soon.",
					},
				}
				jsonWarning, _ := json.Marshal(warningMsg)
				// Попытка отправить предупреждение неблокирующим способом
				// Если и это не удается, ничего страшного, основная логика - счетчик
				select {
				case client.send <- jsonWarning:
				default:
					log.Printf("[Shard %d] Failed to send buffer warning message to client %s (Conn: %s) - buffer still full.", s.id, client.UserID, client.ConnectionID)
				}
			}
		}
		return true
	})

	// Обновляем метрики
	if clientCount > 0 {
		s.metrics.mu.Lock()
		s.metrics.messagesSent += int64(clientCount)
		s.metrics.mu.Unlock()
	}

	// Добавляем тип сообщения в лог для более информативной отладки
	if messageType != "" {
		log.Printf("Shard %d: message of type %s broadcast to %d clients", s.id, messageType, clientCount)
	} else {
		log.Printf("Shard %d: message broadcast to %d clients", s.id, clientCount)
	}
}

// SubscribeToQuiz подписывает клиента на сообщения указанной викторины в этом шарде
func (s *Shard) SubscribeToQuiz(client *Client, quizID uint) {
	log.Printf("[Shard %d][Sub] SubscribeToQuiz called for Client %s (Conn: %s) to Quiz %d", s.id, client.UserID, client.ConnectionID, quizID) // НОВЫЙ ЛОГ - Начало функции

	if quizID == 0 {
		log.Printf("[Shard %d][Sub] Attempt to subscribe client %s to quiz 0. Unsubscribing instead.", s.id, client.UserID)
		s.UnsubscribeFromQuiz(client)
		return
	}

	oldQuizID := client.GetQuizID()
	log.Printf("[Shard %d][Sub] Client %s: Old QuizID is %d, New QuizID is %d", s.id, client.UserID, oldQuizID, quizID) // НОВЫЙ ЛОГ - Проверка ID

	if oldQuizID == quizID {
		log.Printf("[Shard %d][Sub] Client %s already has atomic QuizID %d. Ensuring map presence.", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Уже подписан (атомно)
		// return // Временно уберем return, чтобы убедиться, что добавление в карту произойдет
	}

	// Отписываем от старой викторины, если была и отличается от новой
	if oldQuizID != 0 && oldQuizID != quizID {
		log.Printf("[Shard %d][Sub] Client %s: Unsubscribing from old Quiz %d", s.id, client.UserID, oldQuizID) // НОВЫЙ ЛОГ - Отписка от старой
		s.unsubscribeInternal(client, oldQuizID)
	}

	// Подписываем на новую викторину
	// client.SetQuizID(quizID) // Уже установлено в хендлере, не будем дублировать

	// Добавляем клиента в карту подписчиков викторины
	log.Printf("[Shard %d][Sub] Client %s: Attempting LoadOrStore for quiz map %d", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Перед LoadOrStore
	quizMapUntyped, loaded := s.quizSubscriptions.LoadOrStore(quizID, &sync.Map{})
	if loaded {
		log.Printf("[Shard %d][Sub] Client %s: Found existing map for quiz %d", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Карта уже была
	} else {
		log.Printf("[Shard %d][Sub] Client %s: Created new map for quiz %d", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Создали карту
	}

	quizMap, ok := quizMapUntyped.(*sync.Map)
	if !ok {
		log.Printf("CRITICAL: Shard %d: Invalid type stored in quizSubscriptions for quiz %d. Expected *sync.Map, Got: %T. Value: %#v", s.id, quizID, quizMapUntyped, quizMapUntyped) // НОВЫЙ ЛОГ - Ошибка типа карты
		// Попытка восстановления
		newMap := &sync.Map{}
		newMap.Store(client, struct{}{})
		s.quizSubscriptions.Store(quizID, newMap)
		log.Printf("CRITICAL RECOVERY: Shard %d: Stored new map for quiz %d with client %s", s.id, quizID, client.UserID)
		return
	}

	// *** КРИТИЧЕСКИЙ ШАГ ***
	log.Printf("[Shard %d][Sub] Client %s: Attempting to STORE client in map for Quiz %d (Map: %p)", s.id, client.UserID, quizID, quizMap) // НОВЫЙ ЛОГ - Перед Store
	quizMap.Store(client, struct{}{})                                                                                                      // Store the client in the specific quiz's map
	log.Printf("[Shard %d][Sub] Client %s: STORED client in map for Quiz %d (Map: %p)", s.id, client.UserID, quizID, quizMap)              // НОВЫЙ ЛОГ - После Store

	// Проверяем сразу после добавления
	if _, loaded := quizMap.Load(client); loaded {
		log.Printf("[Shard %d][Sub] Client %s VERIFIED in map for Quiz %d immediately after Store.", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Верификация OK
	} else {
		log.Printf("[Shard %d][Sub] Client %s FAILED VERIFICATION in map for Quiz %d immediately after Store!", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ - Верификация FAILED
	}
}

// UnsubscribeFromQuiz отписывает клиента от текущей викторины
func (s *Shard) UnsubscribeFromQuiz(client *Client) {
	quizID := client.GetQuizID()
	if quizID != 0 {
		s.unsubscribeInternal(client, quizID)
		client.ClearQuizID() // Сбрасываем ID викторины у клиента
		log.Printf("Shard %d: Client %s unsubscribed from Quiz %d", s.id, client.UserID, quizID)
	}
}

// unsubscribeInternal - внутренняя функция для удаления клиента из карты подписок викторины
func (s *Shard) unsubscribeInternal(client *Client, quizID uint) {
	log.Printf("[Shard %d][Unsub] unsubscribeInternal called for Client %s (Conn: %s) from Quiz %d", s.id, client.UserID, client.ConnectionID, quizID) // НОВЫЙ ЛОГ

	if quizMapUntyped, ok := s.quizSubscriptions.Load(quizID); ok {
		quizMap, ok := quizMapUntyped.(*sync.Map)
		if !ok {
			log.Printf("CRITICAL: Shard %d: Invalid type stored in quizSubscriptions for quiz %d during unsubscribe. Expected *sync.Map, Got: %T", s.id, quizID, quizMapUntyped) // НОВЫЙ ЛОГ
			return
		}
		log.Printf("[Shard %d][Unsub] Client %s: Attempting to DELETE client from map for Quiz %d (Map: %p)", s.id, client.UserID, quizID, quizMap) // НОВЫЙ ЛОГ
		quizMap.Delete(client)
		log.Printf("[Shard %d][Unsub] Client %s: DELETED client from map for Quiz %d (Map: %p)", s.id, client.UserID, quizID, quizMap) // НОВЫЙ ЛОГ

		// Проверка после удаления
		if _, loaded := quizMap.Load(client); !loaded {
			log.Printf("[Shard %d][Unsub] Client %s VERIFIED deletion from map for Quiz %d.", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ
		} else {
			log.Printf("[Shard %d][Unsub] Client %s FAILED VERIFICATION of deletion from map for Quiz %d!", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ
		}

		// Опционально: можно удалить карту викторины из s.quizSubscriptions, если она стала пустой
		// Для этого нужен способ проверить размер sync.Map, что нетривиально и может быть неэффективно.
		// Пока оставляем пустые карты.
	} else {
		log.Printf("[Shard %d][Unsub] Client %s: No map found for Quiz %d during unsubscribe.", s.id, client.UserID, quizID) // НОВЫЙ ЛОГ
	}
}

// BroadcastToQuiz отправляет сообщение только тем клиентам шарда,
// которые подписаны на указанную викторину.
func (s *Shard) BroadcastToQuiz(quizID uint, message []byte) {
	// НОВЫЙ ЛОГ
	log.Printf("[Shard %d][Quiz %d] BroadcastToQuiz called. Message type: %s", s.id, quizID, messageTypeFromBytes(message))
	clientCount := 0
	if quizMapUntyped, ok := s.quizSubscriptions.Load(quizID); ok {
		quizMap, ok := quizMapUntyped.(*sync.Map)
		if !ok {
			log.Printf("CRITICAL: Shard %d: Invalid type stored in quizSubscriptions for quiz %d during broadcast", s.id, quizID)
			return
		}
		quizMap.Range(func(key, value interface{}) bool {
			client, ok := key.(*Client)
			if !ok {
				log.Printf("Shard %d: Invalid client type in quiz %d subscription map", s.id, quizID)
				return true // Пропускаем некорректные записи
			}

			// НОВЫЙ ЛОГ
			log.Printf("[Shard %d][Quiz %d][Range] Iterating over client: User %s, Conn %s", s.id, quizID, client.UserID, client.ConnectionID)

			// Перед select
			log.Printf("[Shard %d][Quiz %d][User %s][Conn %s] Attempting to queue message type: %s", s.id, quizID, client.UserID, client.ConnectionID, messageTypeFromBytes(message))

			select {
			case client.send <- message:
				clientCount++
				log.Printf("[Shard %d][Quiz %d][User %s][Conn %s] Successfully queued message type: %s. Buffer len: %d", s.id, quizID, client.UserID, client.ConnectionID, messageTypeFromBytes(message), len(client.send))
			default:
				// Буфер клиента переполнен, отключаем клиента (копипаста из handleBroadcast)
				// Добавляем лог перед существующим логом об ошибке
				log.Printf("[Shard %d][Quiz %d][User %s][Conn %s] FAILED to queue message type: %s (BUFFER FULL/CLOSED). Buffer len: %d. Initiating unregister.", s.id, quizID, client.UserID, client.ConnectionID, messageTypeFromBytes(message), len(client.send))
				log.Printf("Shard %d: client %s buffer full during quiz broadcast, unregistering", s.id, client.UserID)
				s.clients.Delete(client)
				quizMap.Delete(client) // Удаляем из карты викторины

				if existingClient, loaded := s.userMap.Load(client.UserID); loaded && existingClient == client {
					s.userMap.Delete(client.UserID)
				}

				if client.conn != nil {
					client.conn.Close()
				}
				// Не закрываем client.send здесь, он закроется в handleUnregister
				// Вызываем handleUnregister асинхронно, чтобы не блокировать рассылку
				// handleUnregister сам отпишет от викторины, но мы уже удалили из quizMap
				go s.handleUnregister(client)

				// Обновляем метрики
				s.metrics.mu.Lock()
				if s.metrics.activeConnections > 0 { // Предотвращаем отрицательные значения
					s.metrics.activeConnections--
				}
				s.metrics.connectionErrors++
				s.metrics.mu.Unlock()
			}
			return true
		})
	}

	if clientCount > 0 {
		// Обновляем метрики отправленных сообщений
		s.metrics.mu.Lock()
		s.metrics.messagesSent += int64(clientCount)
		s.metrics.mu.Unlock()
		log.Printf("Shard %d: Message broadcast to %d clients in Quiz %d", s.id, clientCount, quizID)
	} else {
		// Можно добавить лог, если для викторины нет подписчиков в этом шарде
		// log.Printf("Shard %d: No clients found for Quiz %d broadcast", s.id, quizID)
	}
}

// runCleanupTicker запускает тикер для периодической очистки
func (s *Shard) runCleanupTicker() {
	// Не запускаем тикер, если интервал не задан
	if s.cleanupInterval <= 0 {
		log.Printf("[Shard %d] Очистка неактивных клиентов отключена (интервал <= 0)", s.id)
		return
	}

	log.Printf("[Shard %d] Запуск рутины очистки каждые %v с таймаутом %v", s.id, s.cleanupInterval, s.inactivityTimeout)
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Printf("[Shard %d] Запуск проверки неактивных клиентов...", s.id)
			s.cleanupInactiveClients(s.inactivityTimeout)
		case <-s.done:
			log.Printf("[Shard %d] Остановка рутины очистки", s.id)
			return
		}
	}
}

// cleanupInactiveClients проверяет и инициирует удаление неактивных клиентов
func (s *Shard) cleanupInactiveClients(timeout time.Duration) {
	inactiveCount := 0
	s.clients.Range(func(key, value interface{}) bool {
		client, ok := key.(*Client)
		if !ok {
			return true // Пропускаем некорректные записи
		}

		// Проверяем время последней активности
		if time.Since(client.lastActivity) > timeout {
			inactiveCount++
			log.Printf("[Shard %d Cleanup] Найден неактивный клиент %s (ConnID: %s). Последняя активность: %v. Инициируем удаление.",
				s.id, client.UserID, client.ConnectionID, client.lastActivity)

			// Отправляем клиента в канал unregister для безопасного удаления
			// Используем неблокирующую отправку, чтобы не зависнуть здесь
			select {
			case s.unregister <- client:
				// Успешно отправлен на удаление
			default:
				// Если канал переполнен, логируем и пропускаем на этой итерации
				log.Printf("[Shard %d Cleanup] WARN: Канал unregister переполнен, не удалось инициировать удаление клиента %s (ConnID: %s)",
					s.id, client.UserID, client.ConnectionID)
			}
		}
		return true // Продолжаем итерацию
	})

	if inactiveCount > 0 {
		log.Printf("[Shard %d Cleanup] Найдено %d неактивных клиентов для потенциального удаления.", s.id, inactiveCount)
	}
	// Фактическое обновление метрик произойдет в handleUnregister
}

// cleanupAllClients закрывает все соединения перед остановкой шарда
func (s *Shard) cleanupAllClients() {
	s.clients.Range(func(key, value interface{}) bool {
		client, ok := key.(*Client)
		if !ok {
			return true
		}

		if client.conn != nil {
			client.conn.Close()
		}
		close(client.send)

		s.clients.Delete(client)
		return true
	})

	log.Printf("Shard %d: all clients cleanup completed", s.id)
}

// SendToUser отправляет сообщение конкретному пользователю в шарде
func (s *Shard) SendToUser(userID string, message []byte) bool {
	clientInterface, exists := s.userMap.Load(userID)
	if !exists {
		return false
	}

	client, ok := clientInterface.(*Client)
	if !ok {
		return false
	}

	select {
	case client.send <- message:
		// Обновляем метрики
		s.metrics.mu.Lock()
		s.metrics.messagesSent++
		s.metrics.mu.Unlock()
		// Сбрасываем счетчик при успешной прямой отправке
		client.resetBufferWarningCount()
		return true
	default:
		// Буфер клиента переполнен
		log.Printf("[Shard %d] Client %s (Conn: %s) buffer full on direct message. Current warning count: %d", s.id, userID, client.ConnectionID, client.getBufferWarningCount())

		newCount := client.incrementBufferWarningCount()
		const maxWarnings = 3

		if newCount >= maxWarnings {
			log.Printf("[Shard %d] Client %s (Conn: %s) exceeded max buffer warnings (%d) on direct message. Unregistering.", s.id, client.UserID, client.ConnectionID, maxWarnings)
			// Отключаем клиента, если превышен порог
			s.clients.Delete(client)

			if existingClient, loaded := s.userMap.Load(client.UserID); loaded && existingClient == client {
				s.userMap.Delete(client.UserID)
			}

			// Отписываем от викторины перед закрытием
			s.UnsubscribeFromQuiz(client)

			if client.conn != nil {
				client.conn.Close()
			}
			close(client.send)

			// Обновляем метрики
			s.metrics.mu.Lock()
			if s.metrics.activeConnections > 0 {
				s.metrics.activeConnections--
			}
			s.metrics.connectionErrors++
			s.metrics.mu.Unlock()
			return false // Сообщение не доставлено, клиент отключен
		} else {
			// Отправляем предупреждение
			log.Printf("[Shard %d] Sending buffer warning %d/%d to client %s (Conn: %s) on direct message", s.id, newCount, maxWarnings, client.UserID, client.ConnectionID)
			warningMsg := map[string]interface{}{
				"type": "server:buffer_warning",
				"data": map[string]interface{}{
					"warning_count": newCount,
					"max_warnings":  maxWarnings,
					"message":       "Your connection is slow or buffer is full. You may be disconnected soon.",
				},
			}
			jsonWarning, _ := json.Marshal(warningMsg)
			select {
			case client.send <- jsonWarning:
			default:
				log.Printf("[Shard %d] Failed to send buffer warning message to client %s (Conn: %s) - buffer still full.", s.id, client.UserID, client.ConnectionID)
			}
			return false // Сообщение не доставлено, но клиент пока не отключен
		}
	}
}

// BroadcastBytes рассылает байтовое сообщение всем клиентам в шарде
func (s *Shard) BroadcastBytes(message []byte) {
	select {
	case s.broadcast <- message:
		// Сообщение успешно отправлено в канал рассылки
	default:
		log.Printf("Shard %d: broadcast channel full, message dropped", s.id)
	}
}

// BroadcastJSON рассылает JSON-сообщение всем клиентам в шарде
func (s *Shard) BroadcastJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	s.BroadcastBytes(data)
	return nil
}

// GetMetrics возвращает метрики шарда
func (s *Shard) GetMetrics() map[string]interface{} {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()

	clientCount := s.GetClientCount()
	loadPercentage := float64(clientCount) / float64(s.maxClients) * 100

	return map[string]interface{}{
		"shard_id":           s.id,
		"active_connections": clientCount,
		"max_clients":        s.maxClients,
		"messages_sent":      s.metrics.messagesSent,
		"messages_received":  s.metrics.messagesReceived,
		"connection_errors":  s.metrics.connectionErrors,
		"load_percentage":    loadPercentage,
		"last_cleanup":       s.metrics.lastCleanupTime.Format(time.RFC3339),
		"inactive_removed":   s.metrics.inactiveClientsRemoved,
	}
}

// GetClientCount возвращает количество активных клиентов в шарде
func (s *Shard) GetClientCount() int {
	var count int
	s.clients.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// Close закрывает шард и освобождает ресурсы
func (s *Shard) Close() {
	close(s.done)
}

// getActiveSubscribersForQuiz возвращает список UserID активных (не выбывших)
// подписчиков для указанной викторины в этом шарде.
func (s *Shard) getActiveSubscribersForQuiz(quizID uint) ([]uint, error) {
	var activeSubscribers []uint

	// Получаем карту подписчиков для данной викторины
	quizSubscribersRaw, ok := s.quizSubscriptions.Load(quizID)
	if !ok {
		// Нет подписчиков на эту викторину в данном шарде
		return activeSubscribers, nil // Returns empty list if no map for quizID
	}

	// --- ИСПРАВЛЕНИЕ: Используем правильный тип *sync.Map и итерацию ---
	quizSubscribersMap, ok := quizSubscribersRaw.(*sync.Map) // Correct type assertion
	if !ok {
		log.Printf("CRITICAL: Shard %d: Invalid type stored in quizSubscriptions for quiz %d in getActiveSubscribersForQuiz. Expected *sync.Map, Got: %T", s.id, quizID, quizSubscribersRaw)
		// Возвращаем пустой список в случае ошибки типа, чтобы не прерывать полностью
		// return activeSubscribers, fmt.Errorf("invalid type in quizSubscriptions for quiz %d", quizID)
		return activeSubscribers, nil
	}

	// Проверяем каждого подписчика в sync.Map с помощью Range
	quizSubscribersMap.Range(func(key, value interface{}) bool {
		client, ok := key.(*Client)
		if !ok || client == nil || client.UserID == "" { // Пропускаем nil или некорректных клиентов
			log.Printf("[Shard %d] WARN: Invalid client key found in quiz %d subscribers map during getActiveSubscribersForQuiz.", s.id, quizID)
			return true // Continue Range
		}

		// Формируем ключ выбывания в Redis
		eliminationKey := fmt.Sprintf("quiz:%d:eliminated:%d", quizID, client.GetUserIDUint())

		// Проверяем наличие ключа в Redis
		eliminated, err := s.cacheRepo.Exists(eliminationKey)
		if err != nil {
			// Логируем ошибку Redis, но считаем пользователя активным, чтобы не блокировать игру
			log.Printf("[Shard %d] WARNING: Ошибка проверки статуса выбывания для пользователя %d в Redis: %v. Пользователь считается активным.", s.id, client.GetUserIDUint(), err)
			eliminated = false // Считаем активным при ошибке Redis
		}

		// Если пользователь не выбыл, добавляем его в список
		if !eliminated {
			activeSubscribers = append(activeSubscribers, client.GetUserIDUint())
		}
		return true // Continue Range
	})
	// --- Конец исправления ---

	return activeSubscribers, nil
}
