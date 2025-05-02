package websocket

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yourusername/trivia-api/internal/config"
	"github.com/yourusername/trivia-api/internal/domain/repository"
)

// WorkerPool представляет пул воркеров для обработки сообщений
type WorkerPool struct {
	tasks        chan func()
	workerCount  int
	wg           sync.WaitGroup
	shuttingDown int32 // атомарный флаг для отслеживания состояния завершения
}

// NewWorkerPool создает новый пул воркеров с указанным количеством
func NewWorkerPool(workerCount int) *WorkerPool {
	// Минимальное количество воркеров
	if workerCount < 1 {
		workerCount = 1
	}

	// Размер буфера задач - в 10 раз больше количества воркеров
	// для обеспечения непрерывной обработки
	pool := &WorkerPool{
		tasks:       make(chan func(), workerCount*10),
		workerCount: workerCount,
	}

	pool.Start()
	return pool
}

// Start запускает всех воркеров в пуле
func (p *WorkerPool) Start() {
	// Завершаем отложенные задачи при повторном запуске
	select {
	case <-p.tasks:
	default:
	}

	atomic.StoreInt32(&p.shuttingDown, 0)

	p.wg.Add(p.workerCount)
	for i := 0; i < p.workerCount; i++ {
		go p.worker(i)
	}

	log.Printf("WorkerPool: запущен пул с %d воркерами", p.workerCount)
}

// worker запускает цикл обработки задач
func (p *WorkerPool) worker(id int) {
	defer p.wg.Done()

	log.Printf("WorkerPool: воркер %d запущен", id)

	for task := range p.tasks {
		// Проверяем, не завершается ли пул
		if atomic.LoadInt32(&p.shuttingDown) == 1 {
			log.Printf("WorkerPool: воркер %d завершает работу при закрытии пула", id)
			return
		}

		// Выполняем задачу с защитой от паники
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("WorkerPool: воркер %d восстановился после паники: %v", id, r)
				}
			}()

			task()
		}()
	}

	log.Printf("WorkerPool: воркер %d завершил работу", id)
}

// Submit добавляет задачу в пул на выполнение
func (p *WorkerPool) Submit(task func()) bool {
	// Проверяем, не завершается ли пул
	if atomic.LoadInt32(&p.shuttingDown) == 1 {
		return false
	}

	select {
	case p.tasks <- task:
		return true
	default:
		// Если буфер переполнен, возвращаем false
		return false
	}
}

// Stop останавливает все воркеры и ожидает их завершения
func (p *WorkerPool) Stop() {
	atomic.StoreInt32(&p.shuttingDown, 1)
	close(p.tasks)
	p.wg.Wait()
	log.Printf("WorkerPool: пул остановлен, все воркеры завершили работу")
}

// ShardedHub представляет собой хаб с шардированием клиентов
// для эффективной обработки большого числа подключений
type ShardedHub struct {
	// Шарды для распределения клиентов
	shards []*Shard

	// Количество шардов
	shardCount int

	// Максимальное количество клиентов в шарде
	maxClientsPerShard int

	// Менеджер метрик
	metrics *HubMetrics

	// Компонент для межсерверного взаимодействия
	cluster *ClusterHub

	// Канал для завершения работы фоновых горутин
	done chan struct{}

	// Пул воркеров для обработки задач
	workerPool *WorkerPool

	// Каналы для алертинга
	alertChan chan AlertMessage

	// Функция для обработки алертов (может быть заменена пользователем)
	alertHandler func(AlertMessage)

	// Мьютекс для безопасной работы с alertHandler
	alertMu sync.RWMutex

	// Добавляем хранилище для информации о других узлах кластера
	clusterPeers sync.Map // Ключ: InstanceID, Значение: map[string]interface{} (распарсенные метрики)

	// Добавляем зависимость для проверки Redis
	cacheRepo repository.CacheRepository

	// Мьютекс для защиты доступа к срезу shards
	shardsMu sync.RWMutex
}

// AlertType определяет тип алерта
type AlertType string

const (
	// AlertHotShard сигнализирует о "горячем" шарде
	AlertHotShard AlertType = "hot_shard"

	// AlertMessageLoss сигнализирует о потерянных сообщениях
	AlertMessageLoss AlertType = "message_loss"

	// AlertBufferOverflow сигнализирует о переполнении буфера
	AlertBufferOverflow AlertType = "buffer_overflow"

	// AlertHighLatency сигнализирует о высокой задержке обработки сообщений
	AlertHighLatency AlertType = "high_latency"
)

// AlertSeverity определяет уровень серьезности алерта
type AlertSeverity string

const (
	// AlertInfo информационный уровень
	AlertInfo AlertSeverity = "info"

	// AlertWarning уровень предупреждения
	AlertWarning AlertSeverity = "warning"

	// AlertCritical критический уровень
	AlertCritical AlertSeverity = "critical"
)

// AlertMessage представляет сообщение алерта
type AlertMessage struct {
	// Тип алерта
	Type AlertType `json:"type"`

	// Уровень серьезности
	Severity AlertSeverity `json:"severity"`

	// Сообщение
	Message string `json:"message"`

	// Метаданные алерта
	Metadata map[string]interface{} `json:"metadata"`

	// Время создания
	Timestamp time.Time `json:"timestamp"`
}

// Проверка компилятором, что ShardedHub реализует интерфейс HubInterface
var _ HubInterface = (*ShardedHub)(nil)

// Проверка компилятором, что ShardedHub реализует интерфейс ClusterAwareHub
var _ ClusterAwareHub = (*ShardedHub)(nil)

// GlobalMetrics содержит общие метрики для всех шардов
type GlobalMetrics struct {
	TotalConnections int64
	MessagesSent     int64
	MessagesReceived int64
	ConnectionErrors int64
	ActiveShards     int
}

// NewShardedHub создает новый ShardedHub с указанной конфигурацией и Pub/Sub провайдером
func NewShardedHub(wsConfig config.WebSocketConfig, provider PubSubProvider, cacheRepo repository.CacheRepository) *ShardedHub {
	shardCount := wsConfig.Sharding.ShardCount
	if shardCount <= 0 {
		shardCount = 4 // Значение по умолчанию
		log.Printf("[ShardedHub] Используется количество шардов по умолчанию: %d", shardCount)
	}
	maxClientsPerShard := wsConfig.Sharding.MaxClientsPerShard
	if maxClientsPerShard <= 0 {
		maxClientsPerShard = 5000 // Значение по умолчанию
		log.Printf("[ShardedHub] Используется макс. клиентов на шард по умолчанию: %d", maxClientsPerShard)
	}

	metrics := NewHubMetrics()

	// Создаем пул воркеров
	workerPool := NewWorkerPool(shardCount * 2)
	workerPool.Start()

	hub := &ShardedHub{
		shardCount:         shardCount,
		maxClientsPerShard: maxClientsPerShard,
		metrics:            metrics,
		done:               make(chan struct{}),
		workerPool:         workerPool,
		alertChan:          make(chan AlertMessage, 1000),
		cacheRepo:          cacheRepo,
	}

	// Инициализируем обработчик алертов по умолчанию
	hub.alertHandler = hub.defaultAlertHandler

	// Создаем шарды
	hub.shards = make([]*Shard, shardCount)
	for i := 0; i < shardCount; i++ {
		// Получаем интервал очистки
		cleanupInterval := time.Duration(wsConfig.Limits.CleanupInterval) * time.Second
		if cleanupInterval <= 0 {
			// Устанавливаем значение по умолчанию, если не задано или некорректно
			cleanupInterval = 5 * time.Minute
			log.Printf("[ShardedHub] Используется интервал очистки по умолчанию: %v", cleanupInterval)
		}
		// Считаем, что PongWait уже включает в себя необходимый запас времени
		// и является подходящим таймаутом неактивности.
		inactivityTimeout := time.Duration(wsConfig.Limits.PongWait) * time.Second
		if inactivityTimeout <= 0 {
			// Устанавливаем значение по умолчанию, если не задано или некорректно
			inactivityTimeout = 60 * time.Second
			log.Printf("[ShardedHub] Используется таймаут неактивности по умолчанию: %v", inactivityTimeout)
		}

		hub.shards[i] = NewShard(i, hub, maxClientsPerShard, cleanupInterval, inactivityTimeout, hub.cacheRepo)
		// Запускаем каждый шард в отдельной горутине
		go hub.shards[i].Run()
	}

	// Создаем компонент для кластерного режима
	hub.cluster = NewClusterHub(hub, wsConfig.Cluster, provider)

	log.Printf("ShardedHub создан с %d шардами", hub.shardCount)
	return hub
}

// defaultAlertHandler обрабатывает алерты по умолчанию - просто логирует их
func (h *ShardedHub) defaultAlertHandler(alert AlertMessage) {
	switch alert.Severity {
	case AlertCritical:
		log.Printf("[КРИТИЧЕСКИЙ АЛЕРТ] %s: %s", alert.Type, alert.Message)
	case AlertWarning:
		log.Printf("[ПРЕДУПРЕЖДЕНИЕ] %s: %s", alert.Type, alert.Message)
	default:
		log.Printf("[ИНФО] %s: %s", alert.Type, alert.Message)
	}

	// Логируем метаданные для отладки
	metadataJson, _ := json.Marshal(alert.Metadata)
	log.Printf("[АЛЕРТ ДЕТАЛИ] %s", string(metadataJson))
}

// SetAlertHandler устанавливает пользовательский обработчик алертов
func (h *ShardedHub) SetAlertHandler(handler func(AlertMessage)) {
	h.alertMu.Lock()
	defer h.alertMu.Unlock()
	h.alertHandler = handler
}

// SendAlert отправляет алерт
func (h *ShardedHub) SendAlert(alertType AlertType, severity AlertSeverity, message string, metadata map[string]interface{}) {
	alert := AlertMessage{
		Type:      alertType,
		Severity:  severity,
		Message:   message,
		Metadata:  metadata,
		Timestamp: time.Now(),
	}

	// Отправляем неблокирующим способом
	select {
	case h.alertChan <- alert:
		// Успешно отправлено
	default:
		// Буфер алертов переполнен, логируем это напрямую
		log.Printf("[ПЕРЕПОЛНЕНИЕ БУФЕРА АЛЕРТОВ] %s: %s", alertType, message)
	}
}

// Run запускает все шарды и кластерный компонент
func (h *ShardedHub) Run() {
	log.Printf("ShardedHub: запуск с %d шардами, до %d клиентов на шард",
		h.shardCount, h.maxClientsPerShard)

	// Запускаем все шарды
	for _, shard := range h.shards {
		go shard.Run()
	}

	// Запускаем сбор метрик
	go h.collectMetrics()

	// Запускаем кластерный компонент
	if err := h.cluster.Start(); err != nil {
		log.Printf("ShardedHub: ошибка запуска кластерного компонента: %v", err)
	}

	// Запускаем обработчик алертов
	go h.handleAlerts()

	// Ожидаем сигнал завершения работы
	<-h.done
	log.Println("ShardedHub: завершение работы")
}

// getShardID вычисляет ID шарда для указанного userID
func (h *ShardedHub) getShardID(userID string) int {
	if userID == "" {
		// Для пустых userID используем псевдослучайное значение на основе времени
		// вместо всегда последнего шарда, чтобы избежать его перегрузки
		now := time.Now().UnixNano()
		return int(now % int64(h.shardCount))
	}

	// Используем хеш-функцию для равномерного распределения
	hasher := fnv.New32a()
	hasher.Write([]byte(userID))
	return int(hasher.Sum32() % uint32(h.shardCount))
}

// getShard возвращает шард для указанного userID
func (h *ShardedHub) getShard(userID string) *Shard {
	shardID := h.getShardID(userID)
	return h.shards[shardID]
}

// RegisterClient регистрирует клиента в соответствующем шарде
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) RegisterClient(client *Client) {
	shard := h.getShard(client.UserID)
	shard.register <- client
}

// RegisterSync регистрирует клиента и ожидает завершения регистрации
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) RegisterSync(client *Client, done chan struct{}) {
	// Добавляем канал обратного вызова в клиента
	client.registrationComplete = done

	// Регистрируем клиента в соответствующем шарде
	shard := h.getShard(client.UserID)
	shard.register <- client
}

// UnregisterClient отменяет регистрацию клиента
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) UnregisterClient(client *Client) {
	shard := h.getShard(client.UserID)
	shard.unregister <- client
}

// Broadcast отправляет сообщение всем клиентам
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) Broadcast(message []byte) {
	h.BroadcastBytes(message)
}

// BroadcastBytes отправляет байтовое сообщение всем клиентам во всех шардах.
// Если включен кластер, сообщение отправляется через Pub/Sub.
// Если кластер отключен, сообщение отправляется напрямую всем локальным шардам.
func (h *ShardedHub) BroadcastBytes(message []byte) {
	if h.cluster != nil {
		// В кластерном режиме отправляем только через Pub/Sub.
		// Локальная доставка произойдет при получении этого сообщения в handleBroadcastMessages.
		if err := h.cluster.BroadcastToCluster(message); err != nil {
			log.Printf("[ShardedHub] Ошибка отправки broadcast сообщения в кластер: %v", err)
		}
	} else {
		// Если кластер отключен, рассылаем только локально.
		h.BroadcastBytesLocal(message)
	}
}

// BroadcastBytesLocal отправляет байтовое сообщение всем локальным шардам через worker pool.
// Этот метод используется для внутренней локальной рассылки.
func (h *ShardedHub) BroadcastBytesLocal(message []byte) {
	// Используем пул воркеров для асинхронной отправки сообщения каждому шарду
	for _, shard := range h.shards {
		// Захватываем переменную shard для замыкания
		currentShard := shard
		success := h.workerPool.Submit(func() {
			// Отправляем сообщение в канал broadcast конкретного шарда
			// Shard.Run() обработает это сообщение и разошлет клиентам
			currentShard.broadcast <- message
		})
		if !success {
			// КРИТИЧЕСКАЯ ОШИБКА: Пул воркеров переполнен, broadcast сообщение не может быть доставлено шарду.
			errMsg := fmt.Sprintf("Критическая ошибка: Пул воркеров переполнен при отправке broadcast в шард %d. Сообщение может быть потеряно.", currentShard.id)
			log.Println("[ShardedHub]", errMsg)
			// Отправляем алерт о системной перегрузке
			h.SendAlert(AlertBufferOverflow, AlertCritical, errMsg,
				map[string]interface{}{
					"shard_id":         currentShard.id,
					"worker_pool_size": h.workerPool.workerCount,
					"task_queue_len":   len(h.workerPool.tasks),
					"component":        "BroadcastBytesLocal",
				})
			// НЕ отбрасываем сообщение, но сигнализируем о проблеме.
			// В идеале, нужна система мониторинга и возможное масштабирование воркеров.
		}
	}
}

// BroadcastJSON сериализует объект в JSON и отправляет его всем клиентам.
func (h *ShardedHub) BroadcastJSON(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	h.BroadcastBytes(data)
	return nil
}

// SendToUser отправляет сообщение конкретному пользователю
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) SendToUser(userID string, message []byte) bool {
	shard := h.getShard(userID)
	result := shard.SendToUser(userID, message)

	// Если пользователь не найден в локальном экземпляре,
	// пробуем отправить через кластер
	if !result && h.cluster != nil {
		go func() {
			if err := h.cluster.SendToUserInCluster(userID, message); err != nil {
				log.Printf("ShardedHub: ошибка отправки сообщения пользователю %s через кластер: %v",
					userID, err)
			}
		}()
	}

	return result
}

// SendJSONToUser отправляет JSON структуру конкретному пользователю
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) SendJSONToUser(userID string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	h.SendToUser(userID, data)
	return nil
}

// BroadcastToQuiz отправляет сообщение всем клиентам указанной викторины во всех шардах.
func (h *ShardedHub) BroadcastToQuiz(quizID uint, message []byte) {
	log.Printf("ShardedHub: Broadcasting message to Quiz %d across all shards", quizID)
	// Используем пул воркеров для параллельной рассылки по шардам
	var wg sync.WaitGroup
	wg.Add(h.shardCount)

	for _, shard := range h.shards {
		// Запускаем рассылку для каждого шарда в отдельной горутине из пула
		currentShard := shard // Захватываем переменную для горутины
		success := h.workerPool.Submit(func() {
			defer wg.Done()
			currentShard.BroadcastToQuiz(quizID, message)
		})
		if !success {
			// Если пул переполнен, выполняем синхронно и логируем
			log.Printf("ShardedHub: Worker pool full, broadcasting to quiz %d in shard %d synchronously", quizID, currentShard.id)
			wg.Done() // Уменьшаем счетчик, так как горутина не будет запущена
			currentShard.BroadcastToQuiz(quizID, message)
		}
	}

	wg.Wait() // Ожидаем завершения рассылки по всем шардам
	log.Printf("ShardedHub: Finished broadcasting to Quiz %d", quizID)
}

// ClientCount возвращает общее количество подключенных клиентов
// Совместимость с интерфейсом старого Hub
func (h *ShardedHub) ClientCount() int {
	var count int
	for _, shard := range h.shards {
		count += shard.GetClientCount()
	}
	return count
}

// GetMetrics возвращает основные метрики хаба
func (h *ShardedHub) GetMetrics() map[string]interface{} {
	return h.metrics.GetBasicMetrics()
}

// GetDetailedMetrics возвращает расширенные метрики хаба, включая шарды и пиры кластера
func (h *ShardedHub) GetDetailedMetrics() map[string]interface{} {
	allMetrics := h.metrics.GetAllMetrics()

	// Добавляем метрики шардов
	shardMetrics := make([]map[string]interface{}, h.shardCount)
	for i, shard := range h.shards {
		shardMetrics[i] = shard.GetMetrics()
	}
	allMetrics["shards"] = shardMetrics

	// Добавляем информацию о пирах кластера
	peerMetrics := make(map[string]interface{})
	h.clusterPeers.Range(func(key, value interface{}) bool {
		instanceID := key.(string)
		peerMetrics[instanceID] = value // Значение уже должно быть map[string]interface{}
		return true
	})
	allMetrics["cluster_peers"] = peerMetrics

	return allMetrics
}

// collectMetrics периодически собирает метрики со всех шардов
func (h *ShardedHub) collectMetrics() {
	log.Println("ShardedHub: сбор метрик")

	// Создаем метрики для всех шардов
	shardMetrics := make([]map[string]interface{}, h.shardCount)
	hotShards := make([]int, 0)
	totalConnections := int64(0)
	maxLoad := float64(0)
	maxLoadShardID := -1

	// Собираем метрики со всех шардов
	for i, shard := range h.shards {
		metrics := shard.GetMetrics()
		shardMetrics[i] = metrics

		// Обновляем общее количество соединений
		if connections, ok := metrics["active_connections"].(int); ok {
			totalConnections += int64(connections)
		}

		// Проверяем нагрузку шарда
		if loadPercentage, ok := metrics["load_percentage"].(float64); ok {
			if loadPercentage > maxLoad {
				maxLoad = loadPercentage
				maxLoadShardID = i
			}

			// Определяем "горячие" шарды
			if loadPercentage > 75 {
				hotShards = append(hotShards, i)

				// Отправляем алерт для "горячего" шарда
				severity := AlertWarning
				if loadPercentage > 90 {
					severity = AlertCritical
				}

				h.SendAlert(AlertHotShard, severity,
					fmt.Sprintf("Обнаружен горячий шард %d с загрузкой %.2f%%", i, loadPercentage),
					map[string]interface{}{
						"shard_id":           i,
						"load_percentage":    loadPercentage,
						"active_connections": metrics["active_connections"],
						"max_clients":        metrics["max_clients"],
					})
			}

			// Проверяем статистику отключений, если доступна
			if disconnectionStats, ok := metrics["disconnection_stats"].(map[string]interface{}); ok {
				if bufferAlert, ok := disconnectionStats["buffer_alert_triggered"].(bool); ok && bufferAlert {
					h.SendAlert(AlertBufferOverflow, AlertCritical,
						fmt.Sprintf("Переполнение буфера отключений в шарде %d", i),
						map[string]interface{}{
							"shard_id":            i,
							"disconnection_stats": disconnectionStats,
						})
				}
			}
		}
	}

	// Обновляем метрики хаба
	h.metrics.mu.Lock()
	h.metrics.activeConnections = totalConnections
	h.metrics.UpdateShardMetrics(shardMetrics)
	h.metrics.mu.Unlock()

	// Проверяем, нужна ли балансировка
	if len(hotShards) > 0 {
		log.Printf("ShardedHub: обнаружены горячие шарды: %v", hotShards)

		// Отправляем общий алерт о "горячих" шардах
		h.SendAlert(AlertHotShard, AlertWarning,
			fmt.Sprintf("Обнаружено %d горячих шардов, максимальная нагрузка %.2f%% (шард %d)",
				len(hotShards), maxLoad, maxLoadShardID),
			map[string]interface{}{
				"hot_shards":        hotShards,
				"max_load":          maxLoad,
				"max_load_shard":    maxLoadShardID,
				"total_connections": totalConnections,
			})
	}
}

// Close закрывает все шарды и освобождает ресурсы
func (h *ShardedHub) Close() {
	log.Println("ShardedHub: закрытие всех шардов")

	// Закрываем кластерный компонент
	if h.cluster != nil {
		h.cluster.Stop()
	}

	// Закрываем все шарды
	for _, shard := range h.shards {
		shard.Close()
	}

	// Закрываем пул воркеров
	if h.workerPool != nil {
		h.workerPool.Stop()
	}

	// Сигнал для завершения фоновых горутин
	close(h.done)

	log.Println("ShardedHub: все ресурсы освобождены")
}

// BroadcastPrioritized отправляет высокоприоритетное сообщение всем клиентам
// с дополнительными гарантиями доставки
func (h *ShardedHub) BroadcastPrioritized(message []byte) error {
	log.Printf("ShardedHub: рассылка высокоприоритетного сообщения")

	// Создаем WaitGroup для ожидания завершения отправки во все шарды
	var wg sync.WaitGroup
	wg.Add(len(h.shards))

	// Увеличенные буферы для высокоприоритетных сообщений
	// чтобы гарантировать, что они не будут отброшены
	for _, shard := range h.shards {
		// Используем пул воркеров для распределения нагрузки
		currentShard := shard // Создаем локальную копию для замыкания
		if !h.workerPool.Submit(func() {
			defer wg.Done()

			// Для высокоприоритетных сообщений блокируем отправку,
			// чтобы гарантировать доставку
			select {
			case currentShard.broadcast <- message:
				// Сообщение успешно отправлено в канал рассылки
			case <-time.After(100 * time.Millisecond): // Уменьшаем таймаут
				// Если канал полный, обрабатываем сообщение напрямую
				log.Printf("Shard %d: приоритетная отправка через прямую рассылку (канал broadcast переполнен)", currentShard.id)

				// Подсчитываем клиентов для метрик
				var clientCount int

				// Выполняем прямую рассылку клиентам
				currentShard.clients.Range(func(key, value interface{}) bool {
					client, ok := key.(*Client)
					if !ok {
						return true // Пропускаем некорректные записи
					}

					// Блокирующая отправка с таймаутом
					select {
					case client.send <- message:
						clientCount++
					case <-time.After(100 * time.Millisecond): // Уменьшаем таймаут
						// Если буфер клиента переполнен и не освобождается, обрабатываем ошибку
						log.Printf("Shard %d: не удалось отправить приоритетное сообщение клиенту %s (таймаут отправки)",
							currentShard.id, client.UserID)
					}

					return true
				})

				// Обновляем метрики
				if clientCount > 0 {
					currentShard.metrics.mu.Lock()
					currentShard.metrics.messagesSent += int64(clientCount)
					currentShard.metrics.mu.Unlock()

					log.Printf("Shard %d: приоритетное сообщение отправлено %d клиентам напрямую",
						currentShard.id, clientCount)
				}
			}
		}) {
			// Если пул воркеров переполнен, выполняем задачу напрямую
			log.Printf("ShardedHub: пул воркеров переполнен, выполняем задачу напрямую для шарда %d", shard.id)
			go func(s *Shard) {
				defer wg.Done()
				s.BroadcastBytes(message)
			}(shard)
		}
	}

	// Ожидаем завершения отправки во все шарды
	wg.Wait()

	// Если включен кластерный режим, отправляем сообщение в другие экземпляры
	if h.cluster != nil {
		go h.cluster.BroadcastToCluster(message)
	}

	return nil
}

// handleAlerts обрабатывает алерты
func (h *ShardedHub) handleAlerts() {
	for {
		select {
		case alert := <-h.alertChan:
			h.alertMu.RLock()
			handler := h.alertHandler
			h.alertMu.RUnlock()

			if handler != nil {
				handler(alert)
			}
		case <-h.done:
			return
		}
	}
}

// GetInstanceID возвращает уникальный ID этого экземпляра хаба
func (h *ShardedHub) GetInstanceID() string {
	if h.cluster != nil && h.cluster.config.Enabled {
		return h.cluster.config.InstanceID
	}
	// Возвращаем какой-то дефолтный ID, если кластер отключен
	// Возможно, стоит генерировать его при создании ShardedHub всегда
	return "standalone_instance"
}

// AddClusterPeer добавляет или обновляет информацию о другом узле кластера
func (h *ShardedHub) AddClusterPeer(instanceID string, metricsData json.RawMessage) {
	var metrics map[string]interface{}
	if err := json.Unmarshal(metricsData, &metrics); err != nil {
		log.Printf("ShardedHub: Ошибка десериализации метрик от пира %s: %v", instanceID, err)
		return
	}
	// Добавляем временную метку получения метрик
	metrics["last_seen"] = time.Now().Format(time.RFC3339)
	h.clusterPeers.Store(instanceID, metrics)
	log.Printf("ShardedHub: Обновлены метрики для пира %s", instanceID)
}

// RemoveClusterPeer удаляет информацию об узле кластера
func (h *ShardedHub) RemoveClusterPeer(instanceID string) {
	if _, loaded := h.clusterPeers.LoadAndDelete(instanceID); loaded {
		log.Printf("ShardedHub: Удален пир %s из списка", instanceID)
	}
}

// GetActiveSubscribers возвращает список UserID активных (не выбывших) подписчиков для викторины.
// Собирает данные со всех шардов.
func (h *ShardedHub) GetActiveSubscribers(quizID uint) ([]uint, error) {
	var allActiveSubscribers []uint
	var wg sync.WaitGroup
	var mu sync.Mutex                           // Мьютекс для безопасного добавления в общий слайс
	errorChan := make(chan error, h.shardCount) // Канал для сбора ошибок от шардов

	// Используем shardsMu для защиты доступа к срезу shards
	h.shardsMu.RLock()
	defer h.shardsMu.RUnlock()

	if len(h.shards) == 0 {
		log.Printf("ShardedHub: GetActiveSubscribers called, but no shards available for quiz %d", quizID)
		return []uint{}, nil // Нет шардов - нет подписчиков
	}

	wg.Add(len(h.shards))
	for _, shard := range h.shards {
		go func(s *Shard) {
			defer wg.Done()
			activeInShard, err := s.getActiveSubscribersForQuiz(quizID)
			if err != nil {
				// Логируем ошибку и отправляем в канал
				log.Printf("[ShardedHub] Ошибка при получении активных подписчиков из шарда %d для викторины %d: %v", s.id, quizID, err)
				errorChan <- fmt.Errorf("ошибка в шарде %d: %w", s.id, err)
				return
			}
			if len(activeInShard) > 0 {
				mu.Lock()
				allActiveSubscribers = append(allActiveSubscribers, activeInShard...)
				mu.Unlock()
			}
		}(shard)
	}

	wg.Wait()
	close(errorChan) // Закрываем канал ошибок после завершения всех горутин

	// Проверяем, были ли ошибки в шардах
	var firstError error // Сохраним первую ошибку для возврата, если нужно
	for err := range errorChan {
		if firstError == nil {
			firstError = err
		}
		// Продолжаем логировать все ошибки
		log.Printf("[ShardedHub] Ошибка при получении активных подписчиков викторины %d: %v", quizID, err)
		// Решаем не прерывать и вернуть собранные данные + первую ошибку
	}

	log.Printf("[ShardedHub] Найдено %d активных подписчиков для викторины %d", len(allActiveSubscribers), quizID)
	// Возвращаем собранные данные и первую ошибку (или nil, если ошибок не было)
	return allActiveSubscribers, firstError
}

// minInt возвращает минимальное из переданных целых чисел
func minInt(nums ...int) int {
	if len(nums) == 0 {
		panic("minInt: no numbers provided")
	}
	min := nums[0]
	for _, num := range nums[1:] {
		if num < min {
			min = num
		}
	}
	return min
}

// TODO: Implement shard rebalancing logic if needed in the future.
// Рекомендуется проводить ребалансировку между игровыми сессиями, а не во время активной викторины.
