package websocket

import (
	"sync"
	"time"
)

// HubMetrics представляет агрегированные метрики всего WebSocket-сервера
type HubMetrics struct {
	// Основные метрики
	totalConnections       int64     // Общее количество подключений за все время
	activeConnections      int64     // Текущее количество активных подключений
	messagesSent           int64     // Общее количество отправленных сообщений
	messagesReceived       int64     // Общее количество полученных сообщений
	connectionErrors       int64     // Общее количество ошибок соединений
	inactiveClientsRemoved int64     // Общее количество удаленных неактивных клиентов
	startTime              time.Time // Время запуска сервера
	lastCleanupTime        time.Time // Время последней очистки

	// Детальные метрики по типам сообщений
	messageTypeCounts map[string]int64 // Счетчики сообщений по типам

	// Метрики шардирования
	shardMetrics      []map[string]interface{} // Метрики всех шардов
	shardDistribution map[int]int              // Распределение клиентов по шардам
	hotShards         []int                    // ID "горячих" шардов (с высокой нагрузкой)

	// Мьютекс для безопасного обновления метрик
	mu sync.RWMutex
}

// NewHubMetrics создает новый экземпляр метрик Hub
func NewHubMetrics() *HubMetrics {
	return &HubMetrics{
		startTime:         time.Now(),
		lastCleanupTime:   time.Now(),
		messageTypeCounts: make(map[string]int64),
		shardDistribution: make(map[int]int),
		hotShards:         make([]int, 0),
	}
}

// IncrementTotalConnections увеличивает счетчик общего количества подключений
func (m *HubMetrics) IncrementTotalConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.totalConnections++
	m.activeConnections++
}

// DecrementActiveConnections уменьшает счетчик активных подключений
func (m *HubMetrics) DecrementActiveConnections() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.activeConnections > 0 {
		m.activeConnections--
	}
}

// AddMessageSent увеличивает счетчик отправленных сообщений
func (m *HubMetrics) AddMessageSent(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagesSent += count
}

// AddMessageReceived увеличивает счетчик полученных сообщений
func (m *HubMetrics) AddMessageReceived() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messagesReceived++
}

// AddConnectionError увеличивает счетчик ошибок соединений
func (m *HubMetrics) AddConnectionError() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectionErrors++
}

// AddInactiveClientsRemoved увеличивает счетчик удаленных неактивных клиентов
func (m *HubMetrics) AddInactiveClientsRemoved(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inactiveClientsRemoved += count
}

// UpdateLastCleanupTime обновляет время последней очистки
func (m *HubMetrics) UpdateLastCleanupTime() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastCleanupTime = time.Now()
}

// IncrementMessageTypeCount увеличивает счетчик сообщений определенного типа
func (m *HubMetrics) IncrementMessageTypeCount(messageType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messageTypeCounts[messageType]++
}

// UpdateShardMetrics обновляет метрики всех шардов
func (m *HubMetrics) UpdateShardMetrics(metrics []map[string]interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shardMetrics = metrics

	// Обновляем распределение клиентов по шардам
	m.shardDistribution = make(map[int]int)
	m.hotShards = make([]int, 0)

	for _, shardMetric := range metrics {
		shardID, ok := shardMetric["shard_id"].(int)
		if !ok {
			continue
		}

		connections, ok := shardMetric["active_connections"].(int)
		if !ok {
			continue
		}

		m.shardDistribution[shardID] = connections

		// Определяем "горячие" шарды (> 75% загрузки)
		loadPercentage, ok := shardMetric["load_percentage"].(float64)
		if !ok {
			continue
		}

		if loadPercentage > 75 {
			m.hotShards = append(m.hotShards, shardID)
		}
	}
}

// GetAllMetrics возвращает все метрики в формате карты для JSON-ответа
func (m *HubMetrics) GetAllMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Рассчитываем время работы
	uptime := time.Since(m.startTime).Seconds()

	// Собираем метрики по типам сообщений
	messageStats := make(map[string]int64)
	for messageType, count := range m.messageTypeCounts {
		messageStats[messageType] = count
	}

	// Формируем итоговую карту
	return map[string]interface{}{
		// Основные метрики
		"total_connections":        m.totalConnections,
		"active_connections":       m.activeConnections,
		"messages_sent":            m.messagesSent,
		"messages_received":        m.messagesReceived,
		"connection_errors":        m.connectionErrors,
		"inactive_clients_removed": m.inactiveClientsRemoved,
		"uptime_seconds":           uptime,
		"start_time":               m.startTime.Format(time.RFC3339),
		"last_cleanup":             m.lastCleanupTime.Format(time.RFC3339),

		// Детальные метрики
		"message_type_stats": messageStats,
		"shard_metrics":      m.shardMetrics,
		"shard_distribution": m.shardDistribution,
		"hot_shards":         m.hotShards,
		"shard_count":        len(m.shardMetrics),
		"avg_connections_per_shard": func() float64 {
			if len(m.shardMetrics) == 0 {
				return 0
			}
			return float64(m.activeConnections) / float64(len(m.shardMetrics))
		}(),
	}
}

// GetBasicMetrics возвращает базовые метрики для совместимости с существующим API
func (m *HubMetrics) GetBasicMetrics() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	uptime := time.Since(m.startTime).Seconds()

	return map[string]interface{}{
		"total_connections":        m.totalConnections,
		"active_connections":       m.activeConnections,
		"messages_sent":            m.messagesSent,
		"messages_received":        m.messagesReceived,
		"connection_errors":        m.connectionErrors,
		"inactive_clients_removed": m.inactiveClientsRemoved,
		"uptime_seconds":           uptime,
		"last_cleanup":             m.lastCleanupTime.Format(time.RFC3339),
	}
}
