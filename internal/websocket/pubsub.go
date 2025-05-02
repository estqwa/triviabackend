package websocket

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/yourusername/trivia-api/internal/config"
)

// Определяем интерфейс здесь, так как создание файла не сработало
// ClusterAwareHub определяет интерфейс для хаба, который может работать в кластере
type ClusterAwareHub interface {
	// BroadcastBytes отправляет байтовое сообщение всем локальным клиентам, принадлежащим этому хабу/шарду.
	// Это НЕ отправляет сообщение в кластер.
	BroadcastBytes(message []byte)

	// BroadcastBytesLocal отправляет байтовое сообщение только локальным клиентам этого инстанса.
	// Используется для предотвращения циклов при получении сообщения из кластера.
	BroadcastBytesLocal(message []byte)

	// SendToUser отправляет байтовое сообщение конкретному локальному пользователю.
	// Возвращает true, если клиент найден локально и сообщение отправлено (или поставлено в очередь), иначе false.
	SendToUser(userID string, message []byte) bool

	// GetInstanceID возвращает уникальный ID этого экземпляра хаба.
	GetInstanceID() string

	// GetMetrics возвращает метрики этого экземпляра хаба (локальные метрики).
	GetMetrics() map[string]interface{}

	// AddClusterPeer добавляет или обновляет информацию о другом узле кластера.
	AddClusterPeer(instanceID string, metrics json.RawMessage) // Используем json.RawMessage для метрик

	// RemoveClusterPeer удаляет информацию об узле кластера.
	RemoveClusterPeer(instanceID string)
}

// PubSubProvider определяет интерфейс для провайдеров публикации/подписки
type PubSubProvider interface {
	// Publish публикует сообщение в указанный канал
	Publish(channel string, message []byte) error

	// Subscribe подписывается на указанный канал и возвращает канал для сообщений
	Subscribe(ctx context.Context, channel string) (<-chan []byte, error)

	// Close закрывает все соединения и освобождает ресурсы
	Close() error
}

// ClusterMessage представляет сообщение, передаваемое между экземплярами Hub
type ClusterMessage struct {
	// MessageType определяет тип сообщения кластера
	// broadcast - широковещательное сообщение для всех клиентов
	// direct - сообщение для конкретного пользователя
	// metrics - обновление метрик кластера
	MessageType string `json:"type"`

	// RecipientID содержит ID получателя для direct-сообщений
	RecipientID string `json:"recipient_id,omitempty"`

	// InstanceID содержит ID отправителя для избежания дублирования
	InstanceID string `json:"instance_id"`

	// Payload содержит данные сообщения
	Payload json.RawMessage `json:"payload"`

	// Timestamp содержит время создания сообщения
	Timestamp time.Time `json:"timestamp"`
}

// NoOpPubSub реализует PubSubProvider для одиночного режима работы
// Этот провайдер не выполняет реальных действий и используется, когда
// горизонтальное масштабирование отключено
type NoOpPubSub struct{}

// Publish реализует метод PubSubProvider.Publish для NoOpPubSub
func (p *NoOpPubSub) Publish(channel string, message []byte) error {
	// Ничего не делаем в одиночном режиме
	return nil
}

// Subscribe реализует метод PubSubProvider.Subscribe для NoOpPubSub
func (p *NoOpPubSub) Subscribe(ctx context.Context, channel string) (<-chan []byte, error) {
	// Возвращаем пустой канал, который никогда не получит сообщения
	msgCh := make(chan []byte)
	go func() {
		<-ctx.Done()
		close(msgCh)
	}()
	return msgCh, nil
}

// Close реализует метод PubSubProvider.Close для NoOpPubSub
func (p *NoOpPubSub) Close() error {
	return nil
}

// ClusterHub управляет взаимодействием экземпляра Hub с кластером через Pub/Sub
type ClusterHub struct {
	config config.ClusterConfig // Используем тип из пакета config
	parent ClusterAwareHub      // Изменено с interface{} на ClusterAwareHub
	// Добавляем провайдера сюда, так как он не в config.ClusterConfig
	Provider PubSubProvider
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// NewClusterHub создает новый экземпляр ClusterHub
func NewClusterHub(parent ClusterAwareHub, cfg config.ClusterConfig, provider PubSubProvider) *ClusterHub {
	ctx, cancel := context.WithCancel(context.Background())
	instanceID := cfg.InstanceID
	if instanceID == "" {
		instanceID = generateInstanceID()
		log.Printf("ClusterHub: Instance ID не задан, сгенерирован: %s", instanceID)
	}

	// Проверяем провайдера
	if provider == nil {
		log.Println("ClusterHub: Провайдер Pub/Sub не предоставлен, используется NoOpPubSub")
		provider = &NoOpPubSub{}
	}

	ch := &ClusterHub{
		config:   cfg, // Сохраняем переданную конфигурацию
		parent:   parent,
		Provider: provider, // Сохраняем провайдера
		ctx:      ctx,
		cancel:   cancel,
	}
	// Устанавливаем правильный InstanceID в конфигурации, если он был сгенерирован
	ch.config.InstanceID = instanceID

	return ch
}

// Start запускает обработку сообщений кластера
func (ch *ClusterHub) Start() error {
	if !ch.config.Enabled {
		log.Println("ClusterHub: кластерный режим отключен, работаем в автономном режиме")
		return nil
	}

	log.Printf("ClusterHub: запуск кластерного режима, ID экземпляра: %s", ch.config.InstanceID)

	// Подписываемся на широковещательные сообщения
	ch.wg.Add(1)
	go func() {
		defer ch.wg.Done()
		ch.handleBroadcastMessages()
	}()

	// Подписываемся на прямые сообщения
	ch.wg.Add(1)
	go func() {
		defer ch.wg.Done()
		ch.handleDirectMessages()
	}()

	// Запускаем периодическую отправку метрик
	ch.wg.Add(1)
	go func() {
		defer ch.wg.Done()
		ch.publishMetrics()
	}()

	return nil
}

// Stop останавливает обработку сообщений кластера
func (ch *ClusterHub) Stop() {
	if !ch.config.Enabled {
		return
	}

	log.Println("ClusterHub: остановка кластерного режима")
	ch.cancel()
	ch.wg.Wait()
}

// BroadcastToCluster отправляет широковещательное сообщение всем экземплярам Hub
func (ch *ClusterHub) BroadcastToCluster(payload []byte) error {
	if !ch.config.Enabled {
		return nil
	}

	msg := ClusterMessage{
		MessageType: "broadcast",
		InstanceID:  ch.config.InstanceID,
		Payload:     payload,
		Timestamp:   time.Now(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return ch.Provider.Publish(ch.config.BroadcastChannel, data)
}

// SendToUserInCluster отправляет сообщение конкретному пользователю через кластер
func (ch *ClusterHub) SendToUserInCluster(userID string, payload []byte) error {
	if !ch.config.Enabled {
		return nil
	}

	msg := ClusterMessage{
		MessageType: "direct",
		RecipientID: userID,
		InstanceID:  ch.config.InstanceID,
		Payload:     payload,
		Timestamp:   time.Now(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return ch.Provider.Publish(ch.config.DirectChannel, data)
}

// handleBroadcastMessages обрабатывает входящие широковещательные сообщения
func (ch *ClusterHub) handleBroadcastMessages() {
	broadcastCh, err := ch.Provider.Subscribe(ch.ctx, ch.config.BroadcastChannel)
	if err != nil {
		log.Printf("ClusterHub: ошибка подписки на канал %s: %v", ch.config.BroadcastChannel, err)
		return
	}

	log.Printf("ClusterHub: начата обработка широковещательных сообщений")

	for {
		select {
		case <-ch.ctx.Done():
			return
		case data, ok := <-broadcastCh:
			if !ok {
				log.Println("ClusterHub: канал широковещательных сообщений закрыт")
				return
			}

			var msg ClusterMessage
			if err := json.Unmarshal(data, &msg); err != nil {
				log.Printf("ClusterHub: ошибка десериализации широковещательного сообщения: %v, Сообщение: %s", err, string(data))
				continue
			}

			// Пропускаем сообщения от самого себя
			if msg.InstanceID == ch.parent.GetInstanceID() {
				continue
			}

			if msg.MessageType == "broadcast" {
				log.Printf("ClusterHub: получено широковещательное сообщение от %s", msg.InstanceID)
				// Передаем сообщение родительскому хабу для локальной рассылки
				// Используем BroadcastBytesLocal, чтобы избежать повторной отправки в кластер
				ch.parent.BroadcastBytesLocal(msg.Payload)
			} else if msg.MessageType == "metrics" {
				// Обрабатываем метрики от другого узла
				ch.parent.AddClusterPeer(msg.InstanceID, msg.Payload)
			} else {
				log.Printf("ClusterHub: получено неизвестное сообщение в broadcast канале от %s: %s", msg.InstanceID, msg.MessageType)
			}
		}
	}
}

// handleDirectMessages прослушивает канал прямых сообщений и обрабатывает их
func (ch *ClusterHub) handleDirectMessages() {
	defer ch.wg.Done()

	if ch.config.DirectChannel == "" {
		log.Println("[ClusterHub:Direct] Канал прямых сообщений не настроен, обработчик не запущен.")
		return
	}

	msgCh, err := ch.Provider.Subscribe(ch.ctx, ch.config.DirectChannel)
	if err != nil {
		log.Printf("[ClusterHub:Direct] CRITICAL: Не удалось подписаться на канал прямых сообщений %s: %v", ch.config.DirectChannel, err)
		// TODO: Рассмотреть возможность отправки алерта
		return
	}
	log.Printf("[ClusterHub:Direct] Успешно подписан на канал прямых сообщений: %s", ch.config.DirectChannel)

	for {
		select {
		case <-ch.ctx.Done():
			log.Println("[ClusterHub:Direct] Контекст отменен, завершение обработки прямых сообщений.")
			return
		case msgBytes, ok := <-msgCh:
			if !ok {
				log.Println("[ClusterHub:Direct] Канал прямых сообщений закрыт.")
				return // Выход, если канал закрыт
			}

			var msg ClusterMessage
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				log.Printf("[ClusterHub:Direct] Ошибка десериализации сообщения из канала %s: %v. Сообщение: %s", ch.config.DirectChannel, err, string(msgBytes))
				continue
			}

			// Игнорируем сообщения от самого себя
			if msg.InstanceID == ch.config.InstanceID {
				continue
			}

			// Обрабатываем только прямые сообщения
			if msg.MessageType == "direct" && msg.RecipientID != "" {
				log.Printf("[ClusterHub:Direct] Получено прямое сообщение для %s от %s", msg.RecipientID, msg.InstanceID)
				// Отправляем сообщение локальному пользователю, если он есть
				// Ошибку не обрабатываем, т.к. SendToUser сам логирует, если получатель не найден локально
				_ = ch.parent.SendToUser(msg.RecipientID, msg.Payload)
			} else {
				log.Printf("[ClusterHub:Direct] Получено сообщение неверного типа или без получателя в канале %s: %+v", ch.config.DirectChannel, msg)
			}
		}
	}
}

// handleMetricsMessages прослушивает канал метрик и обновляет информацию о пирах
func (ch *ClusterHub) handleMetricsMessages() {
	defer ch.wg.Done()

	if ch.config.MetricsChannel == "" {
		log.Println("[ClusterHub:Metrics] Канал метрик не настроен, обработчик не запущен.")
		return
	}

	// Используем контекст ch.ctx для подписки
	msgCh, err := ch.Provider.Subscribe(ch.ctx, ch.config.MetricsChannel)
	if err != nil {
		log.Printf("[ClusterHub:Metrics] CRITICAL: Не удалось подписаться на канал метрик %s: %v", ch.config.MetricsChannel, err)
		// Здесь можно добавить отправку алерта, если parent это поддерживает
		// Например, через type assertion или отдельный интерфейс
		// if alerter, ok := ch.parent.(AlertSender); ok {
		//     alerter.SendAlert(...)
		// }
		return
	}
	log.Printf("[ClusterHub:Metrics] Успешно подписан на канал метрик: %s", ch.config.MetricsChannel)

	for {
		select {
		case <-ch.ctx.Done():
			log.Println("[ClusterHub:Metrics] Контекст отменен, завершение обработки метрик.")
			return
		case msgBytes, ok := <-msgCh:
			if !ok {
				log.Println("[ClusterHub:Metrics] Канал метрик закрыт.")
				return // Выход, если канал закрыт
			}

			var msg ClusterMessage
			if err := json.Unmarshal(msgBytes, &msg); err != nil {
				log.Printf("[ClusterHub:Metrics] Ошибка десериализации сообщения из канала %s: %v. Сообщение: %s", ch.config.MetricsChannel, err, string(msgBytes))
				continue
			}

			// Игнорируем сообщения от самого себя
			if msg.InstanceID == ch.config.InstanceID {
				continue
			}

			// Обрабатываем сообщения метрик и удаления пиров
			switch msg.MessageType {
			case "metrics":
				log.Printf("[ClusterHub:Metrics] Получены метрики от %s", msg.InstanceID)
				// Ошибка здесь не критична для работы обработчика, просто логируем
				ch.parent.AddClusterPeer(msg.InstanceID, msg.Payload)
			case "peer_removed":
				log.Printf("[ClusterHub:Metrics] Получено уведомление об удалении пира %s", msg.InstanceID)
				// Ошибка здесь не критична для работы обработчика, просто логируем
				ch.parent.RemoveClusterPeer(msg.InstanceID)
			default:
				log.Printf("[ClusterHub:Metrics] Получено сообщение неизвестного типа в канале %s: %+v", ch.config.MetricsChannel, msg)
			}
		}
	}
}

// publishMetrics периодически публикует метрики этого экземпляра в кластер
func (ch *ClusterHub) publishMetrics() {
	if ch.config.MetricsInterval <= 0 {
		log.Println("ClusterHub: Публикация метрик отключена (интервал <= 0)")
		return
	}

	// Преобразуем интервал из конфига (int секунд) в time.Duration
	interval := time.Duration(ch.config.MetricsInterval) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.Printf("ClusterHub: Запуск публикации метрик каждые %v", interval)

	for {
		select {
		case <-ch.ctx.Done():
			// Отправляем сообщение об удалении узла перед выходом
			ch.sendPeerRemovalMessage()
			return
		case <-ticker.C:
			// Получаем метрики от родительского хаба
			metrics := ch.parent.GetMetrics()
			payload, err := json.Marshal(metrics)
			if err != nil {
				log.Printf("ClusterHub: Ошибка сериализации метрик: %v", err)
				continue
			}

			msg := ClusterMessage{
				MessageType: "metrics",
				InstanceID:  ch.parent.GetInstanceID(),
				Payload:     payload,
				Timestamp:   time.Now(),
			}

			data, err := json.Marshal(msg)
			if err != nil {
				log.Printf("ClusterHub: Ошибка сериализации сообщения с метриками: %v", err)
				continue
			}

			// Публикуем метрики в канал метрик
			if err := ch.Provider.Publish(ch.config.MetricsChannel, data); err != nil {
				log.Printf("ClusterHub: Ошибка публикации метрик в %s: %v", ch.config.MetricsChannel, err)
			}
		}
	}
}

// sendPeerRemovalMessage отправляет сообщение об удалении узла из кластера
func (ch *ClusterHub) sendPeerRemovalMessage() {
	// Проверяем, что канал метрик настроен
	if ch.config.MetricsChannel == "" {
		log.Println("ClusterHub: Невозможно отправить сообщение об удалении узла, канал метрик не настроен.")
		return
	}

	log.Printf("ClusterHub: Отправка сообщения об удалении узла %s в канал %s", ch.parent.GetInstanceID(), ch.config.MetricsChannel)
	msg := ClusterMessage{
		MessageType: "peer_removed", // Новый тип сообщения
		InstanceID:  ch.parent.GetInstanceID(),
		Timestamp:   time.Now(),
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("ClusterHub: Ошибка сериализации сообщения об удалении узла: %v", err)
		return
	}
	// Удаляем неиспользуемый контекст
	// ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	// defer cancel()
	// Исправляем вызов Publish - он возвращает просто error
	// Публикуем сообщение об удалении узла в канал метрик
	if err := ch.Provider.Publish(ch.config.MetricsChannel, data); err != nil {
		log.Printf("ClusterHub: Ошибка публикации сообщения об удалении узла в %s: %v", ch.config.MetricsChannel, err)
	}
}

// RedisPubSub реализует PubSubProvider с использованием Redis
type RedisPubSub struct {
	client redis.UniversalClient // Принимаем готовый клиент
	// config        RedisConfig // Удаляем локальную копию конфига
	ctx           context.Context
	cancel        context.CancelFunc
	subscriptions sync.Map   // Хранит активные подписки (channel -> *redis.PubSub)
	mu            sync.Mutex // Защищает доступ к subscriptions
}

// NewRedisPubSub создает новый Redis Pub/Sub провайдер, используя существующий UniversalClient.
func NewRedisPubSub(client redis.UniversalClient) (*RedisPubSub, error) {
	if client == nil {
		return nil, errors.New("redis client cannot be nil for RedisPubSub")
	}

	// Проверяем соединение клиента перед использованием
	ctx, cancelCheck := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelCheck()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("provided redis client failed ping check: %w", err)
	}

	ctxPubSub, cancelPubSub := context.WithCancel(context.Background())

	rp := &RedisPubSub{
		client:        client,
		ctx:           ctxPubSub,
		cancel:        cancelPubSub,
		subscriptions: sync.Map{},
	}

	log.Println("RedisPubSub provider created using existing client.")
	return rp, nil
}

// Publish публикует сообщение в указанный канал
func (p *RedisPubSub) Publish(channel string, message []byte) error {
	// Используем retry логику, вынесенную в config
	cmd := p.client.Publish(p.ctx, channel, message)
	if err := cmd.Err(); err != nil {
		log.Printf("RedisPubSub: Error publishing to channel '%s': %v", channel, err)
		return fmt.Errorf("failed to publish to Redis channel %s: %w", channel, err)
	}
	log.Printf("RedisPubSub: Published message to channel '%s' (Subscribers: %d)", channel, cmd.Val())
	return nil
}

// Subscribe подписывается на указанный канал Redis
func (p *RedisPubSub) Subscribe(ctx context.Context, channel string) (<-chan []byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if sub, ok := p.subscriptions.Load(channel); ok {
		log.Printf("RedisPubSub: Already subscribed to channel '%s'", channel)
		// Возвращаем существующий канал сообщений
		redisSub, ok := sub.(*redis.PubSub)
		if ok {
			// Создаем новый канал-прокси, чтобы не закрыть оригинальный
			msgChProxy := make(chan []byte, 100)
			go func() {
				origCh := redisSub.Channel()
				for {
					select {
					case msg, ok := <-origCh:
						if !ok {
							close(msgChProxy)
							return
						}
						// Пересылаем сообщение в прокси-канал
						select {
						case msgChProxy <- []byte(msg.Payload):
						default:
							log.Printf("RedisPubSub: Proxy channel for '%s' is full. Dropping message.", channel)
						}
					case <-ctx.Done(): // Если контекст нового подписчика завершен
						close(msgChProxy)
						log.Printf("RedisPubSub: Proxy subscription to '%s' cancelled by context.", channel)
						return
					case <-p.ctx.Done(): // Если весь PubSub остановлен
						close(msgChProxy)
						return
					}
				}
			}()
			return msgChProxy, nil
		}
	}

	log.Printf("RedisPubSub: Subscribing to channel '%s'", channel)

	// Создаем новую подписку
	pubsub := p.client.Subscribe(p.ctx, channel)

	// Ждем подтверждения подписки
	_, err := pubsub.Receive(p.ctx)
	if err != nil {
		pubsub.Close() // Закрываем подписку в случае ошибки
		log.Printf("RedisPubSub: Error receiving subscription confirmation for channel '%s': %v", channel, err)
		return nil, fmt.Errorf("failed to subscribe to Redis channel %s: %w", channel, err)
	}

	p.subscriptions.Store(channel, pubsub)
	log.Printf("RedisPubSub: Successfully subscribed to channel '%s'", channel)

	msgCh := make(chan []byte, 100) // Буферизированный канал

	// Запускаем горутину для чтения сообщений из Redis и пересылки в канал
	go func() {
		defer func() {
			p.mu.Lock()
			p.subscriptions.Delete(channel)
			p.mu.Unlock()
			pubsub.Close()
			close(msgCh)
			log.Printf("RedisPubSub: Unsubscribed and closed channel '%s'", channel)
		}()

		redisCh := pubsub.Channel()
		for {
			select {
			case msg, ok := <-redisCh:
				if !ok {
					log.Printf("RedisPubSub: Redis channel '%s' closed by server.", channel)
					return // Канал закрыт со стороны Redis
				}
				// Пересылаем сообщение подписчику
				select {
				case msgCh <- []byte(msg.Payload):
				case <-p.ctx.Done():
					log.Printf("RedisPubSub: Goroutine for channel '%s' stopped by manager context.", channel)
					return
				case <-ctx.Done():
					log.Printf("RedisPubSub: Goroutine for channel '%s' stopped by subscriber context.", channel)
					return
				}
			case <-p.ctx.Done():
				log.Printf("RedisPubSub: Goroutine for channel '%s' stopped by manager context (outer select).", channel)
				return
			case <-ctx.Done():
				log.Printf("RedisPubSub: Goroutine for channel '%s' stopped by subscriber context (outer select).", channel)
				return
			}
		}
	}()

	return msgCh, nil
}

// Close закрывает все соединения Redis и активные подписки
func (p *RedisPubSub) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	log.Println("RedisPubSub: Closing Redis client and all subscriptions...")
	// Отменяем контекст, чтобы остановить все горутины подписок
	p.cancel()

	var lastErr error

	// Закрываем все активные подписки
	p.subscriptions.Range(func(key, value interface{}) bool {
		channel := key.(string)
		pubsub, ok := value.(*redis.PubSub)
		if ok {
			if err := pubsub.Close(); err != nil {
				log.Printf("RedisPubSub: Error closing subscription to channel '%s': %v", channel, err)
				lastErr = err // Сохраняем последнюю ошибку
			}
		}
		return true
	})

	// Закрываем основного клиента Redis
	if p.client != nil {
		if err := p.client.Close(); err != nil {
			log.Printf("RedisPubSub: Error closing Redis client: %v", err)
			lastErr = err
		}
	}

	log.Println("RedisPubSub: Closed.")
	return lastErr
}

// isRedisConnError проверяет, является ли ошибка ошибкой соединения Redis
// (Эта функция может потребовать уточнения в зависимости от используемых библиотек)
func isRedisConnError(err error) bool {
	if err == nil {
		return false
	}
	// Простые проверки строк. В реальном приложении лучше использовать
	// более надежные проверки, например, errors.Is с конкретными типами ошибок Redis.
	strErr := err.Error()
	return strings.Contains(strErr, "connection refused") ||
		strings.Contains(strErr, "i/o timeout") ||
		strings.Contains(strErr, "EOF") ||
		strings.Contains(strErr, "broken pipe")
}

// Вспомогательная функция для выполнения операции с ретраями (заменена на встроенную логику клиента)
/*
func (p *RedisPubSub) executeWithRetry(operation func() error) error {
	// ... (старая логика ретраев)
}
*/

// generateInstanceID создает уникальный ID для экземпляра Hub
func generateInstanceID() string {
	return "instance_" + time.Now().Format("20060102150405") + "_" + randomString(8)
}

// randomString генерирует случайную строку указанной длины
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
		time.Sleep(1 * time.Nanosecond) // Добавляем минимальную задержку для лучшей случайности
	}
	return string(result)
}
