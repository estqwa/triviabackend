package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// WebSocketMetricsHandler возвращает обработчик для получения базовых метрик хаба
func WebSocketMetricsHandler(provider MetricsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metrics := provider.GetMetrics()

		// Добавляем время генерации метрик
		metrics["generated_at"] = time.Now().Format(time.RFC3339)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Printf("Error encoding WebSocket metrics: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

// DetailedWebSocketMetricsHandler возвращает обработчик для получения детальных метрик (включая шарды)
func DetailedWebSocketMetricsHandler(provider DetailedInfoProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Проверяем, что провайдер не nil
		if provider == nil {
			w.WriteHeader(http.StatusNotImplemented)
			w.Write([]byte("Detailed metrics not available for this hub type"))
			return
		}

		// Получаем детальные метрики
		metrics := provider.GetDetailedMetrics()
		metrics["generated_at"] = time.Now().Format(time.RFC3339)

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metrics); err != nil {
			log.Printf("Error encoding detailed WebSocket metrics: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}

// WebSocketHealthCheckHandler возвращает обработчик для проверки состояния хаба
func WebSocketHealthCheckHandler(provider MetricsProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Простая проверка: если есть активные клиенты, считаем здоровым
		// Можно добавить более сложные проверки (например, пинг к Redis для PubSub)
		status := "healthy"
		statusCode := http.StatusOK
		clientCount := 0

		if provider != nil {
			clientCount = provider.ClientCount()
		} else {
			status = "unavailable"
			statusCode = http.StatusServiceUnavailable
		}

		response := map[string]interface{}{
			"status":             status,
			"active_connections": clientCount,
			"timestamp":          time.Now().Format(time.RFC3339),
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding WebSocket health check response: %v", err)
		}
	}
}

// WebSocketSystemAlertsHandler возвращает текущие системные алерты и потенциальные проблемы
func WebSocketSystemAlertsHandler(hub interface{}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Проверка метода запроса
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Получаем информацию о системе
		var alerts []map[string]interface{}
		var systemStatus string = "healthy"

		hubMetrics := make(map[string]interface{})

		// Собираем метрики в зависимости от типа хаба
		if shardedHub, ok := hub.(*ShardedHub); ok {
			hubMetrics = shardedHub.GetDetailedMetrics()

			// Проверяем наличие "горячих" шардов
			if hotShards, ok := hubMetrics["hot_shards"].([]int); ok && len(hotShards) > 0 {
				systemStatus = "degraded"

				// Добавляем алерт о горячих шардах
				alerts = append(alerts, map[string]interface{}{
					"type":     "hot_shards",
					"severity": "warning",
					"message":  fmt.Sprintf("Обнаружено %d горячих шардов", len(hotShards)),
					"details":  hotShards,
				})
			}

			// Проверяем буфер отключений
			if shardMetrics, ok := hubMetrics["shard_metrics"].([]map[string]interface{}); ok {
				for _, shard := range shardMetrics {
					shardID, idOk := shard["shard_id"].(int)
					if !idOk {
						continue
					}

					if disconnectionStats, ok := shard["disconnection_stats"].(map[string]interface{}); ok {
						if bufferAlert, ok := disconnectionStats["buffer_alert_triggered"].(bool); ok && bufferAlert {
							systemStatus = "critical"

							// Добавляем алерт о переполнении буфера отключений
							alerts = append(alerts, map[string]interface{}{
								"type":     "buffer_overflow",
								"severity": "critical",
								"message":  fmt.Sprintf("Переполнение буфера отключений в шарде %d", shardID),
								"details":  disconnectionStats,
							})
						}

						// Проверяем количество отложенных отключений
						if pendingDisconnects, ok := disconnectionStats["pending_disconnects"].(int32); ok && pendingDisconnects > 50 {
							severity := "warning"
							if pendingDisconnects > 100 {
								severity = "critical"
								systemStatus = "critical"
							}

							// Добавляем алерт о большом количестве отложенных отключений
							alerts = append(alerts, map[string]interface{}{
								"type":     "high_pending_disconnects",
								"severity": severity,
								"message": fmt.Sprintf("Большое количество отложенных отключений в шарде %d: %d",
									shardID, pendingDisconnects),
								"details": map[string]interface{}{
									"shard_id":            shardID,
									"pending_disconnects": pendingDisconnects,
								},
							})
						}
					}

					// Проверяем загрузку шарда
					if loadPercentage, ok := shard["load_percentage"].(float64); ok && loadPercentage > 90 {
						severity := "warning"
						if loadPercentage > 95 {
							severity = "critical"
							systemStatus = "critical"
						}

						// Добавляем алерт о высокой загрузке шарда
						alerts = append(alerts, map[string]interface{}{
							"type":     "high_shard_load",
							"severity": severity,
							"message":  fmt.Sprintf("Высокая загрузка шарда %d: %.2f%%", shardID, loadPercentage),
							"details": map[string]interface{}{
								"shard_id":           shardID,
								"load_percentage":    loadPercentage,
								"active_connections": shard["active_connections"],
								"max_clients":        shard["max_clients"],
							},
						})
					}
				}
			}

			// Проверяем статистику потерянных сообщений, если она доступна
			if messageStats, ok := hubMetrics["message_stats"].(map[string]interface{}); ok {
				if failedCount, ok := messageStats["messages_sent_failed"].(int64); ok && failedCount > 0 {
					failedPriority := "unknown"
					severity := "info"

					// Проверяем, есть ли потерянные критичные сообщения
					if priorityStats, ok := messageStats["priority_stats"].(map[string]map[string]int64); ok {
						if criticalStats, ok := priorityStats["critical"]; ok {
							if criticalFailed, ok := criticalStats["failed"]; ok && criticalFailed > 0 {
								failedPriority = "critical"
								severity = "critical"
								systemStatus = "critical"
							} else if highStats, ok := priorityStats["high"]; ok {
								if highFailed, ok := highStats["failed"]; ok && highFailed > 0 {
									failedPriority = "high"
									severity = "warning"
									if systemStatus == "healthy" {
										systemStatus = "degraded"
									}
								}
							}
						}
					}

					// Добавляем алерт о потерянных сообщениях
					alerts = append(alerts, map[string]interface{}{
						"type":     "message_loss",
						"severity": severity,
						"message":  fmt.Sprintf("Обнаружены потерянные сообщения: %d", failedCount),
						"details": map[string]interface{}{
							"failed_count":    failedCount,
							"failed_priority": failedPriority,
							"message_stats":   messageStats,
						},
					})
				}
			}
		}

		// Формируем ответ
		response := map[string]interface{}{
			"status":       systemStatus,
			"alerts":       alerts,
			"alerts_count": len(alerts),
			"check_time":   time.Now().Format(time.RFC3339),
			"hub_type":     hubTypeName(hub),
		}

		// Добавляем рекомендации в случае проблем
		if systemStatus != "healthy" {
			recommendations := []string{}

			if systemStatus == "critical" {
				recommendations = append(recommendations,
					"Проверьте буферы отключений шардов и увеличьте их размер если необходимо",
					"Временно приостановите новые подключения до стабилизации системы")
			}

			if containsAlertType(alerts, "hot_shards") {
				recommendations = append(recommendations,
					"Запустите ручную балансировку шардов",
					"Увеличьте количество шардов или добавьте новый экземпляр сервера")
			}

			if containsAlertType(alerts, "message_loss") {
				recommendations = append(recommendations,
					"Проверьте настройки приоритетов сообщений",
					"Используйте кластерный режим для надежной доставки сообщений")
			}

			response["recommendations"] = recommendations
		}

		// Отправляем ответ
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		if err := json.NewEncoder(w).Encode(response); err != nil {
			http.Error(w, "Error encoding alerts", http.StatusInternalServerError)
			return
		}
	}
}

// hubTypeName возвращает строковое название типа хаба
func hubTypeName(hub interface{}) string {
	if _, ok := hub.(*ShardedHub); ok {
		return "ShardedHub"
	}
	return "UnknownHub"
}

// containsAlertType проверяет наличие алерта указанного типа
func containsAlertType(alerts []map[string]interface{}, alertType string) bool {
	for _, alert := range alerts {
		if t, ok := alert["type"].(string); ok && t == alertType {
			return true
		}
	}
	return false
}

// renderPrometheusMetrics форматирует метрики в формате Prometheus
func renderPrometheusMetrics(w http.ResponseWriter, metrics map[string]interface{}) {
	// Время генерации метрик
	timestamp := time.Now().Unix() * 1000

	// Обрабатываем основные метрики
	prometheusFormat := func(name string, value interface{}, help string, metricType string) {
		fmt.Fprintf(w, "# HELP websocket_%s %s\n", name, help)
		fmt.Fprintf(w, "# TYPE websocket_%s %s\n", name, metricType)
		fmt.Fprintf(w, "websocket_%s %v %d\n", name, value, timestamp)
	}

	// Маппинг метрик на описания и типы
	metricDescriptions := map[string]struct {
		help string
		typ  string
	}{
		"total_connections":        {"Total number of connections since server start", "counter"},
		"active_connections":       {"Current number of active connections", "gauge"},
		"messages_sent":            {"Total number of messages sent", "counter"},
		"messages_received":        {"Total number of messages received", "counter"},
		"connection_errors":        {"Total number of connection errors", "counter"},
		"inactive_clients_removed": {"Total number of inactive clients removed", "counter"},
		"uptime_seconds":           {"Server uptime in seconds", "gauge"},
	}

	// Выводим основные метрики
	for metricName, description := range metricDescriptions {
		if value, ok := metrics[metricName]; ok {
			prometheusFormat(metricName, value, description.help, description.typ)
		}
	}

	// Обрабатываем данные шардов, если они есть
	if shardMetrics, ok := metrics["shard_metrics"].([]map[string]interface{}); ok {
		for _, shard := range shardMetrics {
			shardID := shard["shard_id"]
			// Метрики шарда
			if connections, ok := shard["active_connections"].(int); ok {
				fmt.Fprintf(w, "websocket_shard_active_connections{shard_id=\"%v\"} %d %d\n",
					shardID, connections, timestamp)
			}
			if messagesSent, ok := shard["messages_sent"].(int64); ok {
				fmt.Fprintf(w, "websocket_shard_messages_sent{shard_id=\"%v\"} %d %d\n",
					shardID, messagesSent, timestamp)
			}
			if loadPercentage, ok := shard["load_percentage"].(float64); ok {
				fmt.Fprintf(w, "websocket_shard_load_percentage{shard_id=\"%v\"} %f %d\n",
					shardID, loadPercentage, timestamp)
			}

			// Добавляем метрики отключений для каждого шарда
			if disconnectionStats, ok := shard["disconnection_stats"].(map[string]interface{}); ok {
				// Метрика отложенных отключений
				if pendingDisconnects, ok := disconnectionStats["pending_disconnects"].(int32); ok {
					fmt.Fprintf(w, "websocket_shard_pending_disconnects{shard_id=\"%v\"} %d %d\n",
						shardID, pendingDisconnects, timestamp)
				}

				// Метрика заполненности буфера отключений
				if bufferUsed, ok := disconnectionStats["disconnect_buffer_used"].(int); ok {
					if bufferCapacity, ok := disconnectionStats["disconnect_buffer_capacity"].(int); ok {
						fmt.Fprintf(w, "websocket_shard_disconnect_buffer_usage{shard_id=\"%v\"} %f %d\n",
							shardID, float64(bufferUsed)/float64(bufferCapacity)*100.0, timestamp)
					}
				}

				// Сигнал тревоги о буфере отключений
				if bufferAlert, ok := disconnectionStats["buffer_alert_triggered"].(bool); ok {
					alertValue := 0
					if bufferAlert {
						alertValue = 1
					}
					fmt.Fprintf(w, "websocket_shard_disconnect_buffer_alert{shard_id=\"%v\"} %d %d\n",
						shardID, alertValue, timestamp)
				}
			}
		}
	}

	// Экспортируем алерты в формате Prometheus
	if hotShards, ok := metrics["hot_shards"].([]int); ok && len(hotShards) > 0 {
		// Сколько горячих шардов
		fmt.Fprintf(w, "# HELP websocket_hot_shards_count Number of shards with high load\n")
		fmt.Fprintf(w, "# TYPE websocket_hot_shards_count gauge\n")
		fmt.Fprintf(w, "websocket_hot_shards_count %d %d\n", len(hotShards), timestamp)

		// Отдельная метрика для каждого горячего шарда
		for _, shardID := range hotShards {
			fmt.Fprintf(w, "websocket_hot_shard{shard_id=\"%d\"} 1 %d\n", shardID, timestamp)
		}
	}

	// Метрики сообщений по приоритетам
	if messageStats, ok := metrics["message_stats"].(map[string]interface{}); ok {
		// Общее количество отправленных сообщений
		if messagesSent, ok := messageStats["messages_sent"].(int64); ok {
			fmt.Fprintf(w, "websocket_messages_sent_total %d %d\n", messagesSent, timestamp)
		}

		// Неудачные отправки
		if messagesFailed, ok := messageStats["messages_sent_failed"].(int64); ok {
			fmt.Fprintf(w, "websocket_messages_sent_failed %d %d\n", messagesFailed, timestamp)
		}

		// Метрики по приоритетам
		if priorityStats, ok := messageStats["priority_stats"].(map[string]map[string]int64); ok {
			for priority, stats := range priorityStats {
				if sent, ok := stats["sent"]; ok {
					fmt.Fprintf(w, "websocket_messages_sent_by_priority{priority=\"%s\"} %d %d\n",
						priority, sent, timestamp)
				}
				if failed, ok := stats["failed"]; ok {
					fmt.Fprintf(w, "websocket_messages_failed_by_priority{priority=\"%s\"} %d %d\n",
						priority, failed, timestamp)

					// Если есть потери критичных сообщений - это важный алерт
					if priority == "critical" && failed > 0 {
						fmt.Fprintf(w, "websocket_critical_messages_lost 1 %d\n", timestamp)
					}
				}
			}
		}
	}

	// Проверяем статус системы и экспортируем как метрику
	if systemStatus, ok := metrics["system_status"].(string); ok {
		statusValue := 0
		switch systemStatus {
		case "healthy":
			statusValue = 0 // 0 - здоровая система
		case "degraded":
			statusValue = 1 // 1 - деградация производительности
		case "critical":
			statusValue = 2 // 2 - критическое состояние
		}

		fmt.Fprintf(w, "# HELP websocket_system_status System health status (0=healthy, 1=degraded, 2=critical)\n")
		fmt.Fprintf(w, "# TYPE websocket_system_status gauge\n")
		fmt.Fprintf(w, "websocket_system_status %d %d\n", statusValue, timestamp)
	}

	// Экспортируем Redis Pub/Sub метрики, если они есть
	if pubSubStats, ok := metrics["pubsub_stats"].(map[string]interface{}); ok {
		// Буфер сообщений Redis
		if bufferSize, ok := pubSubStats["current_buffer_size"].(int); ok {
			fmt.Fprintf(w, "websocket_pubsub_buffer_size %d %d\n", bufferSize, timestamp)
		}

		// Состояние подключения
		if isConnected, ok := pubSubStats["is_connected"].(bool); ok {
			connValue := 0
			if isConnected {
				connValue = 1
			}
			fmt.Fprintf(w, "websocket_pubsub_connected %d %d\n", connValue, timestamp)
		}

		// Статистика сообщений
		if droppedMessages, ok := pubSubStats["dropped_messages"].(int64); ok {
			fmt.Fprintf(w, "websocket_pubsub_dropped_messages %d %d\n", droppedMessages, timestamp)
		}
	}
}
