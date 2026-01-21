package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/golang-jwt/jwt/v4"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
	"github.com/yourusername/trivia-api/internal/websocket"
)

// Определим интерфейс KeyProvider, который TokenManager должен будет реализовать
// Это позволит избежать прямой зависимости JWTService от TokenManager
type KeyProvider interface {
	GetCurrentSigningKey(ctx context.Context) (*entity.JWTKey, error)
	GetKeysForValidation(ctx context.Context) (map[string]string, error)
}

// JWTCustomClaims содержит пользовательские поля для токена
type JWTCustomClaims struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	// Add CSRF secret to claims
	CSRFSecret string `json:"csrf_secret,omitempty"`
	jwt.RegisteredClaims
	// Add specific claim for WS ticket identification
	Usage string `json:"usage,omitempty"`
}

// JWTService предоставляет методы для работы с JWT
type JWTService struct {
	expirationHrs int
	// Черный список для инвалидированных пользователей (in-memory)
	invalidatedUsers map[uint]time.Time
	// Мьютекс для безопасной работы с картой в многопоточной среде
	mu sync.RWMutex
	// Репозиторий для персистентного хранения инвалидированных токенов
	invalidTokenRepo repository.InvalidTokenRepository
	// Add field for WS ticket expiry
	wsTicketExpiry time.Duration
	// Интервал для очистки кеша
	cleanupInterval time.Duration
	keyProvider     KeyProvider // Добавлено: зависимость от провайдера ключей
	pubSubProvider  websocket.PubSubProvider
	appCtx          context.Context
}

// NewJWTService создает новый сервис JWT и возвращает ошибку при проблемах
func NewJWTService(
	expirationHrs int,
	invalidTokenRepo repository.InvalidTokenRepository,
	wsTicketExpirySec int,
	cleanupInterval time.Duration,
	keyProvider KeyProvider, // Добавлен параметр KeyProvider
	pubSubProvider websocket.PubSubProvider,
	appCtx context.Context,
) (*JWTService, error) {
	if invalidTokenRepo == nil {
		return nil, fmt.Errorf("InvalidTokenRepository is required for JWTService")
	}
	if keyProvider == nil {
		return nil, fmt.Errorf("KeyProvider is required for JWTService")
	}
	if pubSubProvider == nil {
		return nil, fmt.Errorf("PubSubProvider is required for JWTService")
	}
	if appCtx == nil {
		return nil, fmt.Errorf("appCtx is required for JWTService")
	}
	// Default expiry if not set or invalid
	if expirationHrs <= 0 {
		expirationHrs = 24 // Default to 24 hours
	}
	wsExpiry := time.Duration(wsTicketExpirySec) * time.Second
	if wsExpiry <= 0 {
		wsExpiry = 60 * time.Second // Default to 60 seconds
	}
	// Default cleanup interval if not set or invalid
	if cleanupInterval <= 0 {
		cleanupInterval = 1 * time.Hour
	}

	service := &JWTService{
		expirationHrs:    expirationHrs,
		invalidatedUsers: make(map[uint]time.Time),
		invalidTokenRepo: invalidTokenRepo,
		wsTicketExpiry:   wsExpiry, // Store configured WS ticket expiry
		cleanupInterval:  cleanupInterval,
		keyProvider:      keyProvider, // Сохраняем keyProvider
		pubSubProvider:   pubSubProvider,
		appCtx:           appCtx,
	}

	// Создаем контекст для загрузки из БД при старте
	startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Загружаем инвалидированные токены из БД при создании сервиса
	service.loadInvalidatedTokensFromDB(startupCtx)

	// Запускаем периодическую очистку кеша
	go service.runCleanupRoutine()

	// Запускаем прослушивание событий инвалидации из Pub/Sub
	go service.listenForInvalidationEvents()

	return service, nil // Возвращаем сервис и nil ошибку при успехе
}

// loadInvalidatedTokensFromDB загружает информацию об инвалидированных токенах из БД
func (s *JWTService) loadInvalidatedTokensFromDB(ctx context.Context) {
	// Если репозиторий не инициализирован, выходим
	if s.invalidTokenRepo == nil {
		log.Println("JWT: Repository not initialized, skipping DB load")
		return
	}

	tokens, err := s.invalidTokenRepo.GetAllInvalidTokens(ctx)
	if err != nil {
		log.Printf("JWT: Error loading invalidated tokens from DB: %v", err)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range tokens {
		s.invalidatedUsers[token.UserID] = token.InvalidationTime
	}

	log.Printf("JWT: Loaded %d invalidated tokens from database", len(tokens))
}

// GenerateTokenWithKey создает новый JWT токен для пользователя, используя предоставленный ключ.
func (s *JWTService) GenerateTokenWithKey(user *entity.User, csrfSecret string, signingKey *entity.JWTKey) (string, error) {
	if signingKey == nil || signingKey.Key == "" || signingKey.ID == "" {
		return "", errors.New("invalid signing key provided for token generation")
	}
	// Убедимся, что используется поддерживаемый алгоритм
	signingMethod := jwt.GetSigningMethod(signingKey.Algorithm)
	if signingMethod == nil {
		return "", fmt.Errorf("unsupported signing algorithm specified in key: %s", signingKey.Algorithm)
	}

	if csrfSecret == "" {
		// Это не должно происходить при обычном потоке генерации токена доступа,
		// так как TokenManager должен генерировать секрет.
		// Логируем как ошибку, если это все же случилось.
		log.Printf("[JWT] ОШИБКА: Попытка сгенерировать токен доступа без CSRF секрета для пользователя ID=%d", user.ID)
		return "", errors.New("CSRF secret cannot be empty for access tokens")
	}

	claims := &JWTCustomClaims{
		UserID: user.ID,
		Email:  user.Email,
		// Role:       user.Role, // TODO: Uncomment and ensure user.Role exists when roles are implemented
		CSRFSecret: csrfSecret, // Включаем CSRF секрет
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * time.Duration(s.expirationHrs))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "trivia-api", // Добавим издателя
			Subject:   fmt.Sprintf("%d", user.ID),
			Audience:  jwt.ClaimStrings{"trivia-user"}, // Пример аудитории
		},
		// Usage не устанавливаем, т.к. это стандартный токен доступа
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	// Добавляем Key ID (kid) в заголовок токена
	token.Header["kid"] = signingKey.ID

	// Подписываем токен, используя секрет из переданного ключа
	tokenString, err := token.SignedString([]byte(signingKey.Key))
	if err != nil {
		log.Printf("[JWT] Ошибка генерации токена для пользователя ID=%d с ключом ID=%s: %v", user.ID, signingKey.ID, err)
		return "", err
	}

	// Не логируем CSRFSecret
	log.Printf("[JWT] Токен доступа успешно сгенерирован для пользователя ID=%d с ключом ID=%s",
		user.ID, signingKey.ID)
	return tokenString, nil
}

// ParseToken проверяет и расшифровывает JWT токен, используя ключи от KeyProvider.
func (s *JWTService) ParseToken(ctx context.Context, tokenString string) (*JWTCustomClaims, error) {
	claims := &JWTCustomClaims{}

	// Используем Keyfunc для динамического получения ключа проверки
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Получаем Key ID (kid) из заголовка токена
		kid, ok := token.Header["kid"].(string)
		if !ok {
			log.Printf("[JWT] Ошибка: отсутствует 'kid' в заголовке токена")
			return nil, errors.New("token header missing 'kid' (Key ID)")
		}

		// Запрашиваем карту валидных ключей у KeyProvider
		validationKeys, keyErr := s.keyProvider.GetKeysForValidation(ctx)
		if keyErr != nil {
			log.Printf("[JWT] Ошибка при получении ключей для валидации: %v", keyErr)
			return nil, fmt.Errorf("failed to get validation keys: %w", keyErr)
		}

		// Ищем секрет по kid
		secret, found := validationKeys[kid]
		if !found {
			log.Printf("[JWT] Ошибка: ключ с ID '%s' не найден среди валидных ключей для проверки токена", kid)
			return nil, fmt.Errorf("validation key with id '%s' not found or inactive", kid)
		}

		// Проверяем метод подписи токена
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("[JWT] Неожиданный метод подписи: %v для kid: %s", token.Header["alg"], kid)
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Возвращаем найденный секрет (уже расшифрованный)
		return []byte(secret), nil
	}

	// Парсим токен с использованием keyFunc
	token, err := jwt.ParseWithClaims(tokenString, claims, keyFunc)

	if err != nil {
		// Более подробное логирование ошибок JWT
		if ve, ok := err.(*jwt.ValidationError); ok {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				log.Printf("[JWT] Ошибка: Токен имеет неверный формат")
				return nil, errors.New("token is malformed")
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				logUserID := uint(0)
				if claims != nil {
					logUserID = claims.UserID
				}
				log.Printf("[JWT] Ошибка: Токен истек срок действия для пользователя ID=%d", logUserID)
				return nil, errors.New("token is expired")
			case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
				log.Printf("[JWT] Ошибка: Токен еще не действителен")
				return nil, errors.New("token not valid yet")
			case ve.Errors&jwt.ValidationErrorSignatureInvalid != 0:
				logUserID := uint(0)
				if claims != nil {
					logUserID = claims.UserID
				}
				kid := "unknown"
				if token != nil && token.Header != nil {
					if k, ok := token.Header["kid"].(string); ok {
						kid = k
					}
				}
				log.Printf("[JWT] Ошибка: Неверная подпись токена для пользователя ID=%d (Key ID: %s)", logUserID, kid)
				return nil, errors.New("signature is invalid")
			// Добавим обработку ошибки отсутствия ключа (из keyFunc)
			case errors.Is(ve.Inner, errors.New("token header missing 'kid' (Key ID)")), // Примерные тексты ошибок из keyFunc
				errors.Is(ve.Inner, fmt.Errorf("validation key with id '' not found or inactive")),
				strings.Contains(ve.Inner.Error(), "validation key with id"):
				log.Printf("[JWT] Ошибка валидации: Ключ для проверки не найден или недействителен. %v", ve.Inner)
				return nil, errors.New("token validation key error")
			default:
				log.Printf("[JWT] Ошибка при разборе токена: %v", err)
				return nil, errors.New("token validation failed")
			}
		} else {
			log.Printf("[JWT] Ошибка при разборе токена: %v", err)
			return nil, err
		}
	}

	if !token.Valid {
		log.Printf("[JWT] Токен недействителен")
		return nil, errors.New("invalid token")
	}

	// Проверяем, является ли токен WS-тикетом
	if claims.Usage == "websocket_auth" {
		log.Printf("[JWT] Проверка WS-тикета для пользователя ID=%d", claims.UserID)
		// Для WS-тикетов пропускаем проверку инвалидации
		return claims, nil
	}

	// Проверка на инвалидацию токена (только для обычных токенов, не для WS-тикетов)
	isInvalidInMem := false
	var invalidationTime time.Time // Переменная для хранения времени инвалидации
	if claims.UserID > 0 {
		s.mu.RLock()
		invTime, exists := s.invalidatedUsers[claims.UserID]
		s.mu.RUnlock()

		if exists {
			invalidationTime = invTime // Сохраняем время для логирования
			// Если время выдачи токена НЕ ПОЗЖЕ времени инвалидации, токен недействителен
			if claims.IssuedAt != nil && !claims.IssuedAt.Time.After(invalidationTime) {
				isInvalidInMem = true
			}
		}
	}

	if isInvalidInMem {
		log.Printf("[JWT] Токен инвалидирован (in-memory check) для пользователя ID=%d, выдан в %v, время инвалидации %v",
			claims.UserID, claims.IssuedAt.Time, invalidationTime)
		return nil, errors.New("token has been invalidated")
	}

	log.Printf("[JWT] Токен успешно проверен для пользователя ID=%d, Email=%s, выдан: %v",
		claims.UserID, claims.Email, claims.IssuedAt.Time)
	return claims, nil
}

// InvalidateTokensForUser добавляет пользователя в черный список,
// делая все ранее выданные токены недействительными
// Добавлен context.Context
func (s *JWTService) InvalidateTokensForUser(ctx context.Context, userID uint) error {
	now := time.Now()
	// Инвалидация в памяти
	s.mu.Lock()
	s.invalidatedUsers[userID] = now
	s.mu.Unlock()

	// Инвалидация в БД
	if s.invalidTokenRepo != nil {
		err := s.invalidTokenRepo.AddInvalidToken(ctx, userID, now)
		if err != nil {
			log.Printf("[JWT] Ошибка при добавлении записи инвалидации в БД для пользователя ID=%d: %v",
				userID, err)
			return err
		}
	}

	// Публикуем событие инвалидации в Pub/Sub
	invalidationEvent := map[string]interface{}{"user_id": userID, "invalidation_time": now.Unix()}
	eventBytes, err := json.Marshal(invalidationEvent)
	if err != nil {
		log.Printf("[JWT] Ошибка сериализации события инвалидации для userID %d: %v", userID, err)
		// Не возвращаем ошибку, чтобы не прерывать основной процесс, но логируем
	} else {
		if pubErr := s.pubSubProvider.Publish("jwt_invalidation_events", eventBytes); pubErr != nil {
			log.Printf("[JWT] Ошибка публикации события инвалидации для userID %d в Pub/Sub: %v", userID, pubErr)
			// Также не возвращаем ошибку, но логируем
		} else {
			log.Printf("[JWT] Событие инвалидации для userID %d опубликовано в Pub/Sub", userID)
		}
	}

	log.Printf("[JWT] Токены инвалидированы для пользователя ID=%d в %v", userID, now)
	return nil
}

// ResetInvalidationForUser удаляет пользователя из черного списка,
// разрешая использование существующих токенов
// Добавлен context.Context
func (s *JWTService) ResetInvalidationForUser(ctx context.Context, userID uint) {
	if userID == 0 {
		log.Printf("JWT: Попытка сброса инвалидации для некорректного UserID: %d", userID)
		return
	}

	s.mu.Lock()
	_, exists := s.invalidatedUsers[userID]
	if exists {
		delete(s.invalidatedUsers, userID)
		log.Printf("JWT: Reset invalidation for UserID: %d", userID)
	} else {
		log.Printf("JWT: UserID: %d was not in the invalidation list", userID)
	}
	s.mu.Unlock()

	// Удаляем также из БД, если репозиторий инициализирован
	if s.invalidTokenRepo != nil {
		err := s.invalidTokenRepo.RemoveInvalidToken(ctx, userID)
		if err != nil {
			log.Printf("[JWT] Ошибка при удалении записи инвалидации из БД для пользователя ID=%d: %v", userID, err)
			// Ошибка удаления из БД не должна останавливать процесс, но ее нужно логировать
		}
	}
}

// CleanupInvalidatedUsers удаляет устаревшие записи об инвалидированных токенах из БД и из кеша
// Добавлен context.Context
func (s *JWTService) CleanupInvalidatedUsers(ctx context.Context) error {
	// Устанавливаем временной порог (например, старше срока жизни refresh-токена или заданного интервала)
	// Здесь используем expirationHrs * 2, как пример
	cutoffTime := time.Now().Add(-time.Hour * time.Duration(s.expirationHrs*2))
	log.Printf("[JWTService] Running cleanup for entries older than %v", cutoffTime)

	// Очистка БД
	if s.invalidTokenRepo != nil {
		err := s.invalidTokenRepo.CleanupOldInvalidTokens(ctx, cutoffTime)
		if err != nil {
			log.Printf("[JWTService] Error cleaning up invalid tokens from DB: %v", err)
			// Продолжаем очистку кеша, даже если в БД была ошибка
		}
	}

	// Очистка кеша в памяти
	s.mu.Lock() // Блокируем карту для записи
	defer s.mu.Unlock()

	cleanedCount := 0
	for userID, invalidationTime := range s.invalidatedUsers {
		if invalidationTime.Before(cutoffTime) {
			delete(s.invalidatedUsers, userID)
			cleanedCount++
		}
	}
	log.Printf("[JWTService] Cleaned up %d stale entries from invalidatedUsers cache", cleanedCount)

	return nil
}

// runCleanupRoutine запускает горутину для периодической очистки кеша
func (s *JWTService) runCleanupRoutine() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	// Используем s.appCtx, переданный при инициализации, для управления жизненным циклом
	// Эта горутина завершится, когда s.appCtx будет отменен.
	log.Printf("[JWTService] Starting periodic cleanup routine every %v", s.cleanupInterval)

	for {
		select {
		case <-ticker.C:
			log.Printf("[JWTService] Running periodic cleanup...")
			// Используем новый контекст для самой операции очистки, если нужно ограничить ее по времени
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), s.cleanupInterval/2)
			if err := s.CleanupInvalidatedUsers(cleanupCtx); err != nil {
				log.Printf("[JWTService] Error during periodic cleanup: %v", err)
			}
			cancelCleanup()
		case <-s.appCtx.Done(): // Слушаем отмену основного контекста приложения
			log.Printf("[JWTService] Cleanup routine stopped due to app context cancellation.")
			return
		}
	}
}

// DebugToken анализирует JWT токен без проверки подписи
// для диагностических целей
func (s *JWTService) DebugToken(tokenString string) map[string]interface{} {
	parser := jwt.Parser{}
	token, parts, err := parser.ParseUnverified(tokenString, &JWTCustomClaims{})

	result := make(map[string]interface{})
	result["raw_token"] = tokenString
	result["parts"] = parts

	if err != nil {
		result["error"] = err.Error()
		return result
	}

	result["header"] = token.Header
	result["claims"] = token.Claims
	result["signature"] = token.Signature
	result["method"] = token.Method.Alg()

	// Дополнительная информация из claims
	if claims, ok := token.Claims.(*JWTCustomClaims); ok {
		result["user_id"] = claims.UserID
		result["email"] = claims.Email
		result["role"] = claims.Role
		if claims.Usage != "" {
			result["usage"] = claims.Usage
		}
		if claims.ExpiresAt != nil {
			result["expires_at"] = claims.ExpiresAt.Time
			result["is_expired"] = time.Now().After(claims.ExpiresAt.Time)
		}
		if claims.IssuedAt != nil {
			result["issued_at"] = claims.IssuedAt.Time
		}
	}

	return result
}

// ParseWSTicket проверяет JWT, используемый как WS тикет
// Обновлено: использует Keyfunc для проверки подписи
func (s *JWTService) ParseWSTicket(ticketString string) (*JWTCustomClaims, error) {
	claims := &JWTCustomClaims{}

	// Используем ту же Keyfunc, что и в ParseToken
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("ticket header missing 'kid' (Key ID)")
		}
		validationKeys, keyErr := s.keyProvider.GetKeysForValidation(context.Background())
		if keyErr != nil {
			return nil, fmt.Errorf("failed to get validation keys: %w", keyErr)
		}
		secret, found := validationKeys[kid]
		if !found {
			return nil, fmt.Errorf("validation key with id '%s' not found or inactive", kid)
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret), nil
	}

	token, err := jwt.ParseWithClaims(ticketString, claims, keyFunc)

	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, errors.New("ticket is expired")
			}
		}
		return nil, fmt.Errorf("invalid ticket: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid ticket")
	}

	if claims.Usage != "websocket_auth" {
		return nil, errors.New("invalid ticket usage")
	}

	if claims.CSRFSecret != "" {
		log.Printf("[JWT] Ошибка: WS-тикет для пользователя ID=%d содержит CSRF секрет", claims.UserID)
		return nil, errors.New("WS ticket should not contain CSRF secret")
	}

	return claims, nil
}

// GenerateWSTicket создает короткоживущий JWT для аутентификации WebSocket
// Обновлено: использует текущий активный ключ для подписи
func (s *JWTService) GenerateWSTicket(userID uint, email string) (string, error) {
	// Получаем текущий ключ для подписи
	signingKey, keyErr := s.keyProvider.GetCurrentSigningKey(context.Background())
	if keyErr != nil {
		log.Printf("CRITICAL: Failed to get current signing key for GenerateWSTicket: %v", keyErr)
		return "", errors.New("failed to get signing key for WS ticket")
	}
	signingMethod := jwt.GetSigningMethod(signingKey.Algorithm)
	if signingMethod == nil {
		return "", fmt.Errorf("unsupported signing algorithm specified in key: %s", signingKey.Algorithm)
	}

	claims := &JWTCustomClaims{
		UserID: userID,
		Email:  email,
		Usage:  "websocket_auth", // Указываем назначение токена
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.wsTicketExpiry)), // Используем настраиваемое время жизни
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "trivia-api",
			Subject:   fmt.Sprintf("%d", userID),
			Audience:  jwt.ClaimStrings{"trivia-ws"}, // Другая аудитория для WS
		},
	}

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = signingKey.ID // Добавляем kid

	tokenString, err := token.SignedString([]byte(signingKey.Key))
	if err != nil {
		log.Printf("[JWT] Ошибка генерации WS-тикета для пользователя ID=%d с ключом ID=%s: %v", userID, signingKey.ID, err)
		return "", err
	}

	log.Printf("[JWT] WS-тикет успешно сгенерирован для пользователя ID=%d с ключом ID=%s, истекает через %v",
		userID, signingKey.ID, s.wsTicketExpiry)
	return tokenString, nil
}

// listenForInvalidationEvents подписывается на события инвалидации из Pub/Sub
// и обновляет локальный кеш.
func (s *JWTService) listenForInvalidationEvents() {
	if s.pubSubProvider == nil {
		log.Println("[JWTService] PubSubProvider не настроен, пропуск прослушивания событий инвалидации.")
		return
	}

	// Подписываемся на канал, используя s.appCtx для управления жизненным циклом подписки
	messages, err := s.pubSubProvider.Subscribe(s.appCtx, "jwt_invalidation_events")
	if err != nil {
		log.Printf("[JWTService] Ошибка подписки на канал jwt_invalidation_events: %v", err)
		return // Если не удалось подписаться, нет смысла продолжать
	}

	log.Println("[JWTService] Успешно подписан на канал jwt_invalidation_events для синхронизации кэша.")

	for {
		select {
		case <-s.appCtx.Done():
			log.Println("[JWTService] Остановка прослушивания событий инвалидации из-за отмены контекста приложения.")
			// PubSubProvider.Close() или отписка будет обработана внешне или через контекст в Subscribe
			return
		case msgBytes, ok := <-messages:
			if !ok {
				log.Println("[JWTService] Канал сообщений Pub/Sub jwt_invalidation_events был закрыт.")
				return // Канал закрыт, выходим
			}

			var eventData struct {
				UserID           uint  `json:"user_id"`
				InvalidationTime int64 `json:"invalidation_time"` // Ожидаем Unix timestamp
			}

			if err := json.Unmarshal(msgBytes, &eventData); err != nil {
				log.Printf("[JWTService] Ошибка десериализации сообщения из Pub/Sub: %v. Сообщение: %s", err, string(msgBytes))
				continue // Пропускаем некорректное сообщение
			}

			if eventData.UserID == 0 {
				log.Printf("[JWTService] Получено событие инвалидации с некорректным UserID: %d", eventData.UserID)
				continue
			}

			// Обновляем локальный кеш
			s.mu.Lock()
			// Если уже есть более свежая запись об инвалидации, не перезаписываем
			// или всегда перезаписываем временем из события. Для простоты - перезаписываем.
			invalidationTime := time.Unix(eventData.InvalidationTime, 0)
			s.invalidatedUsers[eventData.UserID] = invalidationTime
			s.mu.Unlock()
			log.Printf("[JWTService] Локальный кэш инвалидации обновлен для UserID %d из Pub/Sub, время: %v", eventData.UserID, invalidationTime)
		}
	}
}
