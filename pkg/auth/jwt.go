package auth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
)

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
	secretKey     string
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
}

// NewJWTService создает новый сервис JWT и возвращает ошибку при проблемах
func NewJWTService(secretKey string, expirationHrs int, invalidTokenRepo repository.InvalidTokenRepository, wsTicketExpirySec int, cleanupInterval time.Duration) (*JWTService, error) {
	if secretKey == "" {
		// log.Fatal("JWT secret key is required")
		return nil, fmt.Errorf("JWT secret key is required for JWTService")
	}
	if invalidTokenRepo == nil {
		// log.Fatal("InvalidTokenRepository is required for JWTService")
		return nil, fmt.Errorf("InvalidTokenRepository is required for JWTService")
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
		secretKey:        secretKey,
		expirationHrs:    expirationHrs,
		invalidatedUsers: make(map[uint]time.Time),
		invalidTokenRepo: invalidTokenRepo,
		wsTicketExpiry:   wsExpiry, // Store configured WS ticket expiry
		cleanupInterval:  cleanupInterval,
	}

	// Создаем контекст для загрузки из БД при старте
	startupCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Загружаем инвалидированные токены из БД при создании сервиса
	service.loadInvalidatedTokensFromDB(startupCtx)

	// Запускаем периодическую очистку кеша
	go service.runCleanupRoutine()

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

// GenerateToken создает новый JWT токен для пользователя
// Теперь принимает csrfSecret для включения в клеймы
func (s *JWTService) GenerateToken(user *entity.User, csrfSecret string) (string, error) {
	// Проверка: CSRF секрет не должен быть пустым для стандартных токенов
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
		},
		// Usage не устанавливаем, т.к. это стандартный токен доступа
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		log.Printf("[JWT] Ошибка генерации токена для пользователя ID=%d: %v", user.ID, err)
		return "", err
	}

	// Не логируем CSRFSecret
	log.Printf("[JWT] Токен доступа успешно сгенерирован для пользователя ID=%d, выдан в %v, истекает через %d часов",
		user.ID, claims.IssuedAt.Time, s.expirationHrs)
	return tokenString, nil
}

// ParseToken проверяет и расшифровывает JWT токен
// Добавлен context.Context для вызова репозитория
func (s *JWTService) ParseToken(ctx context.Context, tokenString string) (*JWTCustomClaims, error) {
	claims := &JWTCustomClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			log.Printf("[JWT] Неожиданный метод подписи: %v", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.secretKey), nil
	})

	if err != nil {
		// Более подробное логирование ошибок JWT
		if ve, ok := err.(*jwt.ValidationError); ok {
			switch {
			case ve.Errors&jwt.ValidationErrorMalformed != 0:
				log.Printf("[JWT] Ошибка: Токен имеет неверный формат")
				return nil, errors.New("token is malformed")
			case ve.Errors&jwt.ValidationErrorExpired != 0:
				log.Printf("[JWT] Ошибка: Токен истек срок действия для пользователя ID=%d", claims.UserID)
				return nil, errors.New("token is expired")
			case ve.Errors&jwt.ValidationErrorNotValidYet != 0:
				log.Printf("[JWT] Ошибка: Токен еще не действителен")
				return nil, errors.New("token not valid yet")
			case ve.Errors&jwt.ValidationErrorSignatureInvalid != 0:
				log.Printf("[JWT] Ошибка: Неверная подпись токена")
				return nil, errors.New("signature is invalid")
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
			if !claims.IssuedAt.Time.After(invalidationTime) {
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

	// Создаем контекст, который можно отменить при необходимости (пока нет Shutdown)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Хотя cancel пока не вызывается

	log.Printf("[JWTService] Starting periodic cleanup routine every %v", s.cleanupInterval)

	for {
		select {
		case <-ticker.C:
			log.Printf("[JWTService] Running periodic cleanup...")
			if err := s.CleanupInvalidatedUsers(context.Background()); err != nil {
				log.Printf("[JWTService] Error during periodic cleanup: %v", err)
			}
		case <-ctx.Done():
			log.Printf("[JWTService] Cleanup routine stopped.")
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
func (s *JWTService) ParseWSTicket(ticketString string) (*JWTCustomClaims, error) {
	claims := &JWTCustomClaims{}
	token, err := jwt.ParseWithClaims(ticketString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.secretKey), nil
	})

	if err != nil {
		// Обработка ошибок валидации
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

	// Проверяем claim 'usage'
	if claims.Usage != "websocket_auth" {
		return nil, errors.New("invalid ticket usage")
	}

	// Дополнительная проверка: WS тикет не должен содержать CSRF секрет
	if claims.CSRFSecret != "" {
		log.Printf("[JWT] Ошибка: WS-тикет для пользователя ID=%d содержит CSRF секрет", claims.UserID)
		return nil, errors.New("WS ticket should not contain CSRF secret")
	}

	// Проверка инвалидации НЕ НУЖНА для WS тикетов

	return claims, nil
}

// GenerateWSTicket создает короткоживущий JWT для аутентификации WebSocket
func (s *JWTService) GenerateWSTicket(userID uint, email string) (string, error) {
	claims := &JWTCustomClaims{
		UserID: userID,
		Email:  email,
		Usage:  "websocket_auth", // Указываем назначение токена
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.wsTicketExpiry)), // Используем настраиваемое время жизни
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(s.secretKey))
	if err != nil {
		log.Printf("[JWT] Ошибка генерации WS-тикета для пользователя ID=%d: %v", userID, err)
		return "", err
	}

	log.Printf("[JWT] WS-тикет успешно сгенерирован для пользователя ID=%d, истекает через %v",
		userID, s.wsTicketExpiry)
	return tokenString, nil
}

// min возвращает минимальное из двух чисел
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
