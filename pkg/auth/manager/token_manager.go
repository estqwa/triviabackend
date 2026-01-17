package manager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"github.com/yourusername/trivia-api/pkg/auth"
)

// Константы для настройки токенов
const (
	// Время жизни access-токена (15 минут)
	AccessTokenLifetime = 15 * time.Minute
	// Время жизни refresh-токена (30 дней)
	RefreshTokenLifetime = 30 * 24 * time.Hour
	// Максимальное количество активных refresh-токенов на пользователя (по умолчанию)
	DefaultMaxRefreshTokensPerUser = 10
	// Имя cookie для refresh-токена
	RefreshTokenCookie = "refresh_token"
	// Имя cookie для access-токена
	AccessTokenCookie = "access_token"
	// Имя заголовка для CSRF токена (хеша)
	CSRFHeader = "X-CSRF-Token"
	// Имя cookie для CSRF секрета (HttpOnly, Secure)
	CSRFSecretCookie = "__Host-csrf-secret" // Используем __Host- префикс для безопасности

	// Время жизни ключа JWT по умолчанию
	DefaultJWTKeyLifetime = 90 * 24 * time.Hour // 90 дней
)

// TokenErrorType определяет тип ошибки токена
type TokenErrorType string

const (
	// Ошибки генерации токенов
	TokenGenerationFailed TokenErrorType = "TOKEN_GENERATION_FAILED"

	// Ошибки валидации
	InvalidRefreshToken TokenErrorType = "INVALID_REFRESH_TOKEN"
	ExpiredRefreshToken TokenErrorType = "EXPIRED_REFRESH_TOKEN"
	InvalidAccessToken  TokenErrorType = "INVALID_ACCESS_TOKEN"
	ExpiredAccessToken  TokenErrorType = "EXPIRED_ACCESS_TOKEN"
	InvalidCSRFToken    TokenErrorType = "INVALID_CSRF_TOKEN"
	UserNotFound        TokenErrorType = "USER_NOT_FOUND"
	InactiveUser        TokenErrorType = "INACTIVE_USER"

	// Ошибки базы данных или репозитория
	DatabaseError TokenErrorType = "DATABASE_ERROR"

	// Прочие ошибки
	TokenRevoked     TokenErrorType = "TOKEN_REVOKED"
	TooManySessions  TokenErrorType = "TOO_MANY_SESSIONS"
	KeyRotationError TokenErrorType = "KEY_ROTATION_ERROR"
	KeyNotFoundError TokenErrorType = "KEY_NOT_FOUND"
)

// TokenError представляет ошибку при работе с токенами
type TokenError struct {
	Type    TokenErrorType
	Message string
	Err     error
}

// Error возвращает строковое представление ошибки
func (e *TokenError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (%v)", e.Type, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Type, e.Message)
}

// NewTokenError создает новую ошибку токена
func NewTokenError(tokenType TokenErrorType, message string, err error) *TokenError {
	return &TokenError{
		Type:    tokenType,
		Message: message,
		Err:     err,
	}
}

// TokenInfo содержит информацию о сроке действия токенов
type TokenInfo struct {
	AccessTokenExpires   time.Time `json:"access_token_expires"`
	RefreshTokenExpires  time.Time `json:"refresh_token_expires"`
	AccessTokenValidFor  float64   `json:"access_token_valid_for"`
	RefreshTokenValidFor float64   `json:"refresh_token_valid_for"`
}

// CSRFToken содержит данные CSRF токена
type CSRFToken struct {
	Token     string
	ExpiresAt time.Time
}

// TokenResponse представляет ответ с токенами
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	CSRFToken    string `json:"csrf_token"`
	UserID       uint   `json:"user_id"`
	RefreshToken string `json:"-"` // Добавляем поле, но исключаем из JSON
	CSRFSecret   string `json:"-"` // Добавляем поле для секрета (не для JSON)
}

// TokenManager управляет выдачей и валидацией токенов
type TokenManager struct {
	jwtService              *auth.JWTService
	refreshTokenRepo        repository.RefreshTokenRepository
	userRepo                repository.UserRepository
	jwtKeyRepo              repository.JWTKeyRepository
	accessTokenExpiry       time.Duration
	refreshTokenExpiry      time.Duration
	maxRefreshTokensPerUser int // Добавлено: настраиваемый лимит сессий
	// Настройки для Cookie
	cookiePath       string
	cookieDomain     string
	cookieSecure     bool // Заменит isProductionMode для прямой настройки
	cookieHttpOnly   bool
	cookieSameSite   http.SameSite
	isProductionMode bool // Оставляем для обратной совместимости или альтернативной настройки Secure
}

// NewTokenManager создает новый менеджер токенов и возвращает ошибку при проблемах
func NewTokenManager(
	refreshTokenRepo repository.RefreshTokenRepository,
	userRepo repository.UserRepository,
	jwtKeyRepo repository.JWTKeyRepository,
) (*TokenManager, error) {
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("RefreshTokenRepository is required for TokenManager")
	}
	if userRepo == nil {
		return nil, fmt.Errorf("UserRepository is required for TokenManager")
	}
	if jwtKeyRepo == nil {
		return nil, fmt.Errorf("JWTKeyRepository is required for TokenManager")
	}

	// Устанавливаем значения по умолчанию, если они не были заданы
	accessTokenExpiry := 30 * time.Minute     // Можно вынести в конфигурацию
	refreshTokenExpiry := 30 * 24 * time.Hour // Можно вынести в конфигурацию
	maxRefreshTokens := 10                    // Можно вынести в конфигурацию

	tm := &TokenManager{
		refreshTokenRepo:        refreshTokenRepo,
		userRepo:                userRepo,
		jwtKeyRepo:              jwtKeyRepo,
		accessTokenExpiry:       accessTokenExpiry,
		refreshTokenExpiry:      refreshTokenExpiry,
		maxRefreshTokensPerUser: maxRefreshTokens,
		// Инициализация настроек cookie по умолчанию
		cookiePath:       "/",
		cookieDomain:     "",   // Пустое значение означает, что браузер использует хост
		cookieSecure:     true, // По умолчанию безопасно
		cookieHttpOnly:   true,
		cookieSameSite:   http.SameSiteStrictMode,
		isProductionMode: true, // По умолчанию считаем production
	}

	// Инициализируем и проверяем наличие ключей при старте
	if err := tm.initializeAndEnsureKeys(context.Background()); err != nil {
		// Логируем ошибку, но не прерываем работу, если JWTService может работать со своим статическим ключом (хотя это не рекомендуется)
		log.Printf("CRITICAL: Failed to initialize JWT keys from repository: %v. TokenManager might not function correctly.", err)
		// Можно вернуть ошибку, чтобы приложение не стартовало без ключей:
		// return nil, fmt.Errorf("failed to initialize JWT keys: %w", err)
	}

	return tm, nil
}

// SetJWTService устанавливает зависимость от JWTService после инициализации.
func (m *TokenManager) SetJWTService(jwtService *auth.JWTService) {
	if jwtService == nil {
		log.Println("WARN: [TokenManager] Attempted to set a nil JWTService.")
		return
	}
	m.jwtService = jwtService
	log.Println("[TokenManager] JWTService has been set.")
}

// SetAccessTokenExpiry устанавливает время жизни access токена
func (m *TokenManager) SetAccessTokenExpiry(duration time.Duration) {
	if duration > 0 {
		m.accessTokenExpiry = duration
		log.Printf("[TokenManager] Access token expiry set to: %v", duration)
	} else {
		log.Printf("[TokenManager] Warning: Invalid access token expiry duration provided: %v. Using default: %v", duration, m.accessTokenExpiry)
	}
}

// SetRefreshTokenExpiry устанавливает время жизни refresh токена
func (m *TokenManager) SetRefreshTokenExpiry(duration time.Duration) {
	if duration > 0 {
		m.refreshTokenExpiry = duration
		log.Printf("[TokenManager] Refresh token expiry set to: %v", duration)
	} else {
		log.Printf("[TokenManager] Warning: Invalid refresh token expiry duration provided: %v. Using default: %v", duration, m.refreshTokenExpiry)
	}
}

// SetProductionMode устанавливает флаг режима production для Secure cookies
// Обновлено: теперь влияет на cookieSecure, если она не установлена явно
func (m *TokenManager) SetProductionMode(isProduction bool) {
	m.isProductionMode = isProduction
	// Устанавливаем cookieSecure на основе режима, если он не был установлен иначе
	m.cookieSecure = isProduction
	log.Printf("[TokenManager] Production mode set to: %v, Cookie Secure set to: %v", isProduction, m.cookieSecure)
}

// SetCookieAttributes позволяет настроить атрибуты cookie
func (m *TokenManager) SetCookieAttributes(path, domain string, secure, httpOnly bool, sameSite http.SameSite) {
	m.cookiePath = path
	m.cookieDomain = domain
	m.cookieSecure = secure
	m.cookieHttpOnly = httpOnly
	m.cookieSameSite = sameSite
	log.Printf("[TokenManager] Cookie attributes set: Path=%s, Domain=%s, Secure=%v, HttpOnly=%v, SameSite=%v",
		path, domain, secure, httpOnly, sameSite)
}

// SetMaxRefreshTokensPerUser устанавливает максимальное количество активных refresh-токенов на пользователя.
// Это значение обычно берется из конфигурации при старте приложения.
func (m *TokenManager) SetMaxRefreshTokensPerUser(limit int) {
	if limit > 0 {
		m.maxRefreshTokensPerUser = limit
		log.Printf("[TokenManager] Max refresh tokens per user set to: %d", limit)
	} else {
		log.Printf("[TokenManager] Warning: Invalid max refresh tokens per user provided: %d. Using default: %d", limit, m.maxRefreshTokensPerUser)
	}
}

// GetMaxRefreshTokensPerUser возвращает текущее максимальное количество активных refresh-токенов на пользователя.
func (m *TokenManager) GetMaxRefreshTokensPerUser() int {
	return m.maxRefreshTokensPerUser
}

// GenerateTokenPair создает новую пару токенов (access и refresh)
// Эта функция теперь использует jwtService напрямую, а не через tokenService
func (m *TokenManager) GenerateTokenPair(userID uint, deviceID, ipAddress, userAgent string) (*TokenResponse, error) {
	if m.jwtService == nil {
		log.Println("CRITICAL: [TokenManager] JWTService not set in TokenManager. Cannot generate tokens.")
		return nil, NewTokenError(TokenGenerationFailed, "JWTService not configured", nil)
	}

	user, err := m.userRepo.GetByID(userID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при получении пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(UserNotFound, "пользователь не найден", err)
	}

	// Получаем текущий ключ для подписи
	signingKey, keyErr := m.GetCurrentSigningKey(context.Background()) // Используем фоновый контекст
	if keyErr != nil {
		log.Printf("CRITICAL: Failed to get current signing key for GenerateTokenPair: %v", keyErr)
		return nil, NewTokenError(KeyNotFoundError, "не удалось получить ключ для подписи токена", keyErr)
	}

	// Генерируем CSRF секрет
	csrfSecret := generateRandomString(32)

	// Генерируем access-токен через jwtService, передавая ключ
	accessToken, err := m.jwtService.GenerateTokenWithKey(user, csrfSecret, signingKey)
	if err != nil {
		log.Printf("[TokenManager] Ошибка генерации access-токена для пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(TokenGenerationFailed, "ошибка генерации access токена", err)
	}

	// Генерируем CSRF токен (хеш)
	csrfTokenHash := HashCSRFSecret(csrfSecret)

	// Генерируем refresh-токен
	refreshTokenString, err := m.generateRefreshToken(userID, deviceID, ipAddress, userAgent)
	if err != nil {
		log.Printf("[TokenManager] Ошибка генерации refresh-токена для пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(TokenGenerationFailed, "ошибка генерации refresh токена", err)
	}

	// Лимитируем количество активных refresh-токенов
	err = m.limitUserSessions(userID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при лимитировании сессий пользователя ID=%d: %v", userID, err)
	}

	log.Printf("[TokenManager] Сгенерирована пара токенов для пользователя ID=%d, JWT Key ID: %s", userID, signingKey.ID)

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.accessTokenExpiry.Seconds()),
		CSRFToken:    csrfTokenHash,
		UserID:       userID,
		RefreshToken: refreshTokenString,
		CSRFSecret:   csrfSecret,
	}, nil
}

// RefreshTokens обновляет пару токенов, используя refresh токен
// Эта функция теперь использует jwtService напрямую
func (m *TokenManager) RefreshTokens(refreshToken, csrfTokenHeader, deviceID, ipAddress, userAgent string) (*TokenResponse, error) {
	if m.jwtService == nil {
		log.Println("CRITICAL: [TokenManager] JWTService not set in TokenManager. Cannot refresh tokens.")
		return nil, NewTokenError(TokenGenerationFailed, "JWTService not configured", nil)
	}
	// Валидируем refresh токен
	tokenEntity, err := m.refreshTokenRepo.GetTokenByValue(refreshToken)
	if err != nil {
		// TODO: Обработать repository.ErrExpiredToken отдельно или перенести его в apperrors
		// if errors.Is(err, apperrors.ErrNotFound) { // Старый код
		// Проверяем на обе ошибки: не найдено или истек
		if errors.Is(err, apperrors.ErrNotFound) || errors.Is(err, apperrors.ErrExpiredToken) {
			return nil, NewTokenError(InvalidRefreshToken, "недействительный или истекший refresh токен", err)
		}
		log.Printf("[TokenManager] Ошибка при получении refresh-токена: %v", err)
		return nil, NewTokenError(DatabaseError, "ошибка при проверке refresh токена", err)
	}

	// Получаем пользователя
	user, err := m.userRepo.GetByID(tokenEntity.UserID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при получении пользователя ID=%d для обновления токенов: %v", tokenEntity.UserID, err)
		return nil, NewTokenError(UserNotFound, "пользователь не найден", err)
	}

	// Помечаем старый refresh токен как истекший
	if err := m.refreshTokenRepo.MarkTokenAsExpired(refreshToken, "rotated"); err != nil {
		log.Printf("[TokenManager] Ошибка при маркировке старого refresh-токена как истекшего (ID: %d): %v", tokenEntity.ID, err)
		// Не критично, продолжаем
	}

	// Получаем текущий ключ для подписи нового access токена
	signingKey, keyErr := m.GetCurrentSigningKey(context.Background())
	if keyErr != nil {
		log.Printf("CRITICAL: Failed to get current signing key for RefreshTokens: %v", keyErr)
		return nil, NewTokenError(KeyNotFoundError, "не удалось получить ключ для подписи токена", keyErr)
	}

	// Генерируем НОВЫЙ CSRF секрет
	newCsrfSecret := generateRandomString(32)

	// Генерируем новый access токен через jwtService, передавая ключ
	newAccessToken, err := m.jwtService.GenerateTokenWithKey(user, newCsrfSecret, signingKey)
	if err != nil {
		log.Printf("[TokenManager] Ошибка генерации нового access-токена для пользователя ID=%d: %v", user.ID, err)
		return nil, NewTokenError(TokenGenerationFailed, "ошибка генерации нового access токена", err)
	}

	// Генерируем новый refresh токен
	newRefreshTokenString, err := m.generateRefreshToken(user.ID, deviceID, ipAddress, userAgent)
	if err != nil {
		log.Printf("[TokenManager] Ошибка генерации нового refresh-токена для пользователя ID=%d: %v", user.ID, err)
		return nil, NewTokenError(TokenGenerationFailed, "ошибка генерации нового refresh токена", err)
	}

	// Лимитируем сессии снова
	err = m.limitUserSessions(user.ID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при лимитировании сессий пользователя ID=%d после обновления: %v", user.ID, err)
	}

	// Генерируем новый CSRF токен (хеш)
	newCSRFTokenHash := HashCSRFSecret(newCsrfSecret)

	log.Printf("[TokenManager] Обновлена пара токенов для пользователя ID=%d, JWT Key ID: %s", user.ID, signingKey.ID)

	return &TokenResponse{
		AccessToken:  newAccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.accessTokenExpiry.Seconds()),
		CSRFToken:    newCSRFTokenHash,
		UserID:       user.ID,
		RefreshToken: newRefreshTokenString,
		CSRFSecret:   newCsrfSecret,
	}, nil
}

// GetTokenInfo возвращает информацию о сроках действия текущих токенов
func (m *TokenManager) GetTokenInfo(refreshToken string) (*TokenInfo, error) {
	// Находим refresh-токен в БД
	token, err := m.refreshTokenRepo.GetTokenByValue(refreshToken)
	if err != nil {
		return nil, NewTokenError(InvalidRefreshToken, "Недействительный refresh-токен", err)
	}

	// Вычисляем время истечения access-токена (примерно)
	accessTokenExpires := time.Now().Add(m.accessTokenExpiry)

	now := time.Now()
	return &TokenInfo{
		AccessTokenExpires:   accessTokenExpires,
		RefreshTokenExpires:  token.ExpiresAt,
		AccessTokenValidFor:  accessTokenExpires.Sub(now).Seconds(),
		RefreshTokenValidFor: token.ExpiresAt.Sub(now).Seconds(),
	}, nil
}

// RevokeRefreshToken отзывает (помечает как истекший) указанный refresh токен
func (m *TokenManager) RevokeRefreshToken(refreshToken string) error {
	if err := m.refreshTokenRepo.MarkTokenAsExpired(refreshToken, "revoked"); err != nil {
		// Проверяем, была ли ошибка "не найдено"
		// if errors.Is(err, repository.ErrNotFound) { // Старый код
		if errors.Is(err, apperrors.ErrNotFound) { // Используем новую ошибку
			log.Printf("[TokenManager] Попытка отозвать несуществующий refresh токен.")
			return NewTokenError(InvalidRefreshToken, "токен не найден", err) // Возвращаем ошибку недействительного токена
		}
		log.Printf("[TokenManager] Ошибка при отзыве refresh-токена: %v", err)
		return NewTokenError(DatabaseError, "ошибка при отзыве токена", err)
	}

	log.Printf("[TokenManager] Отозван refresh-токен")
	return nil
}

// RevokeAllUserTokens отзывает все refresh-токены пользователя
func (m *TokenManager) RevokeAllUserTokens(userID uint) error {
	if m.jwtService == nil {
		log.Println("CRITICAL: [TokenManager] JWTService not set in TokenManager. Cannot invalidate JWT tokens.")
		// Продолжаем отзывать refresh токены, но логируем проблему
	}

	// Помечаем все refresh-токены пользователя как истекшие
	if err := m.refreshTokenRepo.MarkAllAsExpiredForUser(userID, "logout_all"); err != nil {
		log.Printf("[TokenManager] Ошибка при отзыве всех refresh-токенов пользователя ID=%d: %v", userID, err)
		// Даже если произошла ошибка с refresh токенами, пытаемся инвалидировать JWT, если сервис доступен
		if m.jwtService != nil {
			if jwtErr := m.jwtService.InvalidateTokensForUser(context.Background(), userID); jwtErr != nil {
				log.Printf("[TokenManager] Дополнительная ошибка при инвалидации JWT токенов пользователя ID=%d: %v", userID, jwtErr)
			}
		}
		return NewTokenError(DatabaseError, "ошибка отзыва refresh токенов", err)
	}

	// Дополнительно инвалидируем JWT после успешного отзыва refresh токенов, если сервис доступен
	if m.jwtService != nil {
		if jwtErr := m.jwtService.InvalidateTokensForUser(context.Background(), userID); jwtErr != nil {
			log.Printf("[TokenManager] Ошибка при инвалидации JWT токенов пользователя ID=%d после отзыва refresh токенов: %v", userID, jwtErr)
			// Не возвращаем ошибку JWT как критическую, так как refresh уже отозваны
		}
	}

	log.Printf("[TokenManager] Отозваны все токены пользователя ID=%d", userID)
	return nil
}

// GetUserActiveSessions возвращает список активных сессий (refresh токенов) для пользователя
func (m *TokenManager) GetUserActiveSessions(userID uint) ([]entity.RefreshToken, error) {
	tokensPtr, err := m.refreshTokenRepo.GetActiveTokensForUser(userID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при получении активных сессий пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(DatabaseError, "ошибка получения сессий", err)
	}

	// Преобразуем []*entity.RefreshToken в []entity.RefreshToken
	tokens := make([]entity.RefreshToken, len(tokensPtr))
	for i, t := range tokensPtr {
		tokens[i] = *t
	}

	log.Printf("[TokenManager] Получено %d активных токенов пользователя ID=%d", len(tokens), userID)
	return tokens, nil
}

// SetRefreshTokenCookie устанавливает refresh-токен в HttpOnly куки
func (m *TokenManager) SetRefreshTokenCookie(w http.ResponseWriter, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    refreshToken,
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure, // Используем настроенное значение
		SameSite: m.cookieSameSite,
		MaxAge:   int(m.refreshTokenExpiry.Seconds()),
	})
}

// SetAccessTokenCookie устанавливает access-токен в HttpOnly куки
func (m *TokenManager) SetAccessTokenCookie(w http.ResponseWriter, accessToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    accessToken,
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure, // Используем настроенное значение
		SameSite: m.cookieSameSite,
		MaxAge:   int(m.accessTokenExpiry.Seconds()),
	})
}

// SetCSRFSecretCookie устанавливает CSRF-секрет в HttpOnly куку
// Добавлено: Новая функция для установки куки секрета
func (m *TokenManager) SetCSRFSecretCookie(w http.ResponseWriter, csrfSecret string) {
	// Время жизни куки секрета должно совпадать со временем жизни access токена
	maxAge := int(m.accessTokenExpiry.Seconds())

	// Используем __Host- префикс только если cookieSecure=true (т.е. в production)
	cookieName := CSRFSecretCookie
	if !m.cookieSecure { // Если НЕ production (HTTP)
		// Убираем префикс __Host-, т.к. он требует Secure=true
		cookieName = strings.TrimPrefix(cookieName, "__Host-")
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName, // Используем скорректированное имя
		Value:    csrfSecret,
		Path:     m.cookiePath,     // Должен быть "/"
		Domain:   m.cookieDomain,   // Должен быть "" для __Host- (но может быть пустым и без него)
		HttpOnly: m.cookieHttpOnly, // True
		Secure:   m.cookieSecure,   // Используем значение из TokenManager (true для prod, false для dev)
		SameSite: m.cookieSameSite, // Lax или Strict
		MaxAge:   maxAge,
	})
	log.Printf("[TokenManager] Установлена CSRF secret cookie (%s) с Secure=%v, MaxAge: %d секунд", cookieName, m.cookieSecure, maxAge)
}

// GetRefreshTokenFromCookie получает refresh-токен из куки
func (m *TokenManager) GetRefreshTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(RefreshTokenCookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", NewTokenError(InvalidRefreshToken, "кука refresh_token не найдена", err)
		}
		return "", NewTokenError(InvalidRefreshToken, "ошибка чтения куки refresh_token", err)
	}
	return cookie.Value, nil
}

// GetAccessTokenFromCookie получает access-токен из куки
func (m *TokenManager) GetAccessTokenFromCookie(r *http.Request) (string, error) {
	cookie, err := r.Cookie(AccessTokenCookie)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", NewTokenError(InvalidAccessToken, "кука access_token не найдена", err)
		}
		return "", NewTokenError(InvalidAccessToken, "ошибка чтения куки access_token", err)
	}
	return cookie.Value, nil
}

// GetCSRFSecretFromCookie получает CSRF-секрет из куки
// Добавлено: Новая функция для получения куки секрета
func (m *TokenManager) GetCSRFSecretFromCookie(r *http.Request) (string, error) {
	// Пробуем найти куку с префиксом __Host- и без него
	cookieNameWithPrefix := CSRFSecretCookie
	cookieNameWithoutPrefix := strings.TrimPrefix(CSRFSecretCookie, "__Host-")

	cookie, err := r.Cookie(cookieNameWithPrefix)
	if err != nil {
		// Если кука с префиксом не найдена, пробуем без префикса
		cookie, err = r.Cookie(cookieNameWithoutPrefix)
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				log.Printf("[TokenManager] CSRF secret cookie ('%s' or '%s') not found", cookieNameWithPrefix, cookieNameWithoutPrefix)
				return "", NewTokenError(InvalidCSRFToken, "кука CSRF секрета не найдена", err)
			}
			log.Printf("[TokenManager] Error reading CSRF secret cookie ('%s' or '%s'): %v", cookieNameWithPrefix, cookieNameWithoutPrefix, err)
			return "", NewTokenError(InvalidCSRFToken, "ошибка чтения куки CSRF секрета", err)
		}
	}

	// Логируем успешное получение куки
	log.Printf("[TokenManager] Successfully retrieved CSRF secret cookie '%s'", cookie.Name)
	return cookie.Value, nil
}

// ClearRefreshTokenCookie удаляет cookie с refresh-токеном
func (m *TokenManager) ClearRefreshTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshTokenCookie,
		Value:    "",
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure,
		SameSite: m.cookieSameSite,
		MaxAge:   -1,
	})
}

// ClearAccessTokenCookie удаляет cookie с access-токеном
func (m *TokenManager) ClearAccessTokenCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     AccessTokenCookie,
		Value:    "",
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure,
		SameSite: m.cookieSameSite,
		MaxAge:   -1,
	})
}

// ClearCSRFSecretCookie удаляет cookie с CSRF-секретом
// Добавлено: Новая функция для очистки куки секрета
func (m *TokenManager) ClearCSRFSecretCookie(w http.ResponseWriter) {
	// Удаляем обе версии куки (с префиксом и без) на всякий случай
	cookieNameWithPrefix := CSRFSecretCookie
	cookieNameWithoutPrefix := strings.TrimPrefix(CSRFSecretCookie, "__Host-")

	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameWithPrefix, // С префиксом
		Value:    "",
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure,
		SameSite: m.cookieSameSite,
		MaxAge:   -1, // Удаление куки
	})
	http.SetCookie(w, &http.Cookie{
		Name:     cookieNameWithoutPrefix, // Без префикса
		Value:    "",
		Path:     m.cookiePath,
		Domain:   m.cookieDomain,
		HttpOnly: m.cookieHttpOnly,
		Secure:   m.cookieSecure,
		SameSite: m.cookieSameSite,
		MaxAge:   -1, // Удаление куки
	})
}

// CleanupExpiredTokens удаляет все истекшие refresh-токены
func (m *TokenManager) CleanupExpiredTokens() error {
	if m.jwtService == nil {
		log.Println("WARN: [TokenManager] JWTService not set in TokenManager. Skipping JWT invalidation cleanup.")
		// Продолжаем очистку refresh токенов
	}

	count, err := m.refreshTokenRepo.CleanupExpiredTokens()
	if err != nil {
		log.Printf("[TokenManager] Ошибка при очистке истекших refresh-токенов: %v", err)
		// Очистка JWT инвалидаций, если сервис доступен
		if m.jwtService != nil {
			if jwtErr := m.jwtService.CleanupInvalidatedUsers(context.Background()); jwtErr != nil {
				log.Printf("[TokenManager] Дополнительная ошибка при очистке инвалидированных JWT токенов: %v", jwtErr)
			}
		}
		return NewTokenError(DatabaseError, "ошибка очистки истекших токенов", err)
	}

	// Для обратной совместимости также запускаем очистку инвалидированных JWT-токенов, если сервис доступен
	if m.jwtService != nil {
		if err := m.jwtService.CleanupInvalidatedUsers(context.Background()); err != nil {
			log.Printf("[TokenManager] Ошибка при очистке инвалидированных JWT токенов: %v", err)
			// Не возвращаем ошибку, так как основная очистка прошла
		}
	}

	log.Printf("[TokenManager] Выполнена очистка %d истекших токенов", count)
	return nil
}

// RotateJWTKeys выполняет ротацию ключей подписи JWT, используя репозиторий.
func (m *TokenManager) RotateJWTKeys(ctx context.Context) (string, error) {
	log.Println("[TokenManager] Initiating JWT key rotation...")

	// 1. Получаем текущий активный ключ
	currentActiveKey, err := m.jwtKeyRepo.GetActiveKey(ctx)
	if err != nil && !errors.Is(err, apperrors.ErrNotFound) {
		return "", fmt.Errorf("failed to get current active key for rotation: %w", err)
	}

	// 2. Деактивируем текущий ключ (если он есть)
	if currentActiveKey != nil {
		now := time.Now()
		if err := m.jwtKeyRepo.DeactivateKey(ctx, currentActiveKey.ID, now); err != nil {
			log.Printf("WARN: Failed to deactivate previous JWT key ID %s during rotation: %v", currentActiveKey.ID, err)
		} else {
			log.Printf("[TokenManager] Deactivated previous JWT key ID: %s", currentActiveKey.ID)
		}
	}

	// 3. Генерируем новый ключ
	newKeyID := generateRandomString(16)
	newSecret := generateRandomString(64)
	now := time.Now()
	expiry := now.Add(DefaultJWTKeyLifetime)

	newKey := &entity.JWTKey{
		ID:        newKeyID,
		Key:       newSecret,
		Algorithm: string(jwt.SigningMethodHS256.Alg()),
		IsActive:  true,
		CreatedAt: now,
		ExpiresAt: expiry,
	}

	// 4. Сохраняем новый ключ
	if err := m.jwtKeyRepo.CreateKey(ctx, newKey); err != nil {
		return "", fmt.Errorf("failed to create new JWT key during rotation: %w", err)
	}

	log.Printf("[TokenManager] Successfully rotated JWT key. New active key ID: %s", newKeyID)
	return newKeyID, nil
}

// GetCurrentSigningKey возвращает текущий активный ключ для подписи JWT из репозитория.
// Возвращает ключ с РАСШИФРОВАННЫМ секретом.
func (m *TokenManager) GetCurrentSigningKey(ctx context.Context) (*entity.JWTKey, error) {
	key, err := m.jwtKeyRepo.GetActiveKey(ctx)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			// Это критическая ситуация, если инициализация прошла, а ключа нет
			log.Println("CRITICAL: No active JWT key found after initialization. Attempting to re-initialize.")
			// Попытка восстановиться (может быть рискованно в production без доп. логики)
			if initErr := m.initializeAndEnsureKeys(ctx); initErr != nil {
				return nil, fmt.Errorf("failed to re-initialize keys after active key not found: %w", initErr)
			}
			// Повторная попытка получить ключ
			key, err = m.jwtKeyRepo.GetActiveKey(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get active key even after re-initialization: %w", err)
			}
		}
		// Возвращаем исходную или новую ошибку
		return nil, fmt.Errorf("failed to get current signing key: %w", err)
	}
	return key, nil
}

// GetKeysForValidation возвращает карту ключей для проверки подписи JWT.
// Ключ карты - Key ID (kid), значение - РАСШИФРОВАННЫЙ секрет.
func (m *TokenManager) GetKeysForValidation(ctx context.Context) (map[string]string, error) {
	keys, err := m.jwtKeyRepo.GetValidationKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWT validation keys from repository: %w", err)
	}

	validationKeyMap := make(map[string]string, len(keys))
	for _, key := range keys {
		if key.Algorithm == string(jwt.SigningMethodHS256.Alg()) { // Проверяем, что алгоритм поддерживается (HS256)
			validationKeyMap[key.ID] = key.Key // Key здесь уже расшифрован
		} else {
			log.Printf("WARN: Skipping JWT key ID %s for validation due to unsupported algorithm: %s", key.ID, key.Algorithm)
		}
	}

	if len(validationKeyMap) == 0 {
		log.Println("WARN: No validation keys found. This might happen on initial startup before the first key is fully propagated.")
		// Возвращаем пустую карту, JWTService должен будет обработать эту ситуацию
		// (например, отказать в валидации, если нет ключей)
	}

	return validationKeyMap, nil
}

// initializeAndEnsureKeys проверяет наличие активного ключа в репозитории и создает его при необходимости.
func (m *TokenManager) initializeAndEnsureKeys(ctx context.Context) error {
	log.Println("[TokenManager] Initializing and ensuring JWT keys...")
	activeKey, err := m.jwtKeyRepo.GetActiveKey(ctx)
	if err != nil && !errors.Is(err, apperrors.ErrNotFound) {
		// Реальная ошибка при доступе к репозиторию
		return fmt.Errorf("error checking for active JWT key: %w", err)
	}

	if activeKey == nil { // Если ошибок нет, но ключ не найден (apperrors.ErrNotFound или первый запуск)
		log.Println("[TokenManager] No active JWT key found in repository. Generating initial key...")
		// Генерируем самый первый ключ
		newKeyID := generateRandomString(16)
		newSecret := generateRandomString(64) // Генерируем 32 байта секрета в hex виде (64 символов)
		now := time.Now()
		// Используем DefaultJWTKeyLifetime для срока жизни ключа
		expiry := now.Add(DefaultJWTKeyLifetime)

		initialKey := &entity.JWTKey{
			ID:        newKeyID,
			Key:       newSecret,
			Algorithm: string(jwt.SigningMethodHS256.Alg()),
			IsActive:  true,
			CreatedAt: now,
			ExpiresAt: expiry,
		}

		if err := m.jwtKeyRepo.CreateKey(ctx, initialKey); err != nil {
			return fmt.Errorf("failed to create initial JWT key: %w", err)
		}
		log.Printf("[TokenManager] Successfully generated and stored initial JWT key ID: %s", newKeyID)
	} else {
		log.Printf("[TokenManager] Active JWT key ID: %s found in repository.", activeKey.ID)
	}
	return nil
}

// Служебные функции

// generateRefreshToken генерирует новый refresh-токен и сохраняет его в БД
// Теперь возвращает сгенерированную строку токена
func (m *TokenManager) generateRefreshToken(userID uint, deviceID, ipAddress, userAgent string) (string, error) {
	// Генерируем случайный токен
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	tokenString := hex.EncodeToString(randomBytes)

	// Время истечения - "скользящее окно" 30 дней от текущего момента
	expiresAt := time.Now().Add(m.refreshTokenExpiry)

	// Создаем запись в БД
	token := entity.NewRefreshToken(userID, tokenString, deviceID, ipAddress, userAgent, expiresAt)

	// Сохраняем в БД
	_, err := m.refreshTokenRepo.CreateToken(token)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// generateRandomString генерирует случайную строку указанной длины в hex формате
func generateRandomString(length int) string {
	b := make([]byte, length/2) // Каждый байт кодируется двумя hex символами
	if _, err := rand.Read(b); err != nil {
		// В реальном приложении здесь должна быть более надежная обработка ошибки,
		// возможно, паника, так как генерация секретов критична.
		log.Printf("CRITICAL: Ошибка генерации случайных байт: %v", err)
		panic(fmt.Sprintf("Failed to generate random string: %v", err))
	}
	return hex.EncodeToString(b)
}

// HashCSRFSecret хеширует CSRF секрет с использованием SHA-256
// Теперь публичная функция
func HashCSRFSecret(secret string) string {
	hasher := sha256.New()
	hasher.Write([]byte(secret))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Добавляем хелпер для лимитирования сессий, чтобы избежать дублирования кода
func (m *TokenManager) limitUserSessions(userID uint) error {
	count, err := m.refreshTokenRepo.CountTokensForUser(userID)
	if err != nil {
		return fmt.Errorf("ошибка подсчета токенов: %w", err)
	}

	if count > m.maxRefreshTokensPerUser {
		log.Printf("[TokenManager] Превышен лимит сессий для пользователя ID=%d (%d > %d). Удаление старых.", userID, count, m.maxRefreshTokensPerUser)
		if err := m.refreshTokenRepo.MarkOldestAsExpiredForUser(userID, m.maxRefreshTokensPerUser, "session_limit"); err != nil {
			return fmt.Errorf("ошибка маркировки старых токенов: %w", err)
		}
	}
	return nil
}
