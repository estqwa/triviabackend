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
	"sync"
	"time"

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

// JWTKeyRotation описывает ключ подписи JWT с метаданными
type JWTKeyRotation struct {
	ID        string    // Идентификатор ключа
	Secret    string    // Секретный ключ
	CreatedAt time.Time // Время создания
	ExpiresAt time.Time // Время истечения
	IsActive  bool      // Флаг активности
}

// TokenManager управляет выдачей и валидацией токенов
type TokenManager struct {
	jwtService              *auth.JWTService
	refreshTokenRepo        repository.RefreshTokenRepository
	userRepo                repository.UserRepository
	jwtKeys                 []JWTKeyRotation
	jwtKeysMutex            sync.RWMutex
	currentJWTKeyID         string
	accessTokenExpiry       time.Duration
	refreshTokenExpiry      time.Duration
	maxRefreshTokensPerUser int       // Добавлено: настраиваемый лимит сессий
	lastKeyRotation         time.Time // Добавлено: время последней ротации ключей
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
	jwtService *auth.JWTService,
	refreshTokenRepo repository.RefreshTokenRepository,
	userRepo repository.UserRepository,
) (*TokenManager, error) {
	if jwtService == nil {
		return nil, fmt.Errorf("JWTService is required for TokenManager")
	}
	if refreshTokenRepo == nil {
		return nil, fmt.Errorf("RefreshTokenRepository is required for TokenManager")
	}
	if userRepo == nil {
		return nil, fmt.Errorf("UserRepository is required for TokenManager")
	}

	// Устанавливаем значения по умолчанию, если они не были заданы
	accessTokenExpiry := 30 * time.Minute     // Можно вынести в конфигурацию
	refreshTokenExpiry := 30 * 24 * time.Hour // Можно вынести в конфигурацию
	maxRefreshTokens := 10                    // Можно вынести в конфигурацию

	tm := &TokenManager{
		jwtService:              jwtService,
		refreshTokenRepo:        refreshTokenRepo,
		userRepo:                userRepo,
		jwtKeys:                 make([]JWTKeyRotation, 0),
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

	// Инициализация JWT ключей при старте
	if err := tm.InitializeJWTKeys(); err != nil {
		log.Printf("Warning: Failed to initialize JWT keys: %v. Using default secret.", err)
		// Продолжаем работу с секретом из jwtService по умолчанию
	}

	return tm, nil
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

// GenerateTokenPair создает новую пару токенов (access и refresh)
// Эта функция теперь использует jwtService напрямую, а не через tokenService
func (m *TokenManager) GenerateTokenPair(userID uint, deviceID, ipAddress, userAgent string) (*TokenResponse, error) {
	user, err := m.userRepo.GetByID(userID)
	if err != nil {
		log.Printf("[TokenManager] Ошибка при получении пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(UserNotFound, "пользователь не найден", err)
	}

	// Генерируем access-токен с использованием текущего активного ключа
	currentKeyID, _, keyErr := m.GetCurrentJWTKey()
	if keyErr != nil {
		log.Printf("[TokenManager] Ошибка получения текущего JWT ключа: %v. Используем дефолтный.", keyErr)
		// Если ключи не настроены, используем секрет из jwtService
	}

	// Генерируем access-токен через jwtService (он сам обработает ключи, если они есть)
	// ПРИМЕЧАНИЕ: Здесь нужен CSRF секрет. Его нужно сгенерировать ДО вызова GenerateToken.
	// Пока передаем пустую строку, это будет исправлено в следующем шаге.
	csrfSecret := generateRandomString(32)                           // Генерируем секрет здесь
	accessToken, err := m.jwtService.GenerateToken(user, csrfSecret) // Передаем секрет
	if err != nil {
		log.Printf("[TokenManager] Ошибка генерации access-токена для пользователя ID=%d: %v", userID, err)
		return nil, NewTokenError(TokenGenerationFailed, "ошибка генерации access токена", err)
	}

	// Генерируем CSRF токен
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
		// Логируем ошибку, но не прерываем процесс выдачи токенов
		log.Printf("[TokenManager] Ошибка при лимитировании сессий пользователя ID=%d: %v", userID, err)
	}

	log.Printf("[TokenManager] Сгенерирована пара токенов для пользователя ID=%d, JWT Key ID: %s", userID, currentKeyID)

	return &TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(m.accessTokenExpiry.Seconds()),
		CSRFToken:    csrfTokenHash,
		UserID:       userID,
		RefreshToken: refreshTokenString, // Возвращаем refresh токен
		CSRFSecret:   csrfSecret,         // Возвращаем секрет для куки
	}, nil
}

// RefreshTokens обновляет пару токенов, используя refresh токен
// Эта функция теперь использует jwtService напрямую
func (m *TokenManager) RefreshTokens(refreshToken, csrfTokenHeader, deviceID, ipAddress, userAgent string) (*TokenResponse, error) {
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
	if err := m.refreshTokenRepo.MarkTokenAsExpired(refreshToken); err != nil {
		log.Printf("[TokenManager] Ошибка при маркировке старого refresh-токена как истекшего (ID: %d): %v", tokenEntity.ID, err)
		// Не критично, продолжаем
	}

	// Генерируем новый access токен через jwtService
	// ПРИМЕЧАНИЕ: Здесь также нужен НОВЫЙ CSRF секрет.
	// Пока передаем пустую строку, это будет исправлено в следующем шаге.
	newCsrfSecret := generateRandomString(32)                              // Генерируем НОВЫЙ секрет
	newAccessToken, err := m.jwtService.GenerateToken(user, newCsrfSecret) // Передаем НОВЫЙ секрет
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

	// Генерируем новый CSRF токен
	newCSRFTokenHash := HashCSRFSecret(newCsrfSecret)

	log.Printf("[TokenManager] Обновлена пара токенов для пользователя ID=%d", user.ID)

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
	if err := m.refreshTokenRepo.MarkTokenAsExpired(refreshToken); err != nil {
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
	// Помечаем все refresh-токены пользователя как истекшие
	if err := m.refreshTokenRepo.MarkAllAsExpiredForUser(userID); err != nil {
		log.Printf("[TokenManager] Ошибка при отзыве всех refresh-токенов пользователя ID=%d: %v", userID, err)
		// Даже если произошла ошибка с refresh токенами, пытаемся инвалидировать JWT
		if jwtErr := m.jwtService.InvalidateTokensForUser(context.Background(), userID); jwtErr != nil {
			log.Printf("[TokenManager] Дополнительная ошибка при инвалидации JWT токенов пользователя ID=%d: %v", userID, jwtErr)
		}
		return NewTokenError(DatabaseError, "ошибка отзыва refresh токенов", err)
	}

	// Дополнительно инвалидируем JWT после успешного отзыва refresh токенов
	if jwtErr := m.jwtService.InvalidateTokensForUser(context.Background(), userID); jwtErr != nil {
		log.Printf("[TokenManager] Ошибка при инвалидации JWT токенов пользователя ID=%d после отзыва refresh токенов: %v", userID, jwtErr)
		// Не возвращаем ошибку JWT как критическую, так как refresh уже отозваны
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
	count, err := m.refreshTokenRepo.CleanupExpiredTokens()
	if err != nil {
		log.Printf("[TokenManager] Ошибка при очистке истекших refresh-токенов: %v", err)
		// Очистка JWT инвалидаций
		if jwtErr := m.jwtService.CleanupInvalidatedUsers(context.Background()); jwtErr != nil {
			log.Printf("[TokenManager] Дополнительная ошибка при очистке инвалидированных JWT токенов: %v", jwtErr)
		}
		return NewTokenError(DatabaseError, "ошибка очистки истекших токенов", err)
	}

	// Для обратной совместимости также запускаем очистку инвалидированных JWT-токенов
	if err := m.jwtService.CleanupInvalidatedUsers(context.Background()); err != nil {
		log.Printf("[TokenManager] Ошибка при очистке инвалидированных JWT токенов: %v", err)
		// Не возвращаем ошибку, так как основная очистка прошла
	}

	log.Printf("[TokenManager] Выполнена очистка %d истекших токенов", count)
	return nil
}

// RotateJWTKeys выполняет ротацию ключей подписи JWT
func (m *TokenManager) RotateJWTKeys() (string, error) {
	// Убрали проверку пользователя, т.к. ротация - системная операция
	// _, err := m.userRepo.GetByID(userID)
	// if err != nil {
	// 	log.Printf("[TokenManager] Пользователь ID=%d не найден при генерации ключа JWT", userID)
	// 	return "", NewTokenError(UserNotFound, "пользователь не найден", err)
	// }

	// Генерируем новый секрет
	newSecret := generateRandomString(64)
	newKeyID := generateRandomString(16)
	now := time.Now()
	// Используем константу для времени жизни ключа
	expiry := now.Add(DefaultJWTKeyLifetime)

	newKey := JWTKeyRotation{
		ID:        newKeyID,
		Secret:    newSecret,
		CreatedAt: now,
		ExpiresAt: expiry,
		IsActive:  true,
	}

	m.jwtKeysMutex.Lock()
	// Деактивируем текущий активный ключ (если есть)
	for i := range m.jwtKeys {
		if m.jwtKeys[i].IsActive {
			m.jwtKeys[i].IsActive = false
			break
		}
	}
	// Добавляем новый ключ
	m.jwtKeys = append(m.jwtKeys, newKey)
	m.currentJWTKeyID = newKeyID
	m.lastKeyRotation = now
	m.jwtKeysMutex.Unlock()

	// TODO: Добавить логику сохранения ключей в персистентное хранилище (БД, файл)
	// сейчас ключи хранятся только в памяти и теряются при перезапуске
	log.Printf("[TokenManager] Успешно сгенерирован и активирован новый JWT ключ ID: %s", newKeyID)

	return newKeyID, nil
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

// generateNewJWTKey генерирует новый ключ подписи JWT
func (m *TokenManager) generateNewJWTKey() (string, error) {
	// Генерируем случайный ключ
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(randomBytes)
	keyID := fmt.Sprintf("key-%d", time.Now().UnixNano())

	// Добавляем новый ключ
	m.jwtKeysMutex.Lock()
	defer m.jwtKeysMutex.Unlock()

	// Создаем новый ключ
	newKey := JWTKeyRotation{
		ID:        keyID,
		Secret:    secret,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour), // 90 дней
		IsActive:  true,
	}

	// Добавляем в список ключей
	m.jwtKeys = append(m.jwtKeys, newKey)
	m.currentJWTKeyID = keyID

	return keyID, nil
}

// deactivateOldJWTKeys помечает старые (неактивные и истекшие) ключи
func (m *TokenManager) deactivateOldJWTKeys() {
	m.jwtKeysMutex.Lock()
	defer m.jwtKeysMutex.Unlock()

	// Деактивируем ключи старше 60 дней
	cutoffTime := time.Now().Add(-60 * 24 * time.Hour)
	for i := range m.jwtKeys {
		if m.jwtKeys[i].CreatedAt.Before(cutoffTime) {
			m.jwtKeys[i].IsActive = false
		}
	}
}

// GetCurrentJWTKey возвращает текущий активный ключ подписи JWT
func (m *TokenManager) GetCurrentJWTKey() (string, string, error) {
	m.jwtKeysMutex.RLock()
	defer m.jwtKeysMutex.RUnlock()

	// Если нет ключей, генерируем новый
	if len(m.jwtKeys) == 0 || m.currentJWTKeyID == "" {
		m.jwtKeysMutex.RUnlock()
		_, err := m.generateNewJWTKey()
		if err != nil {
			return "", "", err
		}
		m.jwtKeysMutex.RLock()
	}

	// Ищем текущий ключ
	for _, key := range m.jwtKeys {
		if key.ID == m.currentJWTKeyID && key.IsActive {
			return key.ID, key.Secret, nil
		}
	}

	// Если текущий ключ не найден или не активен, ищем любой активный
	for _, key := range m.jwtKeys {
		if key.IsActive {
			m.currentJWTKeyID = key.ID
			return key.ID, key.Secret, nil
		}
	}

	// Если нет активных ключей, генерируем новый (после разблокировки мьютекса)
	m.jwtKeysMutex.RUnlock()
	_, err := m.generateNewJWTKey()
	if err != nil {
		return "", "", err
	}
	m.jwtKeysMutex.RLock()

	// Находим новый ключ
	for _, key := range m.jwtKeys {
		if key.ID == m.currentJWTKeyID {
			return key.ID, key.Secret, nil
		}
	}

	return "", "", errors.New("не удалось найти или создать активный ключ JWT")
}

// SetMaxRefreshTokensPerUser устанавливает максимальное количество активных сессий для пользователя
func (m *TokenManager) SetMaxRefreshTokensPerUser(limit int) {
	if limit <= 0 {
		limit = DefaultMaxRefreshTokensPerUser
	}
	m.maxRefreshTokensPerUser = limit
	log.Printf("[TokenManager] Установлен лимит активных сессий: %d", limit)
}

// GetMaxRefreshTokensPerUser возвращает текущий лимит активных сессий
func (m *TokenManager) GetMaxRefreshTokensPerUser() int {
	return m.maxRefreshTokensPerUser
}

// InitializeJWTKeys инициализирует ключи подписи JWT при запуске
func (m *TokenManager) InitializeJWTKeys() error {
	// Добавляем ключ по умолчанию из конфигурации jwtService
	// TODO: Получать секрет из конфигурации, а не напрямую из jwtService?
	defaultSecret := "" // Нужно получить секрет из jwtService или конфига
	if m.jwtService != nil {
		// defaultSecret = m.jwtService.GetSecret() // Примерный вызов
		// Пытаемся получить секрет из самого сервиса JWT, если он его хранит (нужен метод GetSecret)
		// В текущей реализации jwtService секрет приватный. Мы можем его либо передать
		// при инициализации TokenManager, либо загрузить из конфигурации.
		// Пока оставим пустым и будем полагаться на ключ из GenerateToken, если Initialize не сработает.
		log.Println("[TokenManager] Не удалось получить секрет по умолчанию из jwtService для инициализации ключей. Используйте конфигурацию или передайте секрет явно.")
	}

	if defaultSecret == "" {
		log.Println("[TokenManager] Предупреждение: Не удалось инициализировать JWT ключи из-за отсутствия секрета по умолчанию.")
		return nil // Не критично, если jwtService сам использует свой секрет
	}

	initialKey := JWTKeyRotation{
		ID:        "initial-key",
		Secret:    defaultSecret,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour), // 90 дней
		IsActive:  true,
	}

	m.jwtKeysMutex.Lock()
	m.jwtKeys = append(m.jwtKeys, initialKey)
	m.currentJWTKeyID = "initial-key"
	m.jwtKeysMutex.Unlock()

	log.Printf("[TokenManager] Успешно сгенерирован и активирован новый JWT ключ ID: %s", "initial-key")

	return nil
}

// CheckKeyRotation проверяет, нужно ли выполнить ротацию ключей JWT
func (m *TokenManager) CheckKeyRotation() bool {
	// Выполняем ротацию ключей раз в месяц
	if time.Since(m.lastKeyRotation) > 30*24*time.Hour {
		log.Printf("[TokenManager] Проверка ротации ключей: пора выполнить ротацию (последняя была %s)", m.lastKeyRotation)
		_, err := m.RotateJWTKeys()
		if err != nil {
			log.Printf("[TokenManager] Ошибка при автоматической ротации ключей: %v", err)
			return false
		}
		m.lastKeyRotation = time.Now()
		return true
	}
	return false
}

// GetActiveJWTKeys возвращает все активные ключи JWT
func (m *TokenManager) GetActiveJWTKeys() []JWTKeyRotation {
	m.jwtKeysMutex.RLock()
	defer m.jwtKeysMutex.RUnlock()

	activeKeys := make([]JWTKeyRotation, 0)
	for _, key := range m.jwtKeys {
		if key.IsActive {
			// Создаем копию без секретного ключа для безопасности
			keyCopy := JWTKeyRotation{
				ID:        key.ID,
				CreatedAt: key.CreatedAt,
				ExpiresAt: key.ExpiresAt,
				IsActive:  key.IsActive,
			}
			activeKeys = append(activeKeys, keyCopy)
		}
	}

	return activeKeys
}

// GetJWTKeySummary возвращает сводку по ключам JWT
func (m *TokenManager) GetJWTKeySummary() map[string]interface{} {
	m.jwtKeysMutex.RLock()
	defer m.jwtKeysMutex.RUnlock()

	activeCount := 0
	inactiveCount := 0
	var oldestKey time.Time
	var newestKey time.Time

	if len(m.jwtKeys) > 0 {
		oldestKey = m.jwtKeys[0].CreatedAt
		newestKey = m.jwtKeys[0].CreatedAt
	}

	for _, key := range m.jwtKeys {
		if key.IsActive {
			activeCount++
		} else {
			inactiveCount++
		}

		if key.CreatedAt.Before(oldestKey) {
			oldestKey = key.CreatedAt
		}
		if key.CreatedAt.After(newestKey) {
			newestKey = key.CreatedAt
		}
	}

	return map[string]interface{}{
		"active_keys":     activeCount,
		"inactive_keys":   inactiveCount,
		"total_keys":      len(m.jwtKeys),
		"current_key_id":  m.currentJWTKeyID,
		"last_rotation":   m.lastKeyRotation,
		"oldest_key_date": oldestKey,
		"newest_key_date": newestKey,
	}
}

// Добавляем хелпер для лимитирования сессий, чтобы избежать дублирования кода
func (m *TokenManager) limitUserSessions(userID uint) error {
	count, err := m.refreshTokenRepo.CountTokensForUser(userID)
	if err != nil {
		return fmt.Errorf("ошибка подсчета токенов: %w", err)
	}

	if count > m.maxRefreshTokensPerUser {
		log.Printf("[TokenManager] Превышен лимит сессий для пользователя ID=%d (%d > %d). Удаление старых.", userID, count, m.maxRefreshTokensPerUser)
		if err := m.refreshTokenRepo.MarkOldestAsExpiredForUser(userID, m.maxRefreshTokensPerUser); err != nil {
			return fmt.Errorf("ошибка маркировки старых токенов: %w", err)
		}
	}
	return nil
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
