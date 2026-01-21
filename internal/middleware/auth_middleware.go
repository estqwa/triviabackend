package middleware

import (
	"net/http"
	"strings"

	"log"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/trivia-api/pkg/auth"
	"github.com/yourusername/trivia-api/pkg/auth/manager"
)

// AuthMiddleware обеспечивает аутентификацию для защищенных маршрутов
type AuthMiddleware struct {
	jwtService   *auth.JWTService
	tokenManager *manager.TokenManager
}

// NewAuthMiddlewareWithManager создает новый middleware с использованием TokenManager
func NewAuthMiddlewareWithManager(jwtService *auth.JWTService, tokenManager *manager.TokenManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtService:   jwtService,
		tokenManager: tokenManager,
	}
}

// RequireAuth проверяет, аутентифицирован ли пользователь
func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string
		var err error

		// Если доступен TokenManager, получаем токен из куки
		if m.tokenManager != nil {
			token, err = m.tokenManager.GetAccessTokenFromCookie(c.Request)
			if err != nil {
				// Если токен в куки не найден, проверяем заголовок для обратной совместимости
				authHeader := c.GetHeader("Authorization")
				if authHeader == "" {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "error_type": "token_missing"})
					c.Abort()
					return
				}

				// Проверяем формат заголовка Bearer {token}
				parts := strings.Split(authHeader, " ")
				if len(parts) != 2 || parts[0] != "Bearer" {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}", "error_type": "token_format"})
					c.Abort()
					return
				}
				token = parts[1]
			}
		} else {
			// Этот блок теперь маловероятен, т.к. TokenManager должен быть всегда
			// но оставляем на всякий случай, если middleware создается без него
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required", "error_type": "token_missing"})
				c.Abort()
				return
			}

			// Проверяем формат заголовка Bearer {token}
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header format must be Bearer {token}", "error_type": "token_format"})
				c.Abort()
				return
			}
			token = parts[1]
		}

		// Проверяем токен
		claims, err := m.jwtService.ParseToken(c, token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token", "error_type": "token_invalid"})
			c.Abort()
			return
		}

		// Устанавливаем ID пользователя в контекст
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)

		// TODO [PRODUCTION]: Реализовать систему ролей вместо hardcoded ID == 1
		// Добавить поле role/is_admin в entity.User и включать его в JWT claims
		if claims.UserID == 1 {
			c.Set("is_admin", true)
		}

		c.Next()
	}
}

// AdminOnly проверяет, является ли пользователь администратором
func (m *AuthMiddleware) AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Проверяем, аутентифицирован ли пользователь
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}

		// Проверяем, является ли пользователь администратором
		isAdmin, exists := c.Get("is_admin")
		if !exists || !isAdmin.(bool) {
			// TODO [PRODUCTION]: Заменить на проверку роли вместо hardcoded ID == 1
			if userID.(uint) != 1 {
				c.JSON(http.StatusForbidden, gin.H{"error": "Admin rights required"})
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// RequireCSRF проверяет наличие и валидность CSRF токена для state-changing методов.
// Реализует Double Submit Cookie с использованием секрета в JWT.
// Должен применяться ПОСЛЕ RequireAuth.
func (m *AuthMiddleware) RequireCSRF() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пропускаем проверку для безопасных методов
		method := c.Request.Method
		if method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions || method == http.MethodTrace {
			c.Next()
			return
		}

		// Проверяем, что TokenManager доступен
		if m.tokenManager == nil {
			log.Printf("[CSRF Middleware] Ошибка: TokenManager не инициализирован.")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "CSRF protection configuration error", "error_type": "internal_server_error"})
			c.Abort()
			return
		}

		// 1. Получаем CSRF токен (хеш) из заголовка X-CSRF-Token
		csrfTokenHeader := c.GetHeader(manager.CSRFHeader)
		if csrfTokenHeader == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF token missing from header", "error_type": "csrf_token_missing"})
			c.Abort()
			return
		}

		// 2. Получаем CSRF секрет из HttpOnly cookie (__Host-csrf-secret)
		csrfSecretCookie, err := m.tokenManager.GetCSRFSecretFromCookie(c.Request)
		if err != nil {
			// Если кука не найдена или ошибка чтения, это проблема
			log.Printf("[CSRF Middleware] Ошибка получения CSRF секрета из cookie: %v", err)
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF secret cookie missing or invalid", "error_type": "csrf_secret_cookie_invalid"})
			c.Abort()
			return
		}
		if csrfSecretCookie == "" {
			// Пустая кука секрета
			log.Println("[CSRF Middleware] Ошибка: Пустое значение CSRF секрета в cookie.")
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF secret cookie value", "error_type": "csrf_secret_cookie_empty"})
			c.Abort()
			return
		}

		// 3. Получаем CSRF секрет из JWT access-токена
		// Сначала получаем сам access токен (из куки или заголовка, как в RequireAuth)
		var accessToken string
		accessToken, err = m.tokenManager.GetAccessTokenFromCookie(c.Request)
		if err != nil {
			authHeader := c.GetHeader("Authorization")
			if authHeader == "" {
				log.Println("[CSRF Middleware] Не найден ни Access Token cookie, ни Authorization header")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication token missing", "error_type": "token_missing"})
				c.Abort()
				return
			}
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				log.Println("[CSRF Middleware] Неверный формат Authorization header")
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format", "error_type": "token_format"})
				c.Abort()
				return
			}
			accessToken = parts[1]
		}

		// Парсим access токен, чтобы получить claims
		claims, err := m.jwtService.ParseToken(c, accessToken)
		if err != nil {
			log.Printf("[CSRF Middleware] Ошибка парсинга Access Token: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired access token", "error_type": "token_invalid"})
			c.Abort()
			return
		}

		// Получаем секрет из клеймов
		csrfSecretJWT := claims.CSRFSecret
		if csrfSecretJWT == "" {
			log.Println("[CSRF Middleware] Ошибка: Отсутствует CSRF секрет в JWT access token.")
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF secret missing in token", "error_type": "csrf_secret_token_missing"})
			c.Abort()
			return
		}

		// 4. Сравниваем секрет из cookie и секрет из JWT
		if csrfSecretCookie != csrfSecretJWT {
			log.Printf("[CSRF Middleware] CSRF secret mismatch for user %d, path %s", claims.UserID, c.Request.URL.Path)
			c.JSON(http.StatusForbidden, gin.H{"error": "CSRF secret mismatch (cookie vs token)", "error_type": "csrf_secret_mismatch"})
			c.Abort()
			return
		}

		// 5. Хешируем секрет (из cookie или JWT, они должны быть одинаковы)
		// Используем публичный метод из пакета manager
		expectedTokenHash := manager.HashCSRFSecret(csrfSecretCookie) // Используем секрет из куки

		// 6. Сравниваем хеш из заголовка с ожидаемым хешом
		if csrfTokenHeader != expectedTokenHash {
			if gin.Mode() == gin.ReleaseMode {
				log.Printf("[CSRF Middleware] Invalid CSRF token for user %d", claims.UserID)
			} else {
				log.Printf("[CSRF Middleware] CSRF token mismatch for user %d, path %s", claims.UserID, c.Request.URL.Path)
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF token (hash mismatch)", "error_type": "csrf_token_invalid"})
			c.Abort()
			return
		}

		// 7. CSRF проверка пройдена
		if gin.Mode() != gin.ReleaseMode {
			log.Printf("[CSRF Middleware] CSRF check passed for user %d, %s %s", claims.UserID, method, c.Request.URL.Path)
		}
		c.Next()
	}
}
