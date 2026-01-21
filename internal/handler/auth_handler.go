package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"github.com/yourusername/trivia-api/internal/service"
	"github.com/yourusername/trivia-api/internal/websocket"
	"github.com/yourusername/trivia-api/pkg/auth/manager"
)

// AuthHandler обрабатывает запросы, связанные с аутентификацией
type AuthHandler struct {
	authService  *service.AuthService
	tokenManager *manager.TokenManager
	wsHub        websocket.HubInterface
}

// NewAuthHandler создает новый обработчик аутентификации
func NewAuthHandler(authService *service.AuthService, tokenManager *manager.TokenManager, wsHub websocket.HubInterface) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		tokenManager: tokenManager,
		wsHub:        wsHub,
	}
}

// Структуры запросов и ответов

// RegisterRequest представляет запрос на регистрацию
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6,max=50"`
}

// LoginRequest представляет запрос на вход
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	DeviceID string `json:"device_id" binding:"omitempty"`
}

// RefreshTokenRequest представляет запрос на обновление токенов
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	DeviceID     string `json:"device_id" binding:"omitempty"`
}

// LogoutRequest представляет запрос на выход
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"omitempty"`
}

// TokenResponse структура для ответа с токенами авторизации
type TokenResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken,omitempty"`
	CSRFToken    string `json:"csrfToken,omitempty"`
	UserID       uint   `json:"userId"`
}

// AuthResponse структура для ответа с пользовательскими данными и токенами
type AuthResponse struct {
	User        *entity.User `json:"user"`
	AccessToken string       `json:"accessToken"`
	TokenType   string       `json:"tokenType"`
	ExpiresIn   int          `json:"expiresIn"`
	// Поле RefreshToken удалено, т.к. теперь используются HttpOnly cookies
}

// SessionInfo представляет информацию о сессии
type SessionInfo struct {
	ID        uint      `json:"id"`
	DeviceID  string    `json:"device_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// ChangePasswordRequest представляет запрос на изменение пароля
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=6"`
}

// ResetPasswordRequest представляет запрос на сброс пароля администратором
type ResetPasswordRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// RevokeSessionRequest представляет запрос на отзыв отдельной сессии
type RevokeSessionRequest struct {
	SessionID uint `json:"session_id" binding:"required"`
}

// Register обрабатывает запрос на регистрацию
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Регистрируем пользователя
	user, err := h.authService.RegisterUser(req.Username, req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[AuthHandler] Пользователь ID=%d (%s) успешно зарегистрирован", user.ID, user.Email)

	// Генерируем токены сразу после регистрации
	tokenResp, err := h.tokenManager.GenerateTokenPair(user.ID, "", c.ClientIP(), c.Request.UserAgent())
	if err != nil {
		h.handleAuthError(c, fmt.Errorf("failed to generate tokens after registration: %w", err))
		return
	}

	// Устанавливаем куки
	// Предполагаем, что RefreshToken извлекается из tokenManager или передан как-то иначе
	// Здесь нам нужно получить сам refresh токен для установки куки
	// Получим последнюю сессию пользователя (немного костыльно, лучше если бы GenerateTokenPair возвращал его)
	if tokenResp.RefreshToken != "" {
		h.tokenManager.SetRefreshTokenCookie(c.Writer, tokenResp.RefreshToken)
	} else {
		log.Printf("[AuthHandler] ОШИБКА: RefreshToken пустой после генерации для пользователя ID=%d", user.ID)
		// Можно вернуть ошибку или продолжить без refresh cookie
	}
	h.tokenManager.SetAccessTokenCookie(c.Writer, tokenResp.AccessToken)
	h.tokenManager.SetCSRFSecretCookie(c.Writer, tokenResp.CSRFSecret)

	// Возвращаем только необходимые данные в JSON
	c.JSON(http.StatusCreated, gin.H{
		"user":        user,                  // Возвращаем информацию о пользователе
		"accessToken": tokenResp.AccessToken, // Access токен для информации (уже в куке)
		"csrfToken":   tokenResp.CSRFToken,   // CSRF токен (хеш) для последующих запросов
		"userId":      tokenResp.UserID,
		"expiresIn":   tokenResp.ExpiresIn,
		"tokenType":   "Bearer",
	})
}

// Login обрабатывает запрос на вход
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data", "details": err.Error()})
		return
	}

	// Используем IP и UserAgent из запроса
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()

	// Используем DeviceID из запроса, если предоставлен
	deviceID := req.DeviceID
	if deviceID == "" {
		deviceID = userAgent // Простой вариант
	}

	// Используем обновленный AuthService.LoginUser
	tokenResp, err := h.authService.LoginUser(req.Email, req.Password, deviceID, ipAddress, userAgent)
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	// Устанавливаем куки
	if tokenResp.RefreshToken != "" {
		h.tokenManager.SetRefreshTokenCookie(c.Writer, tokenResp.RefreshToken)
	} else {
		log.Printf("[AuthHandler] ОШИБКА: RefreshToken пустой после генерации для пользователя ID=%d", tokenResp.UserID)
		h.handleAuthError(c, fmt.Errorf("failed to retrieve refresh token after login"))
		return
	}
	h.tokenManager.SetAccessTokenCookie(c.Writer, tokenResp.AccessToken)
	// Устанавливаем CSRF Secret Cookie
	h.tokenManager.SetCSRFSecretCookie(c.Writer, tokenResp.CSRFSecret)

	// Получаем информацию о пользователе
	user, userErr := h.authService.GetUserByID(tokenResp.UserID)
	if userErr != nil {
		log.Printf("[AuthHandler] Ошибка получения пользователя ID=%d после логина: %v", tokenResp.UserID, userErr)
	}

	// Формируем ответ
	c.JSON(http.StatusOK, gin.H{
		"user":        user,
		"accessToken": tokenResp.AccessToken,
		"csrfToken":   tokenResp.CSRFToken, // Возвращаем хеш
		"userId":      tokenResp.UserID,
		"expiresIn":   tokenResp.ExpiresIn,
		"tokenType":   "Bearer",
	})
}

// RefreshToken обновляет access токен с помощью refresh токена
// Обновлено: использует TokenManager, получает refresh из куки, csrf из заголовка
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// Получаем refresh токен из HttpOnly куки
	refreshToken, err := h.tokenManager.GetRefreshTokenFromCookie(c.Request)
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	// Получаем CSRF токен (хеш) из заголовка X-CSRF-Token
	csrfTokenHeader := c.GetHeader(manager.CSRFHeader)
	if csrfTokenHeader == "" {
		h.handleAuthError(c, manager.NewTokenError(manager.InvalidCSRFToken, "CSRF token missing from header", nil))
		return
	}

	// Используем IP и UserAgent из запроса
	ipAddress := c.ClientIP()
	userAgent := c.Request.UserAgent()
	deviceID := "" // Пока используем пустой

	// Используем обновленный AuthService.RefreshTokens
	// ПРИМЕЧАНИЕ: csrfTokenHeader здесь передается, но в новой логике он не используется внутри RefreshTokens
	// Проверка CSRF должна выполняться в middleware ДО вызова этого хендлера
	tokenResp, err := h.authService.RefreshTokens(refreshToken, csrfTokenHeader, deviceID, ipAddress, userAgent)
	if err != nil {
		h.handleAuthError(c, err)
		return
	}

	// Устанавливаем новую куку для Access Token
	h.tokenManager.SetAccessTokenCookie(c.Writer, tokenResp.AccessToken)
	// Устанавливаем новую куку для Refresh Token
	if tokenResp.RefreshToken != "" {
		h.tokenManager.SetRefreshTokenCookie(c.Writer, tokenResp.RefreshToken)
	} else {
		log.Printf("[AuthHandler] ОШИБКА: RefreshToken пустой после генерации для пользователя ID=%d", tokenResp.UserID)
		h.handleAuthError(c, fmt.Errorf("failed to retrieve new refresh token after refresh"))
		return
	}
	// Устанавливаем новую куку для CSRF Secret
	h.tokenManager.SetCSRFSecretCookie(c.Writer, tokenResp.CSRFSecret)

	// Формируем ответ
	c.JSON(http.StatusOK, gin.H{
		"accessToken": tokenResp.AccessToken,
		"csrfToken":   tokenResp.CSRFToken, // Возвращаем новый хеш
		"userId":      tokenResp.UserID,
		"expiresIn":   tokenResp.ExpiresIn,
		"tokenType":   "Bearer",
	})
}

// GetMe возвращает информацию о текущем пользователе
func (h *AuthHandler) GetMe(c *gin.Context) {
	// Получаем ID пользователя из контекста (установлен middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	user, err := h.authService.GetUserByID(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              user.ID,
		"username":        user.Username,
		"email":           user.Email,
		"profile_picture": user.ProfilePicture,
		"games_played":    user.GamesPlayed,
		"total_score":     user.TotalScore,
		"highest_score":   user.HighestScore,
	})
}

// UpdateProfileRequest представляет запрос на обновление профиля
type UpdateProfileRequest struct {
	Username       string `json:"username" binding:"omitempty,min=3,max=50"`
	ProfilePicture string `json:"profile_picture" binding:"omitempty,max=255"`
}

// UpdateProfile обновляет профиль пользователя
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID := c.MustGet("user_id").(uint)

	var req UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.authService.UpdateUserProfile(userID, req.Username, req.ProfilePicture); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Profile updated successfully"})
}

// Logout обрабатывает выход пользователя.
// Он извлекает refresh token из HttpOnly cookie, инвалидирует его
// и очищает cookie на стороне клиента.
func (h *AuthHandler) Logout(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Println("[AuthHandler] Logout: Refresh token cookie not found.")
			h.tokenManager.ClearRefreshTokenCookie(c.Writer)
			h.tokenManager.ClearAccessTokenCookie(c.Writer)
			h.tokenManager.ClearCSRFSecretCookie(c.Writer) // Очищаем куку секрета
			c.JSON(http.StatusOK, gin.H{"message": "Already logged out or session expired"})
			return
		}
		log.Printf("[AuthHandler] Logout: Error reading refresh token cookie: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not process logout due to cookie error"})
		return
	}

	if refreshToken == "" {
		log.Println("[AuthHandler] Logout: Refresh token cookie was found but empty.")
		h.tokenManager.ClearRefreshTokenCookie(c.Writer)
		h.tokenManager.ClearAccessTokenCookie(c.Writer)
		h.tokenManager.ClearCSRFSecretCookie(c.Writer) // Очищаем куку секрета
		c.JSON(http.StatusOK, gin.H{"message": "Invalid session state"})
		return
	}

	err = h.authService.LogoutUser(refreshToken)
	if err != nil {
		log.Printf("[AuthHandler] Logout: Failed to invalidate refresh token: %v", err)
	}

	h.tokenManager.ClearRefreshTokenCookie(c.Writer)
	h.tokenManager.ClearAccessTokenCookie(c.Writer)
	h.tokenManager.ClearCSRFSecretCookie(c.Writer) // Очищаем куку секрета

	log.Println("[AuthHandler] Logout: User logged out successfully.")
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}

// GetProfile обрабатывает запрос на получение профиля пользователя

// LogoutAllDevices обрабатывает запрос на выход со всех устройств
func (h *AuthHandler) LogoutAllDevices(c *gin.Context) {
	userID := c.MustGet("user_id").(uint)

	if err := h.authService.RevokeAllUserSessions(userID, "user_logout_all"); err != nil {
		log.Printf("[AuthHandler] Ошибка при выходе из всех сессий: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Не удалось выйти из всех сессий", "error_type": "internal_error"})
		return
	}

	if h.wsHub != nil {
		logoutEvent := map[string]interface{}{
			"event":     "logout_all_devices",
			"user_id":   userID,
			"timestamp": time.Now().Format(time.RFC3339),
			"reason":    "user_logout_all",
		}
		if err := h.sendWebSocketNotification(userID, logoutEvent); err != nil {
			log.Printf("[AuthHandler] Ошибка отправки уведомления через WebSocket: %v", err)
		}
	}

	h.tokenManager.ClearRefreshTokenCookie(c.Writer)
	h.tokenManager.ClearAccessTokenCookie(c.Writer)
	h.tokenManager.ClearCSRFSecretCookie(c.Writer) // Очищаем куку секрета

	c.JSON(http.StatusOK, gin.H{"message": "Выход из всех сессий выполнен успешно"})
}

// GetActiveSessions возвращает список активных сессий пользователя
func (h *AuthHandler) GetActiveSessions(c *gin.Context) {
	// Получаем ID пользователя из контекста
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	// Получаем список сессий
	sessions, err := h.authService.GetUserActiveSessions(userID.(uint))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get active sessions"})
		return
	}

	// Формируем ответ
	var result []SessionInfo
	for _, session := range sessions {
		result = append(result, SessionInfo{
			ID:        session.ID,
			DeviceID:  session.DeviceID,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"sessions": result,
		"count":    len(result),
	})
}

// ResetAuth обрабатывает запрос на сброс состояния аутентификации
// Используется для исправления проблем со старыми аккаунтами
func (h *AuthHandler) ResetAuth(c *gin.Context) {
	// Этот метод доступен только для администраторов
	// Проверяем, что пользователь - администратор
	isAdmin, exists := c.Get("is_admin")
	if !exists || !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
		return
	}

	// Получаем ID пользователя из запроса
	type ResetRequest struct {
		UserID uint `json:"user_id" binding:"required"`
	}

	var req ResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[AuthHandler] Администратор ID=%d сбрасывает инвалидацию токенов для пользователя ID=%d", c.MustGet("user_id").(uint), req.UserID)

	// Вызываем сервис для сброса статуса инвалидации в репозитории invalid_tokens
	h.authService.ResetUserTokenInvalidation(req.UserID)

	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Token invalidation status reset for user %d", req.UserID)})
}

// CheckRefreshToken проверяет валидность refresh-токена без его обновления
func (h *AuthHandler) CheckRefreshToken(c *gin.Context) {
	// Получаем refresh токен из cookie
	var refreshToken string
	var err error

	if h.tokenManager != nil {
		refreshToken, err = h.tokenManager.GetRefreshTokenFromCookie(c.Request)
		if err != nil {
			// Пробуем получить из тела запроса для обратной совместимости
			var req struct {
				RefreshToken string `json:"refresh_token" binding:"required"`
			}
			if c.ShouldBindJSON(&req) == nil {
				refreshToken = req.RefreshToken
			} else {
				log.Printf("[AuthHandler] Ошибка валидации данных при проверке refresh-токена: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error":      "Требуется refresh-токен",
					"error_type": "token_invalid",
				})
				return
			}
		}
	} else {
		// Для обратной совместимости
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[AuthHandler] Ошибка валидации данных при проверке refresh-токена: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "Требуется refresh-токен",
				"error_type": "token_invalid",
			})
			return
		}
		refreshToken = req.RefreshToken
	}

	// Проверяем токен через сервис
	isValid, err := h.authService.CheckRefreshToken(refreshToken)
	if err != nil {
		log.Printf("[AuthHandler] Ошибка при проверке refresh-токена: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":      "Ошибка проверки токена",
			"error_type": "server_error",
		})
		return
	}

	// Возвращаем результат проверки
	c.JSON(http.StatusOK, gin.H{
		"valid": isValid,
	})
}

// GetTokenInfo возвращает информацию о сроке действия токенов
func (h *AuthHandler) GetTokenInfo(c *gin.Context) {
	// Получаем refresh токен из cookie
	var refreshToken string
	var err error

	if h.tokenManager != nil {
		refreshToken, err = h.tokenManager.GetRefreshTokenFromCookie(c.Request)
		if err != nil {
			// Пробуем получить из тела запроса для обратной совместимости
			var req struct {
				RefreshToken string `json:"refresh_token" binding:"required"`
			}
			if c.ShouldBindJSON(&req) == nil {
				refreshToken = req.RefreshToken
			} else {
				log.Printf("[AuthHandler] Ошибка валидации данных при получении информации о токене: %v", err)
				c.JSON(http.StatusBadRequest, gin.H{
					"error":      "Требуется refresh-токен",
					"error_type": "token_invalid",
				})
				return
			}
		}
	} else {
		// Для обратной совместимости
		var req struct {
			RefreshToken string `json:"refresh_token" binding:"required"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			log.Printf("[AuthHandler] Ошибка валидации данных при получении информации о токене: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{
				"error":      "Требуется refresh-токен",
				"error_type": "token_invalid",
			})
			return
		}
		refreshToken = req.RefreshToken
	}

	// Получаем информацию о токене
	var tokenInfo interface{}
	if h.tokenManager != nil {
		// Используем новый TokenManager
		info, err := h.tokenManager.GetTokenInfo(refreshToken)
		if err != nil {
			log.Printf("[AuthHandler] Ошибка при получении информации о токене: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "Ошибка получения информации о токене",
				"error_type": "server_error",
			})
			return
		}
		tokenInfo = info
	} else {
		// Используем старый сервис
		info, err := h.authService.GetTokenInfo(refreshToken)
		if err != nil {
			log.Printf("[AuthHandler] Ошибка при получении информации о токене: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":      "Ошибка получения информации о токене",
				"error_type": "server_error",
			})
			return
		}

		// Вычисляем время до истечения токенов
		now := time.Now()
		tokenInfo = gin.H{
			"access_token_expires":    info.AccessTokenExpires,
			"refresh_token_expires":   info.RefreshTokenExpires,
			"access_token_valid_for":  info.AccessTokenExpires.Sub(now).Seconds(),
			"refresh_token_valid_for": info.RefreshTokenExpires.Sub(now).Seconds(),
		}
	}

	// Возвращаем информацию о сроке действия токенов
	c.JSON(http.StatusOK, tokenInfo)
}

// DebugToken анализирует JWT токен без проверки подписи
// для диагностических целей
func (h *AuthHandler) DebugToken(c *gin.Context) {
	// Этот метод доступен только для администраторов
	isAdmin, exists := c.Get("is_admin")
	if !exists || !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Только для администраторов"})
		return
	}

	var req struct {
		Token string `json:"token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[AuthHandler] Ошибка валидации данных при отладке токена: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Требуется токен"})
		return
	}

	// Получаем отладочную информацию о токене
	result := h.authService.DebugToken(req.Token)

	// Возвращаем информацию о токене
	c.JSON(http.StatusOK, result)
}

// ChangePassword обрабатывает запрос на изменение пароля пользователя
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID := c.MustGet("user_id").(uint)

	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("[ChangePassword] Ошибка валидации запроса: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[ChangePassword] Запрос на изменение пароля для пользователя ID=%d", userID)

	if err := h.authService.ChangePassword(userID, req.OldPassword, req.NewPassword); err != nil {
		log.Printf("[ChangePassword] Ошибка при изменении пароля: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	log.Printf("[ChangePassword] Пароль успешно изменен для пользователя ID=%d", userID)
	c.JSON(http.StatusOK, gin.H{"message": "password changed successfully"})
}

// AdminResetPassword обрабатывает запрос на сброс пароля администратором
func (h *AuthHandler) AdminResetPassword(c *gin.Context) {
	// Проверяем, что пользователь - администратор
	isAdmin, exists := c.Get("is_admin")
	if !exists || !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Только для администраторов"})
		return
	}

	var req ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Находим пользователя по email
	user, err := h.authService.GetUserByEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Пользователь не найден"})
		return
	}

	// Обновляем пароль без проверки старого пароля
	if err := h.authService.AdminResetPassword(user.ID, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при сбросе пароля"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Пароль успешно сброшен",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
	})
}

// RevokeSession обрабатывает запрос на отзыв отдельной сессии
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	userID := c.MustGet("user_id").(uint) // ID пользователя, который делает запрос

	var req RevokeSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные запроса", "error_type": "invalid_request"})
		return
	}

	// Проверяем, что сессия принадлежит пользователю
	token, err := h.authService.GetRefreshTokenByID(req.SessionID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Сессия не найдена", "error_type": "session_not_found"})
		return
	}

	if token.UserID != userID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Доступ запрещен", "error_type": "forbidden"})
		return
	}

	// Получаем причину
	reason := c.Query("reason")
	if reason == "" {
		reason = "user_revoked"
	}

	// Отзываем сессию
	err = h.authService.RevokeSessionByID(req.SessionID, reason)
	if err != nil {
		log.Printf("[AuthHandler] Ошибка при отзыве сессии: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при отзыве сессии", "error_type": "internal_error"})
		return
	}

	// Отправляем уведомление через WebSocket о завершении сессии
	if h.wsHub != nil {
		// Отправляем уведомление о завершении сессии
		sessionEvent := map[string]interface{}{
			"event":      "session_revoked",
			"session_id": req.SessionID,
			"timestamp":  time.Now().Format(time.RFC3339),
			"reason":     reason,
			"user_id":    token.UserID, // Добавляем user_id для лучшей идентификации
		}

		// Отправляем уведомление пользователю
		if err := h.sendWebSocketNotification(token.UserID, sessionEvent); err != nil {
			log.Printf("[AuthHandler] Ошибка отправки уведомления через WebSocket: %v", err)
			// Обработка ошибки не критична для основного функционала
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Сессия успешно завершена", "session_id": req.SessionID})
}

// GetSessionLimit возвращает текущий лимит сессий для пользователя
func (h *AuthHandler) GetSessionLimit(c *gin.Context) {
	// Получаем ID пользователя из контекста
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Пользователь не аутентифицирован", "error_type": "unauthorized"})
		return
	}

	// Получаем лимит сессий из TokenManager
	var limit int
	if h.tokenManager != nil {
		limit = h.tokenManager.GetMaxRefreshTokensPerUser()
	} else {
		// Если TokenManager не инициализирован, используем значение по умолчанию
		limit = 10
	}

	// Получаем текущее количество активных сессий
	sessions, err := h.authService.GetUserActiveSessions(userID.(uint))
	if err != nil {
		log.Printf("[AuthHandler] Ошибка при получении активных сессий: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении активных сессий", "error_type": "internal_error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"limit":     limit,
		"current":   len(sessions),
		"remaining": limit - len(sessions),
	})
}

// UpdateSessionLimit обновляет лимит сессий для пользователя (админ-функция)
// Больше не поддерживается через API. Управляется через конфигурационный файл.
func (h *AuthHandler) UpdateSessionLimit(c *gin.Context) {
	// Проверяем права администратора
	isAdmin, exists := c.Get("is_admin")
	if !exists || !isAdmin.(bool) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Требуются права администратора", "error_type": "forbidden"})
		return
	}

	log.Printf("[AuthHandler] Попытка вызова UpdateSessionLimit администратором ID=%d. Этот функционал управляется конфигурацией.", c.MustGet("user_id").(uint))
	c.JSON(http.StatusNotImplemented, gin.H{
		"message":    "Обновление лимита сессий через API больше не поддерживается. Этот параметр управляется конфигурационным файлом.",
		"error_type": "not_implemented",
	})
}

// GenerateWsTicket генерирует краткоживущий токен для WebSocket подключения
func (h *AuthHandler) GenerateWsTicket(c *gin.Context) {
	// Получаем ID пользователя из контекста (установлен middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "error_type": "token_missing"})
		return
	}

	// Получаем email пользователя из контекста
	email, emailExists := c.Get("email")
	if !emailExists {
		// Если email нет в контексте, получаем из БД
		user, err := h.authService.GetUserByID(userID.(uint))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch user data"})
			return
		}
		email = user.Email
	}

	// Генерируем WS-тикет через JWTService
	ticket, err := h.authService.GenerateWsTicket(userID.(uint), email.(string))
	if err != nil {
		log.Printf("[AuthHandler] Ошибка генерации WS-тикета: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate WebSocket ticket"})
		return
	}

	// Возвращаем тикет клиенту
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": gin.H{
			"ticket": ticket,
		},
	})
}

// GetCSRFToken возвращает хеш CSRF-токена, извлекая секрет из HttpOnly cookie
// Этот эндпоинт должен быть защищен RequireAuth
func (h *AuthHandler) GetCSRFToken(c *gin.Context) {
	// Получаем ID пользователя из контекста, чтобы убедиться, что пользователь аутентифицирован
	userID, exists := c.Get("user_id")
	if !exists {
		// Эта ситуация не должна возникать, если используется RequireAuth
		log.Printf("[AuthHandler] GetCSRFToken: User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "error_type": "context_missing_user"})
		return
	}

	// Получаем CSRF секрет из cookie с помощью TokenManager
	csrfSecretCookie, err := h.tokenManager.GetCSRFSecretFromCookie(c.Request)
	if err != nil {
		log.Printf("[AuthHandler] GetCSRFToken: Ошибка получения CSRF секрета из cookie для пользователя ID=%v: %v", userID, err)
		// Отправляем ошибку, указывающую на проблему с получением токена
		c.JSON(http.StatusForbidden, gin.H{"error": "CSRF secret cookie missing or invalid", "error_type": "csrf_secret_cookie_error"})
		return
	}
	if csrfSecretCookie == "" {
		log.Printf("[AuthHandler] GetCSRFToken: Пустое значение CSRF секрета в cookie для пользователя ID=%v", userID)
		c.JSON(http.StatusForbidden, gin.H{"error": "Invalid CSRF secret cookie value", "error_type": "csrf_secret_cookie_empty"})
		return
	}

	// Хешируем секрет с помощью публичной функции из TokenManager
	csrfTokenHash := manager.HashCSRFSecret(csrfSecretCookie)

	// Возвращаем хеш токена
	c.JSON(http.StatusOK, gin.H{"csrf_token": csrfTokenHash})
}

// Вспомогательные функции

// Вспомогательные методы для проверки CSRF токена и обработки ошибок

// handleAuthError обрабатывает ошибки аутентификации и возвращает соответствующие HTTP-ответы
func (h *AuthHandler) handleAuthError(c *gin.Context, err error) {
	var tokenErr *manager.TokenError
	log.Printf("[AuthHandler] Auth Error: %v", err) // Логируем полную ошибку для отладки

	if errors.As(err, &tokenErr) {
		switch tokenErr.Type {
		case manager.ExpiredRefreshToken, manager.ExpiredAccessToken:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Сессия истекла", "error_type": "token_expired"})
		case manager.InvalidRefreshToken, manager.InvalidAccessToken:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Недействительный токен", "error_type": "token_invalid"})
		case manager.InvalidCSRFToken:
			c.JSON(http.StatusForbidden, gin.H{"error": "Недействительный CSRF токен", "error_type": "csrf_mismatch"})
		case manager.UserNotFound:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные", "error_type": "invalid_credentials"})
		case manager.TokenGenerationFailed:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки запроса", "error_type": "token_generation_failed"})
		case manager.TooManySessions:
			c.JSON(http.StatusConflict, gin.H{"error": "Превышен лимит активных сессий", "error_type": "too_many_sessions"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Внутренняя ошибка сервера", "error_type": "internal_server_error"})
		}
	} else if errors.Is(err, apperrors.ErrUnauthorized) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Ошибка аутентификации или неверные данные", "error_type": "unauthorized"})
	} else if errors.Is(err, apperrors.ErrForbidden) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Доступ запрещен", "error_type": "forbidden"})
	} else if errors.Is(err, apperrors.ErrNotFound) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Запрашиваемый ресурс не найден", "error_type": "not_found"})
	} else if errors.Is(err, apperrors.ErrConflict) {
		c.JSON(http.StatusConflict, gin.H{"error": "Конфликт данных", "error_type": "conflict"})
	} else if errors.Is(err, apperrors.ErrValidation) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка валидации данных", "error_type": "validation_error"})
	} else if errors.Is(err, apperrors.ErrExpiredToken) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен истек", "error_type": "token_expired"})
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Внутренняя ошибка сервера", "error_type": "internal_server_error"})
	}
}

// sendWebSocketNotification отправляет уведомление через WebSocket
func (h *AuthHandler) sendWebSocketNotification(userID uint, event map[string]interface{}) error {
	if h.wsHub == nil {
		return nil // WebSocket отключен
	}
	userIDStr := fmt.Sprintf("%d", userID)
	err := h.wsHub.SendJSONToUser(userIDStr, event)
	if err != nil {
		log.Printf("[AuthHandler] Ошибка отправки уведомления через WebSocket: %v", err)
		return err
	}
	return nil
}
