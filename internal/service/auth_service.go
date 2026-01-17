package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/domain/repository"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"github.com/yourusername/trivia-api/pkg/auth"
	"github.com/yourusername/trivia-api/pkg/auth/manager"
)

// AuthService предоставляет методы для работы с аутентификацией и пользователями
type AuthService struct {
	userRepo   repository.UserRepository
	jwtService *auth.JWTService // Нужен для ParseToken и Invalidate
	// tokenService     *auth.TokenService             // УДАЛЕНО
	tokenManager     *manager.TokenManager             // Теперь основная зависимость для токенов
	refreshTokenRepo repository.RefreshTokenRepository // Оставляем для прямого доступа, если нужно
	invalidTokenRepo repository.InvalidTokenRepository // Добавляем репозиторий инвалидных токенов
}

// NewAuthService создает новый сервис аутентификации и возвращает ошибку при проблемах
func NewAuthService(
	userRepo repository.UserRepository,
	jwtService *auth.JWTService,
	// tokenService *auth.TokenService, // УДАЛЕНО
	tokenManager *manager.TokenManager, // ПРИНИМАЕМ TokenManager
	refreshTokenRepo repository.RefreshTokenRepository,
	invalidTokenRepo repository.InvalidTokenRepository, // ПРИНИМАЕМ InvalidTokenRepo
) (*AuthService, error) { // Изменена сигнатура
	if userRepo == nil {
		// log.Fatal("UserRepository is required for AuthService")
		return nil, fmt.Errorf("UserRepository is required for AuthService") // Возвращаем ошибку
	}
	if jwtService == nil {
		// log.Fatal("JWTService is required for AuthService")
		return nil, fmt.Errorf("JWTService is required for AuthService") // Возвращаем ошибку
	}
	if tokenManager == nil { // ПРОВЕРЯЕМ TokenManager
		// log.Fatal("TokenManager is required for AuthService")
		return nil, fmt.Errorf("TokenManager is required for AuthService") // Возвращаем ошибку
	}
	if refreshTokenRepo == nil {
		// log.Fatal("RefreshTokenRepository is required for AuthService")
		return nil, fmt.Errorf("RefreshTokenRepository is required for AuthService") // Возвращаем ошибку
	}
	if invalidTokenRepo == nil {
		// log.Fatal("InvalidTokenRepository is required for AuthService")
		return nil, fmt.Errorf("InvalidTokenRepository is required for AuthService") // Возвращаем ошибку
	}

	return &AuthService{
		userRepo:   userRepo,
		jwtService: jwtService,
		// tokenService:     tokenService, // УДАЛЕНО
		tokenManager:     tokenManager, // ИСПОЛЬЗУЕМ TokenManager
		refreshTokenRepo: refreshTokenRepo,
		invalidTokenRepo: invalidTokenRepo,
	}, nil // Возвращаем сервис и nil ошибку
}

// RegisterUser регистрирует нового пользователя
func (s *AuthService) RegisterUser(username, email, password string) (*entity.User, error) {
	// Проверяем, существует ли пользователь с таким email
	_, err := s.userRepo.GetByEmail(email)
	if err == nil {
		// Используем стандартную ошибку конфликта
		return nil, fmt.Errorf("%w: user with this email already exists", apperrors.ErrConflict)
	}
	if !errors.Is(err, apperrors.ErrNotFound) {
		return nil, fmt.Errorf("failed to check email existence: %w", err)
	}

	// Проверяем, существует ли пользователь с таким username
	_, err = s.userRepo.GetByUsername(username)
	if err == nil {
		// Используем стандартную ошибку конфликта
		return nil, fmt.Errorf("%w: user with this username already exists", apperrors.ErrConflict)
	}
	if !errors.Is(err, apperrors.ErrNotFound) {
		return nil, fmt.Errorf("failed to check username existence: %w", err)
	}

	// Хеширование пароля убрано отсюда.
	// Пароль будет автоматически хеширован хуком BeforeSave в entity.User
	// при вызове userRepo.Create.
	user := &entity.User{
		Username: username,
		Email:    email,
		Password: password, // Передаем пароль как есть
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return user, nil
}

// AuthResponse содержит данные для ответа на запрос авторизации
type AuthResponse struct {
	User         *entity.User `json:"user"`
	AccessToken  string       `json:"access_token"`
	RefreshToken string       `json:"refresh_token"`
}

// LoginUser аутентифицирует пользователя и возвращает пару токенов
// Обновлено для использования TokenManager
func (s *AuthService) LoginUser(email, password, deviceID, ipAddress, userAgent string) (*manager.TokenResponse, error) {
	user, err := s.AuthenticateUser(email, password)
	if err != nil {
		// Ошибка уже залогирована в AuthenticateUser
		// Пробрасываем ошибку (вероятно, apperrors.ErrUnauthorized)
		return nil, err
	}

	// Используем TokenManager для генерации токенов
	tokenResp, err := s.tokenManager.GenerateTokenPair(user.ID, deviceID, ipAddress, userAgent)
	if err != nil {
		log.Printf("[AuthService] Ошибка генерации токенов для пользователя ID=%d: %v", user.ID, err)
		return nil, fmt.Errorf("ошибка генерации токенов")
	}

	// Сброс инвалидации JWT для пользователя при успешном входе
	// Создаем контекст для вызова
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.jwtService.ResetInvalidationForUser(ctx, user.ID)

	log.Printf("[AuthService] Пользователь ID=%d (%s) успешно вошел в систему", user.ID, user.Email)
	return tokenResp, nil
}

// RefreshTokens обновляет пару токенов, используя refresh токен
// Обновлено для использования TokenManager
func (s *AuthService) RefreshTokens(refreshToken, csrfToken, deviceID, ipAddress, userAgent string) (*manager.TokenResponse, error) {
	// Используем TokenManager для обновления токенов
	tokenResp, err := s.tokenManager.RefreshTokens(refreshToken, csrfToken, deviceID, ipAddress, userAgent)
	if err != nil {
		var tokenErr *manager.TokenError
		if errors.As(err, &tokenErr) {
			log.Printf("[AuthService] Ошибка обновления токенов: %s - %s", tokenErr.Type, tokenErr.Message)
			// Пробрасываем ошибку TokenManager
			return nil, err // Возвращаем исходную ошибку TokenError
		} else {
			log.Printf("[AuthService] Неизвестная ошибка обновления токенов: %v", err)
			return nil, fmt.Errorf("внутренняя ошибка сервера при обновлении токенов: %w", err)
		}
	}

	log.Printf("[AuthService] Токены успешно обновлены для пользователя ID=%d", tokenResp.UserID)
	return tokenResp, nil
}

// GetUserByID возвращает пользователя по ID
func (s *AuthService) GetUserByID(userID uint) (*entity.User, error) {
	return s.userRepo.GetByID(userID)
}

// UpdateUserProfile обновляет профиль пользователя
func (s *AuthService) UpdateUserProfile(userID uint, username, profilePicture string) error {
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// Если имя пользователя изменилось, проверяем, что оно уникально
	if username != user.Username {
		existingUser, _ := s.userRepo.GetByUsername(username)
		if existingUser != nil {
			return fmt.Errorf("%w: username '%s' already taken", apperrors.ErrConflict, username)
		}
	}

	// Используем безопасный метод обновления профиля без изменения пароля
	updates := map[string]interface{}{
		"username":        username,
		"profile_picture": profilePicture,
	}

	return s.userRepo.UpdateProfile(userID, updates)
}

// ChangePassword изменяет пароль пользователя и инвалидирует все токены
func (s *AuthService) ChangePassword(userID uint, oldPassword, newPassword string) error {
	// Получаем пользователя для проверки старого пароля
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return err
	}

	// Проверяем, что старый пароль верный
	if !user.CheckPassword(oldPassword) {
		return fmt.Errorf("%w: incorrect old password", apperrors.ErrUnauthorized)
	}

	// Обновляем пароль с использованием безопасного метода
	// UserRepo.UpdatePassword выполняет хеширование и использует прямой SQL-запрос
	// для обхода хука BeforeSave и предотвращения двойного хеширования
	if err := s.userRepo.UpdatePassword(userID, newPassword); err != nil {
		return err
	}

	// Инвалидируем все токены пользователя
	return s.LogoutAllDevices(userID)
}

// LogoutUser отзывает указанный refresh токен
// Обновлено для использования TokenManager
func (s *AuthService) LogoutUser(refreshToken string) error {
	// Используем TokenManager для отзыва refresh токена
	err := s.tokenManager.RevokeRefreshToken(refreshToken)
	if err != nil {
		log.Printf("[AuthService] Ошибка отзыва refresh токена: %v", err)
		// Можно не возвращать ошибку клиенту, если токен уже недействителен
		var tokenErr *manager.TokenError
		if errors.As(err, &tokenErr) && tokenErr.Type == manager.InvalidRefreshToken {
			return nil // Токен уже недействителен, считаем логаут успешным
		}
		return fmt.Errorf("ошибка при выходе из системы: %w", err)
	}

	log.Printf("[AuthService] Refresh токен успешно отозван")
	return nil
}

// LogoutAllDevices отзывает все токены пользователя
// Обновлено для использования TokenManager и jwtService напрямую
func (s *AuthService) LogoutAllDevices(userID uint) error {
	// Используем TokenManager для отзыва всех refresh токенов
	err := s.tokenManager.RevokeAllUserTokens(userID)
	if err != nil {
		log.Printf("[AuthService] Ошибка при отзыве всех refresh токенов пользователя ID=%d: %v", userID, err)
		// Продолжаем, чтобы попытаться инвалидировать JWT
	}

	// Дополнительно инвалидируем текущие JWT токены через jwtService
	// Создаем контекст для вызова
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if jwtErr := s.jwtService.InvalidateTokensForUser(ctx, userID); jwtErr != nil {
		log.Printf("[AuthService] Ошибка при инвалидации JWT токенов пользователя ID=%d: %v", userID, jwtErr)
		// Если ошибка была и с refresh токенами, возвращаем ее
		if err != nil {
			return fmt.Errorf("ошибка при выходе со всех устройств (refresh): %w", err)
		}
		return fmt.Errorf("ошибка при выходе со всех устройств (jwt): %w", jwtErr)
	}

	log.Printf("[AuthService] Все сессии для пользователя ID=%d завершены", userID)
	return nil
}

// ResetUserTokenInvalidation сбрасывает флаг инвалидации для пользователя
// Использует jwtService и InvalidTokenRepository напрямую
func (s *AuthService) ResetUserTokenInvalidation(userID uint) {
	// Создаем контекст для вызова
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Сброс в jwtService (in-memory)
	s.jwtService.ResetInvalidationForUser(ctx, userID)

	// Удаление записи из БД
	if err := s.invalidTokenRepo.RemoveInvalidToken(ctx, userID); err != nil {
		log.Printf("[AuthService] Ошибка при удалении записи инвалидации из БД для пользователя ID=%d: %v", userID, err)
	}
	log.Printf("[AuthService] Сброшена инвалидация токенов для пользователя ID=%d", userID)
}

// GetUserActiveSessions возвращает активные сессии пользователя
// Обновлено для использования TokenManager
func (s *AuthService) GetUserActiveSessions(userID uint) ([]entity.RefreshToken, error) {
	sessions, err := s.tokenManager.GetUserActiveSessions(userID)
	if err != nil {
		log.Printf("[AuthService] Ошибка получения активных сессий для пользователя ID=%d: %v", userID, err)
		return nil, fmt.Errorf("не удалось получить список сессий")
	}
	return sessions, nil
}

// CheckRefreshToken проверяет действительность refresh токена
// Обновлено: Логика проверки теперь полностью в TokenManager, этот метод можно удалить или сделать прокси
func (s *AuthService) CheckRefreshToken(refreshToken string) (bool, error) {
	// Проксируем вызов к TokenManager
	// return s.tokenManager.CheckRefreshToken(refreshToken) // У TokenManager нет такого публичного метода
	// Вместо этого можно использовать GetTokenInfo или RefreshTokens с проверкой ошибки
	_, err := s.tokenManager.GetTokenInfo(refreshToken)
	if err != nil {
		var tokenErr *manager.TokenError
		if errors.As(err, &tokenErr) && (tokenErr.Type == manager.InvalidRefreshToken || tokenErr.Type == manager.ExpiredRefreshToken) {
			return false, nil // Токен недействителен или истек
		}
		return false, err // Другая ошибка
	}
	return true, nil // Токен действителен
}

// GetTokenInfo возвращает информацию о сроках действия токенов
// Обновлено для использования TokenManager
func (s *AuthService) GetTokenInfo(refreshToken string) (*manager.TokenInfo, error) {
	info, err := s.tokenManager.GetTokenInfo(refreshToken)
	if err != nil {
		log.Printf("[AuthService] Ошибка получения информации о токене: %v", err)
		// Пробрасываем ошибку TokenManager или другую
		return nil, err
	}
	return info, nil
}

// DebugToken декодирует токен для отладки
// Использует jwtService напрямую
func (s *AuthService) DebugToken(tokenString string) map[string]interface{} {
	return s.jwtService.DebugToken(tokenString)
}

// GetUserByEmail возвращает пользователя по Email
func (s *AuthService) GetUserByEmail(email string) (*entity.User, error) {
	return s.userRepo.GetByEmail(email)
}

// AdminResetPassword сбрасывает пароль пользователя администратором
// Не требует проверки старого пароля и инвалидирует все токены пользователя
func (s *AuthService) AdminResetPassword(userID uint, newPassword string) error {
	// Обновляем пароль с использованием безопасного метода
	// UserRepo.UpdatePassword выполняет хеширование и использует прямой SQL-запрос
	// для обхода хука BeforeSave и предотвращения двойного хеширования
	if err := s.userRepo.UpdatePassword(userID, newPassword); err != nil {
		return err
	}

	// Инвалидируем все токены пользователя
	return s.LogoutAllDevices(userID)
}

// GetRefreshTokenByUserID получает активный refresh токен пользователя
func (s *AuthService) GetRefreshTokenByUserID(userID uint) (*entity.RefreshToken, error) {
	tokens, err := s.refreshTokenRepo.GetActiveTokensForUser(userID)
	if err != nil {
		return nil, err
	}

	if len(tokens) == 0 {
		return nil, errors.New("no active refresh tokens found")
	}

	// Возвращаем первый активный токен
	return tokens[0], nil
}

// AuthenticateUser проверяет учетные данные пользователя без создания токенов
func (s *AuthService) AuthenticateUser(email, password string) (*entity.User, error) {
	// Получаем пользователя по email
	user, err := s.userRepo.GetByEmail(email)
	if err != nil {
		log.Printf("[AuthService] Пользователь с email %s не найден: %v", email, err)
		// Возвращаем стандартную ошибку
		return nil, fmt.Errorf("%w: invalid credentials", apperrors.ErrUnauthorized)
	}

	// Проверяем пароль
	if !user.CheckPassword(password) {
		log.Printf("[AuthService] Неверный пароль для пользователя с email %s", email)
		// Возвращаем стандартную ошибку
		return nil, fmt.Errorf("%w: invalid credentials", apperrors.ErrUnauthorized)
	}

	return user, nil
}

// IsSessionOwnedByUser проверяет, принадлежит ли сессия пользователю
func (s *AuthService) IsSessionOwnedByUser(userID, sessionID uint) (bool, error) {
	if s.refreshTokenRepo == nil {
		return false, errors.New("refresh token repository not available")
	}

	// Получаем токен по ID
	token, err := s.refreshTokenRepo.GetTokenByID(sessionID)
	if err != nil {
		if errors.Is(err, apperrors.ErrNotFound) {
			return false, nil
		}
		return false, err
	}

	// Проверяем, что токен принадлежит пользователю
	return token.UserID == userID, nil
}

// RevokeSession отзывает отдельную сессию по ID
func (s *AuthService) RevokeSession(sessionID uint) error {
	if s.refreshTokenRepo == nil {
		return errors.New("refresh token repository not available")
	}

	return s.refreshTokenRepo.MarkTokenAsExpiredByID(sessionID, "session_revoked")
}

// GetRefreshTokenByID получает refresh-токен по его ID
func (s *AuthService) GetRefreshTokenByID(tokenID uint) (*entity.RefreshToken, error) {
	return s.refreshTokenRepo.GetTokenByID(tokenID)
}

// RevokeSessionByID отзывает конкретную сессию по ее ID
// Обновлено для использования TokenManager
func (s *AuthService) RevokeSessionByID(sessionID uint, reason string) error {
	// Получаем токен по ID, чтобы убедиться, что он существует
	token, err := s.refreshTokenRepo.GetTokenByID(sessionID)
	if err != nil {
		log.Printf("[AuthService] Ошибка получения сессии ID=%d для отзыва: %v", sessionID, err)
		return fmt.Errorf("ошибка получения сессии")
	}
	if token == nil {
		return fmt.Errorf("сессия с ID %d не найдена", sessionID)
	}

	// Используем TokenManager для отзыва
	err = s.tokenManager.RevokeRefreshToken(token.Token) // TokenManager отзывает по значению токена
	if err != nil {
		log.Printf("[AuthService] Ошибка отзыва сессии ID=%d через TokenManager: %v", sessionID, err)
		// Попытаемся пометить как истекший напрямую через репозиторий с причиной
		if repoErr := s.refreshTokenRepo.MarkTokenAsExpiredByID(sessionID, reason); repoErr != nil {
			log.Printf("[AuthService] Ошибка прямой маркировки сессии ID=%d как истекшей: %v", sessionID, repoErr)
			return fmt.Errorf("ошибка отзыва сессии")
		}
	}

	log.Printf("[AuthService] Сессия ID=%d успешно отозвана. Причина: %s", sessionID, reason)
	return nil
}

// RevokeAllUserSessions отзывает все сессии пользователя с указанием причины
func (s *AuthService) RevokeAllUserSessions(userID uint, reason string) error {
	// Получаем все активные сессии пользователя
	tokens, err := s.refreshTokenRepo.GetActiveTokensForUser(userID)
	if err != nil {
		return fmt.Errorf("не удалось получить активные сессии: %w", err)
	}

	// Отзываем каждую сессию с указанием причины
	for _, token := range tokens {
		now := time.Now()
		token.RevokedAt = &now
		token.Reason = reason
		token.IsExpired = true

		err = s.refreshTokenRepo.MarkTokenAsExpiredByID(token.ID, reason)
		if err != nil {
			log.Printf("Ошибка при отзыве сессии ID=%d: %v", token.ID, err)
			// Продолжаем отзыв других сессий
		}
	}

	return nil
}

// GetActiveSessionsWithDetails возвращает детализированную информацию об активных сессиях пользователя
// Обновлено для использования TokenManager
func (s *AuthService) GetActiveSessionsWithDetails(userID uint) ([]map[string]interface{}, error) {
	sessions, err := s.tokenManager.GetUserActiveSessions(userID)
	if err != nil {
		log.Printf("[AuthService] Ошибка получения активных сессий (детали) для пользователя ID=%d: %v", userID, err)
		return nil, fmt.Errorf("не удалось получить список сессий")
	}

	var sessionDetails []map[string]interface{}
	for _, session := range sessions {
		// Используем метод SessionInfo() из entity.RefreshToken
		details := session.SessionInfo()
		sessionDetails = append(sessionDetails, details)
	}

	return sessionDetails, nil
}

// GenerateWsTicket генерирует короткоживущий тикет для аутентификации WebSocket
// Использует jwtService напрямую
func (s *AuthService) GenerateWsTicket(userID uint, email string) (string, error) {
	ticket, err := s.jwtService.GenerateWSTicket(userID, email)
	if err != nil {
		log.Printf("[AuthService] Ошибка генерации WebSocket тикета для пользователя ID=%d: %v", userID, err)
		return "", fmt.Errorf("ошибка генерации тикета")
	}
	return ticket, nil
}

// InvalidateUserTokens выполняет инвалидацию JWT токенов для пользователя
// Это публичный метод, чтобы его можно было вызвать из handler
func (s *AuthService) InvalidateUserTokens(userID uint) error {
	// Создаем контекст для вызова
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.jwtService.InvalidateTokensForUser(ctx, userID)
}
