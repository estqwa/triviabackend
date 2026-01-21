package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// ============================================================================
// Моки для тестирования AuthService
// ============================================================================

// MockUserRepository реализует repository.UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *entity.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id uint) (*entity.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*entity.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) GetByUsername(username string) (*entity.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *entity.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateProfile(userID uint, updates map[string]interface{}) error {
	args := m.Called(userID, updates)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(userID uint, newPassword string) error {
	args := m.Called(userID, newPassword)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateScore(userID uint, score int64) error {
	args := m.Called(userID, score)
	return args.Error(0)
}

func (m *MockUserRepository) IncrementGamesPlayed(userID uint) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserRepository) List(limit, offset int) ([]entity.User, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.User), args.Error(1)
}

func (m *MockUserRepository) GetLeaderboard(limit, offset int) ([]entity.User, int64, error) {
	args := m.Called(limit, offset)
	if args.Get(0) == nil {
		return nil, 0, args.Error(2)
	}
	return args.Get(0).([]entity.User), args.Get(1).(int64), args.Error(2)
}

// MockRefreshTokenRepository реализует repository.RefreshTokenRepository
type MockRefreshTokenRepository struct {
	mock.Mock
}

func (m *MockRefreshTokenRepository) CreateToken(token *entity.RefreshToken) (uint, error) {
	args := m.Called(token)
	return args.Get(0).(uint), args.Error(1)
}

func (m *MockRefreshTokenRepository) GetTokenByValue(token string) (*entity.RefreshToken, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) GetTokenByID(id uint) (*entity.RefreshToken, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) CheckToken(token string) (bool, error) {
	args := m.Called(token)
	return args.Bool(0), args.Error(1)
}

func (m *MockRefreshTokenRepository) MarkTokenAsExpired(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) MarkTokenAsExpiredByID(id uint) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) DeleteToken(token string) error {
	args := m.Called(token)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) MarkAllAsExpiredForUser(userID uint) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockRefreshTokenRepository) CleanupExpiredTokens() (int64, error) {
	args := m.Called()
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRefreshTokenRepository) GetActiveTokensForUser(userID uint) ([]*entity.RefreshToken, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entity.RefreshToken), args.Error(1)
}

func (m *MockRefreshTokenRepository) CountTokensForUser(userID uint) (int, error) {
	args := m.Called(userID)
	return args.Int(0), args.Error(1)
}

func (m *MockRefreshTokenRepository) MarkOldestAsExpiredForUser(userID uint, limit int) error {
	args := m.Called(userID, limit)
	return args.Error(0)
}

// MockInvalidTokenRepository реализует repository.InvalidTokenRepository
type MockInvalidTokenRepository struct {
	mock.Mock
}

func (m *MockInvalidTokenRepository) AddInvalidToken(ctx context.Context, userID uint, invalidationTime time.Time) error {
	args := m.Called(ctx, userID, invalidationTime)
	return args.Error(0)
}

func (m *MockInvalidTokenRepository) RemoveInvalidToken(ctx context.Context, userID uint) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockInvalidTokenRepository) IsTokenInvalid(ctx context.Context, userID uint, tokenIssuedAt time.Time) (bool, error) {
	args := m.Called(ctx, userID, tokenIssuedAt)
	return args.Bool(0), args.Error(1)
}

func (m *MockInvalidTokenRepository) GetAllInvalidTokens(ctx context.Context) ([]entity.InvalidToken, error) {
	args := m.Called(ctx)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]entity.InvalidToken), args.Error(1)
}

func (m *MockInvalidTokenRepository) CleanupOldInvalidTokens(ctx context.Context, cutoffTime time.Time) error {
	args := m.Called(ctx, cutoffTime)
	return args.Error(0)
}

// ============================================================================
// createTestAuthService создаёт AuthService для тестирования с моками
// ============================================================================

func createTestAuthService(
	userRepo *MockUserRepository,
	refreshTokenRepo *MockRefreshTokenRepository,
	invalidTokenRepo *MockInvalidTokenRepository,
) *AuthService {
	return &AuthService{
		userRepo:         userRepo,
		refreshTokenRepo: refreshTokenRepo,
		invalidTokenRepo: invalidTokenRepo,
		jwtService:       nil, // nil для unit-тестов, не используется напрямую
		tokenManager:     nil, // nil для unit-тестов, не используется напрямую
	}
}

// ============================================================================
// Тесты для AuthService
// ============================================================================

func TestAuthService_RegisterUser_Success(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)

	// Пользователь не существует
	mockUserRepo.On("GetByEmail", "new@example.com").Return(nil, apperrors.ErrNotFound)
	mockUserRepo.On("GetByUsername", "newuser").Return(nil, apperrors.ErrNotFound)
	mockUserRepo.On("Create", mock.AnythingOfType("*entity.User")).Return(nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	user, err := authService.RegisterUser("newuser", "new@example.com", "password123")

	// Assert
	require.NoError(t, err, "Регистрация должна быть успешной")
	assert.NotNil(t, user, "Пользователь должен быть создан")
	assert.Equal(t, "newuser", user.Username)
	assert.Equal(t, "new@example.com", user.Email)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_RegisterUser_DuplicateEmail(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	existingUser := &entity.User{
		ID:       1,
		Username: "existinguser",
		Email:    "existing@example.com",
	}

	// Пользователь с таким email уже существует
	mockUserRepo.On("GetByEmail", "existing@example.com").Return(existingUser, nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	user, err := authService.RegisterUser("newuser", "existing@example.com", "password123")

	// Assert
	assert.Error(t, err, "Должна быть ошибка при дублировании email")
	assert.Nil(t, user, "Пользователь не должен быть создан")
	assert.Contains(t, err.Error(), "email", "Ошибка должна указывать на email")
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_RegisterUser_DuplicateUsername(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	existingUser := &entity.User{
		ID:       1,
		Username: "existinguser",
		Email:    "other@example.com",
	}

	// Email свободен, но username занят
	mockUserRepo.On("GetByEmail", "new@example.com").Return(nil, apperrors.ErrNotFound)
	mockUserRepo.On("GetByUsername", "existinguser").Return(existingUser, nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	user, err := authService.RegisterUser("existinguser", "new@example.com", "password123")

	// Assert
	assert.Error(t, err, "Должна быть ошибка при дублировании username")
	assert.Nil(t, user, "Пользователь не должен быть создан")
	assert.Contains(t, err.Error(), "username", "Ошибка должна указывать на username")
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_AuthenticateUser_ValidCredentials(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	plainPassword := "correctPassword123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)

	existingUser := &entity.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	mockUserRepo.On("GetByEmail", "test@example.com").Return(existingUser, nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	user, err := authService.AuthenticateUser("test@example.com", plainPassword)

	// Assert
	require.NoError(t, err, "Аутентификация должна быть успешной")
	assert.NotNil(t, user)
	assert.Equal(t, uint(1), user.ID)
	assert.Equal(t, "testuser", user.Username)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_AuthenticateUser_InvalidPassword(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctPassword"), bcrypt.DefaultCost)

	existingUser := &entity.User{
		ID:       1,
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	mockUserRepo.On("GetByEmail", "test@example.com").Return(existingUser, nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	user, err := authService.AuthenticateUser("test@example.com", "wrongPassword")

	// Assert
	assert.Error(t, err, "Должна быть ошибка при неправильном пароле")
	assert.Nil(t, user, "Пользователь не должен быть возвращён")
	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_ChangePassword_Success — пропущен, так как ChangePassword вызывает
// LogoutAllDevices, который требует TokenManager. Рекомендуется интеграционный тест.

func TestAuthService_ChangePassword_WrongOldPassword(t *testing.T) {
	// Arrange
	mockUserRepo := new(MockUserRepository)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("correctOldPassword"), bcrypt.DefaultCost)

	existingUser := &entity.User{
		ID:       1,
		Username: "testuser",
		Password: string(hashedPassword),
	}

	mockUserRepo.On("GetByID", uint(1)).Return(existingUser, nil)

	authService := createTestAuthService(mockUserRepo, nil, nil)

	// Act
	err := authService.ChangePassword(1, "wrongOldPassword", "newPassword")

	// Assert
	assert.Error(t, err, "Должна быть ошибка при неправильном старом пароле")
	mockUserRepo.AssertExpectations(t)
}

// TestAuthService_LogoutAllDevices — пропущен, требует мок TokenManager и JWTService,
// которые сложно создать для unit-теста. Рекомендуется интеграционный тест.
