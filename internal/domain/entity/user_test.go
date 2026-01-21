package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// mockTx создаёт минимальный мок для передачи в BeforeSave
// В реальности BeforeSave не использует tx напрямую, но сигнатура требует его
var mockTx *gorm.DB = nil

func TestUser_BeforeSave_HashesPassword(t *testing.T) {
	// Arrange: создаём пользователя с открытым паролем
	plainPassword := "mySecretPassword123"
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: plainPassword,
	}

	// Act: вызываем BeforeSave
	err := user.BeforeSave(mockTx)

	// Assert: пароль должен быть хеширован
	require.NoError(t, err, "BeforeSave не должен возвращать ошибку")
	assert.NotEqual(t, plainPassword, user.Password, "Пароль должен быть изменён после хеширования")
	assert.True(t, len(user.Password) > 50, "Хеш bcrypt должен быть длиннее 50 символов")

	// Проверяем, что пароль действительно bcrypt-хеш
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(plainPassword))
	assert.NoError(t, err, "Хеш должен соответствовать исходному паролю")
}

func TestUser_BeforeSave_SkipsAlreadyHashedPassword(t *testing.T) {
	// Arrange: создаём пользователя с уже хешированным паролем
	plainPassword := "alreadyHashed"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}
	originalHash := user.Password

	// Act: вызываем BeforeSave
	err = user.BeforeSave(mockTx)

	// Assert: пароль не должен измениться (нет двойного хеширования)
	require.NoError(t, err, "BeforeSave не должен возвращать ошибку")
	assert.Equal(t, originalHash, user.Password, "Уже хешированный пароль не должен изменяться")
}

func TestUser_BeforeSave_SkipsEmptyPassword(t *testing.T) {
	// Arrange: пользователь с пустым паролем
	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "",
	}

	// Act: вызываем BeforeSave
	err := user.BeforeSave(mockTx)

	// Assert: пароль должен остаться пустым
	require.NoError(t, err, "BeforeSave не должен возвращать ошибку для пустого пароля")
	assert.Equal(t, "", user.Password, "Пустой пароль должен оставаться пустым")
}

func TestUser_CheckPassword_CorrectPassword(t *testing.T) {
	// Arrange: создаём пользователя и хешируем его пароль
	plainPassword := "correctPassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(plainPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	// Act & Assert: правильный пароль должен вернуть true
	result := user.CheckPassword(plainPassword)
	assert.True(t, result, "CheckPassword должен вернуть true для правильного пароля")
}

func TestUser_CheckPassword_IncorrectPassword(t *testing.T) {
	// Arrange: создаём пользователя и хешируем его пароль
	correctPassword := "correctPassword123"
	wrongPassword := "wrongPassword456"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	// Act & Assert: неправильный пароль должен вернуть false
	result := user.CheckPassword(wrongPassword)
	assert.False(t, result, "CheckPassword должен вернуть false для неправильного пароля")
}

func TestUser_CheckPassword_EmptyPassword(t *testing.T) {
	// Arrange: пользователь с хешем, проверка пустого пароля
	correctPassword := "somePassword123"
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	require.NoError(t, err)

	user := &User{
		Username: "testuser",
		Email:    "test@example.com",
		Password: string(hashedPassword),
	}

	// Act & Assert: пустой пароль не должен совпадать
	result := user.CheckPassword("")
	assert.False(t, result, "CheckPassword должен вернуть false для пустого пароля")
}

func TestUser_TableName(t *testing.T) {
	// Arrange
	user := User{}

	// Act & Assert
	assert.Equal(t, "users", user.TableName(), "TableName должен возвращать 'users'")
}
