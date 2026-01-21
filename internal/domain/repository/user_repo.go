package repository

import (
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// UserRepository определяет методы для работы с пользователями
type UserRepository interface {
	Create(user *entity.User) error
	GetByID(id uint) (*entity.User, error)
	GetByEmail(email string) (*entity.User, error)
	GetByUsername(username string) (*entity.User, error)
	Update(user *entity.User) error
	UpdateProfile(userID uint, updates map[string]interface{}) error
	UpdatePassword(userID uint, newPassword string) error
	UpdateScore(userID uint, score int64) error
	IncrementGamesPlayed(userID uint) error
	List(limit, offset int) ([]entity.User, error)
	// GetLeaderboard возвращает пользователей для лидерборда с пагинацией и общим количеством
	GetLeaderboard(limit, offset int) ([]entity.User, int64, error)
}
