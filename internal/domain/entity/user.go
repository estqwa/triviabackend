package entity

import (
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// User представляет пользователя в системе
type User struct {
	ID             uint      `gorm:"primaryKey" json:"id"`
	Username       string    `gorm:"size:50;not null;uniqueIndex" json:"username"`
	Email          string    `gorm:"size:100;not null;uniqueIndex" json:"email"`
	Password       string    `gorm:"size:100;not null" json:"-"`
	ProfilePicture string    `gorm:"size:255;not null;default:''" json:"profile_picture"`
	GamesPlayed    int64     `gorm:"not null;default:0" json:"games_played"`
	TotalScore     int64     `gorm:"not null;default:0" json:"total_score"`
	HighestScore   int64     `gorm:"not null;default:0" json:"highest_score"`
	WinsCount      int64     `gorm:"not null;default:0;index:idx_users_leaderboard" json:"wins_count"`
	TotalPrizeWon  int64     `gorm:"not null;default:0;index:idx_users_leaderboard" json:"total_prize_won"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// TableName определяет имя таблицы для GORM
func (User) TableName() string {
	return "users"
}

// BeforeSave хеширует пароль перед сохранением, только если он не является bcrypt-хешем
func (u *User) BeforeSave(tx *gorm.DB) error {
	// Хешируем пароль только если он:
	// 1. Не пустой
	// 2. Не является уже bcrypt-хешем (начинается с "$2a$", "$2b$" или "$2y$")
	if len(u.Password) > 0 && !strings.HasPrefix(u.Password, "$2a$") &&
		!strings.HasPrefix(u.Password, "$2b$") && !strings.HasPrefix(u.Password, "$2y$") {
		// Используем стандартное значение cost factor для bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[User.BeforeSave] Ошибка при хешировании пароля для email=%s: %v", u.Email, err)
			return err
		}
		u.Password = string(hashedPassword)
	}
	return nil
}

// CheckPassword проверяет, соответствует ли переданный пароль хешу
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}
