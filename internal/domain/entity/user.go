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
	Username       string    `gorm:"size:50;not null;unique" json:"username"`
	Email          string    `gorm:"size:100;not null;unique" json:"email"`
	Password       string    `gorm:"size:100;not null" json:"-"`
	ProfilePicture string    `gorm:"size:255" json:"profile_picture"`
	GamesPlayed    int64     `json:"games_played"`
	TotalScore     int64     `json:"total_score"`
	HighestScore   int64     `json:"highest_score"`
	WinsCount      int64     `json:"wins_count"`
	TotalPrizeWon  int64     `json:"total_prize_won"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// BeforeSave хеширует пароль перед сохранением, только если он не является bcrypt-хешем
func (u *User) BeforeSave(tx *gorm.DB) error {
	// Дополнительное логирование для отслеживания вызовов BeforeSave
	log.Printf("[User.BeforeSave] Вызов для пользователя ID=%d, Email=%s", u.ID, u.Email)

	// Хешируем пароль только если он:
	// 1. Не пустой
	// 2. Не является уже bcrypt-хешем (начинается с "$2a$", "$2b$" или "$2y$")
	if len(u.Password) > 0 && !strings.HasPrefix(u.Password, "$2a$") &&
		!strings.HasPrefix(u.Password, "$2b$") && !strings.HasPrefix(u.Password, "$2y$") {
		// Логирование для диагностики
		log.Printf("[User.BeforeSave] Хеширование пароля для пользователя ID=%d, Email=%s (старый пароль не был хешем)",
			u.ID, u.Email)

		// Используем стандартное значение cost factor для bcrypt
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("[User.BeforeSave] Ошибка при хешировании пароля: %v", err)
			return err
		}
		u.Password = string(hashedPassword)
	} else if len(u.Password) > 0 {
		// Логирование для диагностики
		log.Printf("[User.BeforeSave] Пропуск хеширования для пользователя ID=%d, Email=%s (пароль уже хеширован)",
			u.ID, u.Email)
	}

	return nil
}

// CheckPassword проверяет, соответствует ли переданный пароль хешу
func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))

	if err != nil {
		log.Printf("[User.CheckPassword] Ошибка проверки пароля для пользователя ID=%d, Email=%s: %v",
			u.ID, u.Email, err)

		// Диагностическая информация о хеше пароля
		if len(u.Password) > 0 {
			log.Printf("[User.CheckPassword] Текущий хеш пароля: %s (длина: %d)",
				u.Password[:10]+"...", len(u.Password))
		} else {
			log.Printf("[User.CheckPassword] Хеш пароля пустой!")
		}

		return false
	}

	log.Printf("[User.CheckPassword] Успешная проверка пароля для пользователя ID=%d, Email=%s",
		u.ID, u.Email)
	return true
}
