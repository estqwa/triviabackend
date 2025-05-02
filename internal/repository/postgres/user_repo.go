package postgres

import (
	"errors"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
)

// UserRepo реализует repository.UserRepository
type UserRepo struct {
	db *gorm.DB
}

// NewUserRepo создает новый репозиторий пользователей
func NewUserRepo(db *gorm.DB) *UserRepo {
	return &UserRepo{db: db}
}

// Create создает нового пользователя
func (r *UserRepo) Create(user *entity.User) error {
	return r.db.Create(user).Error
}

// GetByID возвращает пользователя по ID
func (r *UserRepo) GetByID(id uint) (*entity.User, error) {
	var user entity.User
	err := r.db.First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetByEmail возвращает пользователя по email
func (r *UserRepo) GetByEmail(email string) (*entity.User, error) {
	var user entity.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// GetByUsername возвращает пользователя по имени пользователя
func (r *UserRepo) GetByUsername(username string) (*entity.User, error) {
	var user entity.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Update обновляет информацию о пользователе
func (r *UserRepo) Update(user *entity.User) error {
	return r.db.Save(user).Error
}

// UpdateProfile обновляет профиль пользователя без изменения пароля
// Этот метод обновляет только указанные поля, не затрагивая пароль
func (r *UserRepo) UpdateProfile(userID uint, updates map[string]interface{}) error {
	// Проверяем, что не пытаемся обновить пароль через этот метод
	delete(updates, "password")

	// Устанавливаем время обновления
	updates["updated_at"] = time.Now()

	return r.db.Model(&entity.User{}).Where("id = ?", userID).Updates(updates).Error
}

// UpdatePassword безопасно обновляет пароль пользователя
// Хеширует пароль перед сохранением в базу данных
func (r *UserRepo) UpdatePassword(userID uint, newPassword string) error {
	// Получаем пользователя для логирования и диагностики
	var user entity.User
	if err := r.db.First(&user, userID).Error; err != nil {
		log.Printf("[UserRepo.UpdatePassword] Ошибка при получении пользователя ID=%d: %v", userID, err)
		return err
	}

	log.Printf("[UserRepo.UpdatePassword] Обновление пароля для пользователя ID=%d, Email=%s",
		userID, user.Email)

	// Хешируем пароль непосредственно здесь, вместо того чтобы полагаться на BeforeSave
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("[UserRepo.UpdatePassword] Ошибка при хешировании пароля: %v", err)
		return err
	}

	// Используем SQL запрос напрямую, чтобы обойти хук BeforeSave и предотвратить двойное хеширование
	result := r.db.Exec(
		"UPDATE users SET password = ?, updated_at = ? WHERE id = ?",
		string(hashedPassword),
		time.Now(),
		userID,
	)

	if result.Error != nil {
		log.Printf("[UserRepo.UpdatePassword] Ошибка при обновлении пароля: %v", result.Error)
		return result.Error
	}

	log.Printf("[UserRepo.UpdatePassword] Пароль успешно обновлён для пользователя ID=%d, Email=%s",
		userID, user.Email)

	return nil
}

// UpdateScore обновляет общий счет пользователя
func (r *UserRepo) UpdateScore(userID uint, score int) error {
	// Выполняем транзакцию для атомарного обновления
	return r.db.Transaction(func(tx *gorm.DB) error {
		var user entity.User
		if err := tx.First(&user, userID).Error; err != nil {
			return err
		}

		// Обновляем общий счет
		user.TotalScore += score

		// Обновляем высший счет, если необходимо
		if score > user.HighestScore {
			user.HighestScore = score
		}

		return tx.Save(&user).Error
	})
}

// IncrementGamesPlayed увеличивает счетчик сыгранных игр
func (r *UserRepo) IncrementGamesPlayed(userID uint) error {
	return r.db.Model(&entity.User{}).
		Where("id = ?", userID).
		UpdateColumn("games_played", gorm.Expr("games_played + ?", 1)).
		Error
}

// List возвращает список пользователей с пагинацией
func (r *UserRepo) List(limit, offset int) ([]entity.User, error) {
	var users []entity.User
	err := r.db.Limit(limit).Offset(offset).Order("id").Find(&users).Error
	return users, err
}

// GetLeaderboard возвращает пользователей для лидерборда с пагинацией и общим количеством,
// отсортированных по количеству побед и общему призу.
func (r *UserRepo) GetLeaderboard(limit, offset int) ([]entity.User, int64, error) {
	var users []entity.User
	var total int64

	// Используем транзакцию для согласованности чтения данных и общего количества
	tx := r.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	if tx.Error != nil {
		return nil, 0, tx.Error
	}

	// Сначала получаем общее количество пользователей
	err := tx.Model(&entity.User{}).Count(&total).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// Затем получаем пользователей для текущей страницы
	// Сортируем по wins_count DESC, затем total_prize_won DESC, и ID для стабильности
	err = tx.Order("wins_count DESC, total_prize_won DESC, id ASC").
		Limit(limit).
		Offset(offset).
		Select("id", "username", "profile_picture", "wins_count", "total_prize_won"). // Выбираем только нужные поля
		Find(&users).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// Коммитим транзакцию
	if err := tx.Commit().Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}
