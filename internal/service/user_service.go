package service

import (
	"log"

	"github.com/yourusername/trivia-api/internal/domain/repository"
	"github.com/yourusername/trivia-api/internal/handler/dto"
)

// UserService предоставляет методы для работы с пользователями
type UserService struct {
	userRepo repository.UserRepository
	// Добавьте другие зависимости, если они понадобятся
}

// NewUserService создает новый сервис пользователей
func NewUserService(userRepo repository.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// GetLeaderboard возвращает пагинированный список пользователей для лидерборда.
func (s *UserService) GetLeaderboard(page, pageSize int) (*dto.PaginatedLeaderboardResponse, error) {
	// Валидация параметров пагинации
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10 // Значение по умолчанию
	} else if pageSize > 100 {
		pageSize = 100 // Максимальный лимит
	}

	offset := (page - 1) * pageSize

	// Получаем данные из репозитория
	users, total, err := s.userRepo.GetLeaderboard(pageSize, offset)
	if err != nil {
		log.Printf("[UserService] Ошибка при получении лидерборда из репозитория: %v", err)
		return nil, err
	}

	// Преобразуем пользователей в DTO
	userDTOs := make([]*dto.LeaderboardUserDTO, len(users))
	for i, user := range users {
		userDTOs[i] = &dto.LeaderboardUserDTO{
			Rank:           offset + i + 1, // Рассчитываем ранг на основе смещения и индекса
			UserID:         user.ID,
			Username:       user.Username,
			ProfilePicture: user.ProfilePicture,
			WinsCount:      user.WinsCount,
			TotalPrizeWon:  user.TotalPrizeWon,
		}
	}

	// Формируем пагинированный ответ
	response := &dto.PaginatedLeaderboardResponse{
		Users:   userDTOs,
		Total:   total,
		Page:    page,
		PerPage: pageSize,
	}

	return response, nil
}

// TODO: Добавить другие методы UserService (GetUserByID, UpdateProfile и т.д.) по мере необходимости
