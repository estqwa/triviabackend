package dto

// LeaderboardUserDTO представляет одного пользователя в лидерборде
type LeaderboardUserDTO struct {
	Rank           int    `json:"rank"`            // Место пользователя в рейтинге
	UserID         uint   `json:"user_id"`         // ID пользователя
	Username       string `json:"username"`        // Имя пользователя
	ProfilePicture string `json:"profile_picture"` // Аватар пользователя
	WinsCount      int64  `json:"wins_count"`      // Количество побед
	TotalPrizeWon  int64  `json:"total_prize_won"` // Общая сумма выигранных призов
}

// PaginatedLeaderboardResponse представляет пагинированный ответ для лидерборда
type PaginatedLeaderboardResponse struct {
	Users   []*LeaderboardUserDTO `json:"users"`    // Список пользователей на странице
	Total   int64                 `json:"total"`    // Общее количество пользователей в лидерборде
	Page    int                   `json:"page"`     // Текущая страница
	PerPage int                   `json:"per_page"` // Количество пользователей на странице
}
