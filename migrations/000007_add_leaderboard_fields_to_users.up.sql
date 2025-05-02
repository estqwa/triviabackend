-- +migrate Up
ALTER TABLE users
ADD COLUMN wins_count INTEGER NOT NULL DEFAULT 0,
ADD COLUMN total_prize_won INTEGER NOT NULL DEFAULT 0; 

-- Индекс для ускорения запросов к лидерборду
CREATE INDEX idx_users_leaderboard ON users (wins_count DESC, total_prize_won DESC);
