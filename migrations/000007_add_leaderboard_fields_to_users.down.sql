    -- +migrate Down
ALTER TABLE users
DROP COLUMN wins_count,
DROP COLUMN total_prize_won; 