-- Откат исправления refresh_tokens
ALTER TABLE refresh_tokens ALTER COLUMN is_expired DROP DEFAULT, ALTER COLUMN is_expired DROP NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN user_agent DROP DEFAULT, ALTER COLUMN user_agent DROP NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN ip_address DROP DEFAULT, ALTER COLUMN ip_address DROP NOT NULL;
-- Не трогаем user_id, token, device_id, expires_at, так как они должны быть NOT NULL

-- Откат исправления invalid_tokens
ALTER TABLE invalid_tokens ALTER COLUMN invalidation_time DROP NOT NULL;

-- Откат исправления results
ALTER TABLE results ALTER COLUMN is_eliminated DROP DEFAULT, ALTER TABLE results ALTER COLUMN is_eliminated DROP NOT NULL;
ALTER TABLE results ALTER COLUMN prize_fund DROP DEFAULT, ALTER TABLE results ALTER COLUMN prize_fund DROP NOT NULL;
ALTER TABLE results ALTER COLUMN is_winner DROP DEFAULT, ALTER TABLE results ALTER COLUMN is_winner DROP NOT NULL;
ALTER TABLE results ALTER COLUMN rank DROP DEFAULT, ALTER TABLE results ALTER COLUMN rank DROP NOT NULL;
ALTER TABLE results ALTER COLUMN total_questions DROP DEFAULT, ALTER TABLE results ALTER COLUMN total_questions DROP NOT NULL;
ALTER TABLE results ALTER COLUMN correct_answers DROP DEFAULT, ALTER TABLE results ALTER COLUMN correct_answers DROP NOT NULL;
ALTER TABLE results ALTER COLUMN profile_picture DROP DEFAULT, ALTER TABLE results ALTER COLUMN profile_picture DROP NOT NULL;
ALTER TABLE results ALTER COLUMN username DROP NOT NULL;

-- Откат исправления user_answers
ALTER TABLE user_answers ALTER COLUMN is_eliminated DROP DEFAULT, ALTER TABLE user_answers ALTER COLUMN is_eliminated DROP NOT NULL;
ALTER TABLE user_answers ALTER COLUMN score DROP DEFAULT, ALTER TABLE user_answers ALTER COLUMN score DROP NOT NULL;
ALTER TABLE user_answers ALTER COLUMN selected_option DROP NOT NULL;

-- Откат исправления quizzes
ALTER TABLE quizzes ALTER COLUMN question_count DROP DEFAULT, ALTER TABLE quizzes ALTER COLUMN question_count DROP NOT NULL;
ALTER TABLE quizzes ALTER COLUMN description DROP DEFAULT, ALTER TABLE quizzes ALTER COLUMN description DROP NOT NULL;

-- Откат исправления users
ALTER TABLE users ALTER COLUMN profile_picture DROP DEFAULT, ALTER COLUMN profile_picture DROP NOT NULL;
ALTER TABLE users ALTER COLUMN highest_score DROP DEFAULT, ALTER TABLE users ALTER COLUMN highest_score DROP NOT NULL;
ALTER TABLE users ALTER COLUMN total_score DROP DEFAULT, ALTER TABLE users ALTER COLUMN total_score DROP NOT NULL;
ALTER TABLE users ALTER COLUMN games_played DROP DEFAULT, ALTER TABLE users ALTER COLUMN games_played DROP NOT NULL; 