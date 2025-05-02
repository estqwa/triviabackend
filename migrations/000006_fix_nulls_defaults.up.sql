-- Исправление users
UPDATE users SET games_played = 0 WHERE games_played IS NULL;
UPDATE users SET total_score = 0 WHERE total_score IS NULL;
UPDATE users SET highest_score = 0 WHERE highest_score IS NULL;
UPDATE users SET profile_picture = '' WHERE profile_picture IS NULL;
ALTER TABLE users ALTER COLUMN games_played SET NOT NULL, ALTER COLUMN games_played SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN total_score SET NOT NULL, ALTER COLUMN total_score SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN highest_score SET NOT NULL, ALTER COLUMN highest_score SET DEFAULT 0;
ALTER TABLE users ALTER COLUMN profile_picture SET NOT NULL, ALTER COLUMN profile_picture SET DEFAULT '';

-- Исправление quizzes
UPDATE quizzes SET description = '' WHERE description IS NULL;
UPDATE quizzes SET question_count = 0 WHERE question_count IS NULL;
ALTER TABLE quizzes ALTER COLUMN description SET NOT NULL, ALTER COLUMN description SET DEFAULT '';
ALTER TABLE quizzes ALTER COLUMN question_count SET NOT NULL, ALTER COLUMN question_count SET DEFAULT 0;

-- Исправление user_answers
UPDATE user_answers SET selected_option = -1 WHERE selected_option IS NULL; -- Заполняем NULL чем-то (например, -1, если 0 - валидный ответ)
UPDATE user_answers SET score = 0 WHERE score IS NULL;
UPDATE user_answers SET is_eliminated = FALSE WHERE is_eliminated IS NULL;
-- NOT NULL уже установлены для user_id, quiz_id, question_id, is_correct, response_time_ms
ALTER TABLE user_answers ALTER COLUMN selected_option SET NOT NULL;
ALTER TABLE user_answers ALTER COLUMN score SET NOT NULL, ALTER COLUMN score SET DEFAULT 0;
ALTER TABLE user_answers ALTER COLUMN is_eliminated SET NOT NULL, ALTER COLUMN is_eliminated SET DEFAULT FALSE;
-- elimination_reason оставляем NULLABLE

-- Исправление results
UPDATE results SET username = 'unknown' WHERE username IS NULL; -- Заполняем NULL чем-то
UPDATE results SET profile_picture = '' WHERE profile_picture IS NULL;
UPDATE results SET correct_answers = 0 WHERE correct_answers IS NULL;
UPDATE results SET total_questions = 0 WHERE total_questions IS NULL;
UPDATE results SET rank = 0 WHERE rank IS NULL;
UPDATE results SET is_winner = FALSE WHERE is_winner IS NULL;
UPDATE results SET prize_fund = 0 WHERE prize_fund IS NULL;
UPDATE results SET is_eliminated = FALSE WHERE is_eliminated IS NULL;
-- NOT NULL уже установлены для user_id, quiz_id, score, completed_at
ALTER TABLE results ALTER COLUMN username SET NOT NULL;
ALTER TABLE results ALTER COLUMN profile_picture SET NOT NULL, ALTER COLUMN profile_picture SET DEFAULT '';
ALTER TABLE results ALTER COLUMN correct_answers SET NOT NULL, ALTER COLUMN correct_answers SET DEFAULT 0;
ALTER TABLE results ALTER COLUMN total_questions SET NOT NULL, ALTER COLUMN total_questions SET DEFAULT 0;
ALTER TABLE results ALTER COLUMN rank SET NOT NULL, ALTER COLUMN rank SET DEFAULT 0;
ALTER TABLE results ALTER COLUMN is_winner SET NOT NULL, ALTER COLUMN is_winner SET DEFAULT FALSE;
ALTER TABLE results ALTER COLUMN prize_fund SET NOT NULL, ALTER COLUMN prize_fund SET DEFAULT 0;
ALTER TABLE results ALTER COLUMN is_eliminated SET NOT NULL, ALTER COLUMN is_eliminated SET DEFAULT FALSE;

-- Исправление invalid_tokens
UPDATE invalid_tokens SET invalidation_time = NOW() WHERE invalidation_time IS NULL; -- Заполняем текущим временем, т.к. NOT NULL обязательно
-- NOT NULL уже установлен для user_id
ALTER TABLE invalid_tokens ALTER COLUMN invalidation_time SET NOT NULL;

-- Исправление refresh_tokens
UPDATE refresh_tokens SET user_id = 0 WHERE user_id IS NULL; -- Заполняем 0 (требует внимания, почему тут NULL)
UPDATE refresh_tokens SET token = 'unknown-' || id::text WHERE token IS NULL; -- Генерируем псевдо-уникальное значение
UPDATE refresh_tokens SET device_id = 'unknown' WHERE device_id IS NULL;
UPDATE refresh_tokens SET expires_at = NOW() + INTERVAL '1 year' WHERE expires_at IS NULL; -- Устанавливаем дату истечения
UPDATE refresh_tokens SET ip_address = '' WHERE ip_address IS NULL;
UPDATE refresh_tokens SET user_agent = '' WHERE user_agent IS NULL;
UPDATE refresh_tokens SET is_expired = FALSE WHERE is_expired IS NULL;
-- NOT NULL уже установлен для user_id (исправлено в миграции 000002), token, device_id (исправлено в миграции 000002), expires_at (исправлено в миграции 000002)
-- Проверяем user_id, token, device_id, expires_at на NOT NULL на всякий случай
ALTER TABLE refresh_tokens ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN token SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN device_id SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN expires_at SET NOT NULL;
ALTER TABLE refresh_tokens ALTER COLUMN ip_address SET NOT NULL, ALTER COLUMN ip_address SET DEFAULT '';
ALTER TABLE refresh_tokens ALTER COLUMN user_agent SET NOT NULL, ALTER COLUMN user_agent SET DEFAULT '';
ALTER TABLE refresh_tokens ALTER COLUMN is_expired SET NOT NULL, ALTER COLUMN is_expired SET DEFAULT FALSE; -- Установлено в 000003 