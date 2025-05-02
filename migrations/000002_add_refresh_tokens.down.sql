-- Удаление индексов
DROP INDEX IF EXISTS idx_refresh_tokens_token;
DROP INDEX IF EXISTS idx_refresh_tokens_user_id;

-- Удаление таблицы
DROP TABLE IF EXISTS refresh_tokens; 