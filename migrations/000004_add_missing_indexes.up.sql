-- Индексы для таблицы user_answers
CREATE INDEX IF NOT EXISTS idx_user_answers_question_id ON user_answers (question_id);
CREATE UNIQUE INDEX IF NOT EXISTS uidx_user_answers_user_quiz_question ON user_answers (user_id, quiz_id, question_id);

-- Индексы для таблицы refresh_tokens
-- Удаляем старый не уникальный индекс, если он существует, перед созданием уникального
DROP INDEX IF EXISTS idx_refresh_tokens_token;
CREATE UNIQUE INDEX IF NOT EXISTS uidx_refresh_tokens_token ON refresh_tokens (token);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at ON refresh_tokens (expires_at);
-- Композитный индекс для поиска активных токенов пользователя
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id_expires_at ON refresh_tokens (user_id, expires_at); 
-- Индекс idx_refresh_tokens_user_id уже создан в 000002
-- Индекс idx_refresh_tokens_not_expired (user_id, is_expired) создан в 000003

-- Индексы для таблицы invalid_tokens
CREATE INDEX IF NOT EXISTS idx_invalid_tokens_invalidation_time ON invalid_tokens (invalidation_time); 