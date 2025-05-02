DROP INDEX IF EXISTS idx_user_answers_question_id;
DROP INDEX IF EXISTS uidx_user_answers_user_quiz_question;

DROP INDEX IF EXISTS uidx_refresh_tokens_token;
-- Восстанавливаем старый не уникальный индекс (если он был нужен)
-- Если он не нужен, эту строку можно удалить
-- CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens (token);
DROP INDEX IF EXISTS idx_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_refresh_tokens_user_id_expires_at;

DROP INDEX IF EXISTS idx_invalid_tokens_invalidation_time; 