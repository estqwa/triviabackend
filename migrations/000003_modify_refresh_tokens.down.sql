-- Удаляем индекс
DROP INDEX IF EXISTS idx_refresh_tokens_not_expired;

-- Удаляем поле is_expired
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS is_expired; 