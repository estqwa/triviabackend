-- Добавляем поле is_expired для маркировки токенов, вместо их удаления
ALTER TABLE refresh_tokens ADD COLUMN is_expired BOOLEAN NOT NULL DEFAULT FALSE;

-- Создаем индекс для быстрого поиска действительных токенов
CREATE INDEX idx_refresh_tokens_not_expired ON refresh_tokens (user_id, is_expired) WHERE is_expired = FALSE;

-- Обновляем имеющиеся токены, помечая их как действительные
UPDATE refresh_tokens SET is_expired = FALSE;

COMMENT ON COLUMN refresh_tokens.is_expired IS 'Флаг, указывающий, что токен истек (вместо его физического удаления)'; 