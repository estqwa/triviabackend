        -- Добавляем колонку для хранения времени отзыва токена
        ALTER TABLE refresh_tokens
        ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ NULL;

        COMMENT ON COLUMN refresh_tokens.revoked_at IS 'Время, когда токен был отозван (если NULL - не отозван)';