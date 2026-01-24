        -- Добавляем колонку для хранения причины отзыва/истечения срока действия
        ALTER TABLE refresh_tokens
        ADD COLUMN IF NOT EXISTS reason TEXT NULL DEFAULT '';

        COMMENT ON COLUMN refresh_tokens.reason IS 'Причина отзыва или истечения срока действия токена (например, user_logout)';