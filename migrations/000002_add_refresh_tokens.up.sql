-- Таблица refresh-токенов
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token TEXT NOT NULL UNIQUE,
    device_id VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50) DEFAULT '',
    user_agent TEXT DEFAULT '',
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- Индекс для быстрого поиска по токену
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens (token);

-- Индекс для поиска токенов пользователя
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id); 