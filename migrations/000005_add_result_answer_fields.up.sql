-- Добавление полей в таблицу results
ALTER TABLE results ADD COLUMN IF NOT EXISTS is_winner BOOLEAN DEFAULT FALSE;
ALTER TABLE results ADD COLUMN IF NOT EXISTS prize_fund BIGINT DEFAULT 0;
ALTER TABLE results ADD COLUMN IF NOT EXISTS is_eliminated BOOLEAN DEFAULT FALSE;

-- Добавление полей в таблицу user_answers
ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS is_eliminated BOOLEAN DEFAULT FALSE;
ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS elimination_reason TEXT;

-- Добавляем комментарии для ясности (опционально)
COMMENT ON COLUMN results.is_winner IS 'Флаг, указывающий, является ли пользователь победителем';
COMMENT ON COLUMN results.prize_fund IS 'Размер доли призового фонда для этого игрока';
COMMENT ON COLUMN results.is_eliminated IS 'Выбыл ли пользователь во время игры (дублируется для удобства запросов)';
COMMENT ON COLUMN user_answers.is_eliminated IS 'Был ли пользователь выбывшим на момент этого ответа';
COMMENT ON COLUMN user_answers.elimination_reason IS 'Причина выбывания (если is_eliminated = true)'; 