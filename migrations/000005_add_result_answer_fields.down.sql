-- Удаление полей из таблицы user_answers
ALTER TABLE user_answers DROP COLUMN IF EXISTS elimination_reason;
ALTER TABLE user_answers DROP COLUMN IF EXISTS is_eliminated;

-- Удаление полей из таблицы results
ALTER TABLE results DROP COLUMN IF EXISTS is_eliminated;
ALTER TABLE results DROP COLUMN IF EXISTS prize_fund;
ALTER TABLE results DROP COLUMN IF EXISTS is_winner; 