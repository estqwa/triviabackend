-- Удаление индексов
DROP INDEX IF EXISTS idx_user_answers_user_id;
DROP INDEX IF EXISTS idx_user_answers_quiz_id;
DROP INDEX IF EXISTS idx_results_quiz_id;
DROP INDEX IF EXISTS idx_results_user_id;
DROP INDEX IF EXISTS idx_questions_quiz_id;
DROP INDEX IF EXISTS idx_quizzes_status;
DROP INDEX IF EXISTS idx_quizzes_scheduled_time;

-- Удаление таблиц
DROP TABLE IF EXISTS results;
DROP TABLE IF EXISTS user_answers;
DROP TABLE IF EXISTS questions;
DROP TABLE IF EXISTS quizzes;
DROP TABLE IF EXISTS invalid_tokens;
DROP TABLE IF EXISTS users;