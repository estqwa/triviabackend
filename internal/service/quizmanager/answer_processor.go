package quizmanager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"
	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// AnswerProcessor отвечает за обработку ответов пользователей
type AnswerProcessor struct {
	// Настройки
	config *Config

	// Зависимости
	deps *Dependencies
}

// NewAnswerProcessor создает новый процессор ответов
func NewAnswerProcessor(config *Config, deps *Dependencies) *AnswerProcessor {
	return &AnswerProcessor{
		config: config,
		deps:   deps,
	}
}

// ProcessAnswer обрабатывает ответ пользователя
func (ap *AnswerProcessor) ProcessAnswer(
	ctx context.Context,
	userID uint,
	question *entity.Question,
	selectedOption int,
	timestamp int64,
	quizState *ActiveQuizState,
	questionStartTimeMs int64,
) error {
	questionID := question.ID

	if quizState == nil || quizState.Quiz == nil {
		log.Printf("[AnswerProcessor] Ошибка: нет активной викторины для ответа пользователя #%d", userID)
		return fmt.Errorf("no active quiz")
	}
	quizID := quizState.Quiz.ID

	log.Printf("[AnswerProcessor] Обработка ответа пользователя #%d на вопрос #%d (викторина #%d), выбранный вариант: %d",
		userID, questionID, quizID, selectedOption)

	// -------------------- Начало проверок --------------------

	// === 1. ПРОВЕРКА ВЫБЫВАНИЯ (ПЕРЕД ВСЕМ ОСТАЛЬНЫМ) ===
	eliminationKey := fmt.Sprintf("quiz:%d:eliminated:%d", quizID, userID)
	isEliminated, err := ap.deps.CacheRepo.Exists(eliminationKey)
	if err != nil {
		// Ошибка Redis при проверке выбывания - критична, возвращаем ошибку
		log.Printf("[AnswerProcessor] CRITICAL: Ошибка Redis при проверке ключа выбывания %s: %v", eliminationKey, err)
		return fmt.Errorf("redis error checking elimination status: %w", err)
	}
	if isEliminated {
		log.Printf("[AnswerProcessor] Пользователь #%d уже выбыл из викторины #%d (проверено в начале)", userID, quizID)
		ap.sendEliminationNotification(userID, quizID, "already_eliminated")
		return fmt.Errorf("user is eliminated from this quiz")
	}

	// === 2. ПРОВЕРКА ВРЕМЕНИ И КОРРЕКТНОСТИ ===

	// Получаем время начала вопроса
	if questionStartTimeMs == 0 {
		log.Printf("[AnswerProcessor] CRITICAL: Время начала для вопроса #%d не найдено в состоянии викторины #%d", questionID, quizID)
		return fmt.Errorf("internal error: question start time not found in state")
	}

	// Фиксируем серверное время получения
	serverReceiveTimeMs := time.Now().UnixNano() / int64(time.Millisecond)
	// Рассчитываем время ответа
	responseTimeMs := serverReceiveTimeMs - questionStartTimeMs
	if responseTimeMs < 0 {
		responseTimeMs = 0
	}

	// Проверяем лимит времени
	timeLimitMs := int64(question.TimeLimitSec * 1000)
	isTimeLimitExceeded := responseTimeMs > timeLimitMs
	isReceivedTooLate := serverReceiveTimeMs > (questionStartTimeMs + timeLimitMs)
	if isReceivedTooLate {
		log.Printf("[AnswerProcessor] Ответ от User #%d на Q #%d получен ПОСЛЕ дедлайна.", userID, questionID)
		isTimeLimitExceeded = true // Гарантируем статус просроченного
	}

	// Проверяем правильность ответа
	isCorrect := question.IsCorrect(selectedOption)
	correctOption := question.CorrectOption
	score := question.CalculatePoints(isCorrect, responseTimeMs)

	// Определяем, должен ли пользователь выбыть СЕЙЧАС
	userShouldBeEliminated := !isCorrect || isTimeLimitExceeded
	eliminationReason := ""
	if userShouldBeEliminated {
		if !isCorrect {
			eliminationReason = "incorrect_answer"
		} else {
			eliminationReason = "time_exceeded"
		}
		log.Printf("[AnswerProcessor] Пользователь #%d должен выбыть из викторины #%d. Причина: %s", userID, quizID, eliminationReason)
	}

	// === 3. СОХРАНЕНИЕ ОТВЕТА (DB First) ===

	// Создаем запись об ответе (ПОКА НЕ СОХРАНЯЕМ)
	userAnswer := &entity.UserAnswer{
		UserID:            userID,
		QuizID:            quizID,
		QuestionID:        questionID,
		SelectedOption:    selectedOption,
		IsCorrect:         isCorrect,
		ResponseTimeMs:    responseTimeMs,
		Score:             score,
		IsEliminated:      userShouldBeEliminated, // Записываем, должен ли он выбыть ПОСЛЕ этого ответа
		EliminationReason: eliminationReason,
		// CreatedAt будет установлен GORM
	}

	// Пытаемся сохранить ответ в БД
	err = ap.deps.ResultRepo.SaveUserAnswer(userAnswer)
	if err != nil {
		// Проверяем ошибку уникального ключа (дубликат ответа)
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // 23505 - unique_violation
			log.Printf("[AnswerProcessor] Пользователь #%d уже отвечал на вопрос #%d викторины #%d (определено по DB unique constraint)", userID, questionID, quizID)
			return fmt.Errorf("user already answered this question")
		}

		// Другая ошибка БД при сохранении ответа
		log.Printf("[AnswerProcessor] CRITICAL: Ошибка при сохранении ответа пользователя #%d на вопрос #%d: %v",
			userID, questionID, err)
		return fmt.Errorf("failed to save user answer: %w", err)
	}

	// === 4. ПОСТ-ОБРАБОТКА (ПОСЛЕ УСПЕШНОГО СОХРАНЕНИЯ В БД) ===

	log.Printf("[AnswerProcessor] Ответ User #%d на Q #%d успешно сохранен в БД.", userID, questionID)

	// Устанавливаем статус выбывшего в Redis, ЕСЛИ он должен выбыть
	if userShouldBeEliminated {
		if errCache := ap.deps.CacheRepo.Set(eliminationKey, "1", 24*time.Hour); errCache != nil {
			// Логируем ошибку Redis, но не возвращаем ее, т.к. ответ уже сохранен
			log.Printf("[AnswerProcessor] WARNING: Не удалось установить статус выбывшего пользователя #%d в Redis: %v", userID, errCache)
		}
		// Отправляем уведомление о выбывании
		ap.sendEliminationNotification(userID, quizID, eliminationReason)
	}

	// Опционально: Устанавливаем флаг, что ответ на этот вопрос дан (для QM)
	answerKey := fmt.Sprintf("quiz:%d:user:%d:question:%d", quizID, userID, questionID)
	if errCache := ap.deps.CacheRepo.Set(answerKey, "1", 1*time.Hour); errCache != nil {
		log.Printf("[AnswerProcessor] WARNING: Не удалось установить флаг ответа в Redis для user #%d, question #%d: %v", userID, questionID, errCache)
	}

	// Отправляем результат пользователю
	answerResultEvent := map[string]interface{}{
		"question_id":         questionID,
		"correct_option":      correctOption,
		"your_answer":         selectedOption,
		"is_correct":          isCorrect,
		"points_earned":       score,
		"time_taken_ms":       responseTimeMs,
		"is_eliminated":       userShouldBeEliminated,
		"elimination_reason":  eliminationReason,
		"time_limit_exceeded": isTimeLimitExceeded,
	}
	if errSend := ap.deps.WSManager.SendEventToUser(fmt.Sprintf("%d", userID), "quiz:answer_result", answerResultEvent); errSend != nil {
		log.Printf("[AnswerProcessor] Ошибка при отправке результата ответа пользователю #%d: %v", userID, errSend)
		// Не возвращаем ошибку, так как ответ уже сохранен
	} else {
		log.Printf("[AnswerProcessor] Успешно обработан и отправлен результат для User #%d на Q #%d (Quiz #%d). Выбыл: %t",
			userID, questionID, quizID, userShouldBeEliminated)
	}

	return nil
}

// HandleReadyEvent обрабатывает событие готовности пользователя
func (ap *AnswerProcessor) HandleReadyEvent(ctx context.Context, userID uint, quizID uint) error {
	log.Printf("[AnswerProcessor] Пользователь #%d отметился как готовый к викторине #%d", userID, quizID)

	// Создаем ключ для Redis и сохраняем информацию о готовности
	readyKey := fmt.Sprintf("quiz:%d:ready_users", quizID)
	userReadyKey := fmt.Sprintf("%s:%d", readyKey, userID)

	if err := ap.deps.CacheRepo.Set(userReadyKey, "1", time.Hour); err != nil {
		log.Printf("[AnswerProcessor] Ошибка при сохранении готовности пользователя #%d к викторине #%d: %v",
			userID, quizID, err)
		return fmt.Errorf("failed to save ready status: %w", err)
	}

	// Отправляем информацию о готовности пользователя всем участникам
	fullEvent := map[string]interface{}{
		"type": "quiz:user_ready",
		"data": map[string]interface{}{
			"user_id": userID,
			"quiz_id": quizID,
			"status":  "ready",
		},
	}

	if err := ap.deps.WSManager.BroadcastEventToQuiz(quizID, fullEvent); err != nil {
		log.Printf("[AnswerProcessor] Ошибка при отправке события готовности пользователя #%d к викторине #%d: %v",
			userID, quizID, err)
		return fmt.Errorf("failed to broadcast ready event: %w", err)
	}

	log.Printf("[AnswerProcessor] Успешно отправлено событие о готовности пользователя #%d к викторине #%d",
		userID, quizID)

	return nil
}

// Новый вспомогательный метод для отправки уведомления о выбывании
func (ap *AnswerProcessor) sendEliminationNotification(userID uint, quizID uint, reason string) {
	eliminationEvent := map[string]interface{}{
		"quiz_id": quizID,
		"user_id": userID, // Включаем UserID, чтобы клиент мог это проверить
		"reason":  reason,
		"message": "Вы выбыли из викторины и можете только наблюдать",
	}

	if err := ap.deps.WSManager.SendEventToUser(fmt.Sprintf("%d", userID), "quiz:elimination", eliminationEvent); err != nil {
		log.Printf("[AnswerProcessor] Ошибка при отправке уведомления о выбывании пользователю #%d: %v", userID, err)
	}
}
