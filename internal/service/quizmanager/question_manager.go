package quizmanager

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	"github.com/yourusername/trivia-api/internal/handler/helper"
)

// QuestionManager отвечает за управление вопросами, их отправку и таймеры
type QuestionManager struct {
	// Настройки
	config *Config

	// Зависимости
	deps *Dependencies

	// Канал для сигнализации о завершении вопроса
	questionDoneCh chan struct{}
}

// NewQuestionManager создает новый менеджер вопросов
func NewQuestionManager(config *Config, deps *Dependencies) *QuestionManager {
	return &QuestionManager{
		config:         config,
		deps:           deps,
		questionDoneCh: make(chan struct{}, 1),
	}
}

// QuestionDone возвращает канал для уведомления о завершении вопроса
func (qm *QuestionManager) QuestionDone() <-chan struct{} {
	return qm.questionDoneCh
}

// AutoFillQuizQuestions автоматически добавляет случайные вопросы в викторину,
// если их количество меньше установленного лимита
func (qm *QuestionManager) AutoFillQuizQuestions(ctx context.Context, quizID uint) error {
	log.Printf("[QuestionManager] Начинаю автозаполнение вопросов для викторины #%d", quizID)

	// Получаем викторину с вопросами
	quiz, err := qm.deps.QuizRepo.GetWithQuestions(quizID)
	if err != nil {
		return fmt.Errorf("не удалось получить викторину: %w", err)
	}

	// Проверяем, нужно ли добавлять вопросы
	currentCount := len(quiz.Questions)
	if currentCount >= qm.config.MaxQuestionsPerQuiz {
		log.Printf("[QuestionManager] Викторина #%d уже имеет максимальное количество вопросов (%d/%d), автозаполнение не требуется",
			quizID, currentCount, qm.config.MaxQuestionsPerQuiz)
		return nil // Уже достаточно вопросов
	}

	// Определяем, сколько вопросов нужно добавить
	neededQuestions := qm.config.MaxQuestionsPerQuiz - currentCount
	log.Printf("[QuestionManager] Викторина #%d имеет %d/%d вопросов, требуется добавить еще %d",
		quizID, currentCount, qm.config.MaxQuestionsPerQuiz, neededQuestions)

	// Создаем карту существующих ID вопросов для исключения повторов
	existingQuestionIDs := make(map[uint]bool)
	for _, q := range quiz.Questions {
		existingQuestionIDs[q.ID] = true
	}

	// Получаем случайные вопросы из базы данных
	// Запрашиваем больше вопросов, чем нужно, чтобы иметь запас для фильтрации
	randomQuestions, err := qm.deps.QuestionRepo.GetRandomQuestions(neededQuestions * 3)
	if err != nil {
		return fmt.Errorf("не удалось получить случайные вопросы: %w", err)
	}

	// Если нет доступных вопросов, возвращаем ошибку
	if len(randomQuestions) == 0 {
		return fmt.Errorf("не удалось найти вопросы для автозаполнения")
	}

	// Фильтруем вопросы, исключая те, которые уже есть в викторине
	availableQuestions := make([]entity.Question, 0)
	for _, q := range randomQuestions {
		if !existingQuestionIDs[q.ID] && q.QuizID != quizID {
			availableQuestions = append(availableQuestions, q)
		}
	}

	// Проверяем, есть ли достаточно доступных вопросов
	if len(availableQuestions) == 0 {
		return fmt.Errorf("нет доступных вопросов для автозаполнения")
	}

	// Ограничиваем количество добавляемых вопросов доступным количеством
	if neededQuestions > len(availableQuestions) {
		neededQuestions = len(availableQuestions)
		log.Printf("[QuestionManager] Доступно только %d вопросов для добавления", neededQuestions)
	}

	// Выбираем нужное количество вопросов
	selectedQuestions := availableQuestions[:neededQuestions]

	// Подготавливаем вопросы для добавления в викторину
	questionsToAdd := make([]entity.Question, len(selectedQuestions))
	for i, q := range selectedQuestions {
		// Создаем новый вопрос с корректными полями
		questionsToAdd[i] = entity.Question{
			QuizID:        quizID,
			Text:          q.Text,
			Options:       make(entity.StringArray, len(q.Options)),
			CorrectOption: q.CorrectOption,
			TimeLimitSec:  q.TimeLimitSec,
			PointValue:    q.PointValue,
		}

		// Используем встроенную функцию copy вместо цикла для копирования данных слайса
		copy(questionsToAdd[i].Options, q.Options)
	}

	// Добавляем вопросы к викторине
	if err := qm.deps.QuestionRepo.CreateBatch(questionsToAdd); err != nil {
		return fmt.Errorf("не удалось добавить вопросы: %w", err)
	}

	// Обновляем счетчик вопросов в викторине
	quiz.QuestionCount += len(questionsToAdd)
	if err := qm.deps.QuizRepo.Update(quiz); err != nil {
		return fmt.Errorf("не удалось обновить счетчик вопросов: %w", err)
	}

	log.Printf("[QuestionManager] Успешно добавлено %d вопросов в викторину #%d",
		len(questionsToAdd), quizID)

	return nil
}

// RunQuizQuestions последовательно отправляет вопросы и управляет таймерами
func (qm *QuestionManager) RunQuizQuestions(ctx context.Context, quizState *ActiveQuizState) error {
	log.Printf("[QuestionManager] Начинаю процесс отправки вопросов для викторины #%d. Всего вопросов: %d",
		quizState.Quiz.ID, len(quizState.Quiz.Questions))

	// Создаем контекст для этой конкретной викторины
	quizCtx, quizCancel := context.WithCancel(ctx)
	defer quizCancel() // Гарантируем отмену при выходе из функции

	// WaitGroup для синхронизации всех таймеров вопросов
	var timerWg sync.WaitGroup

	// Отправляем сообщение о начале викторины
	startEvent := map[string]interface{}{
		"quiz_id":        quizState.Quiz.ID,
		"title":          quizState.Quiz.Title,
		"question_count": len(quizState.Quiz.Questions),
	}

	// Используем новую сигнатуру
	startFullEvent := map[string]interface{}{"type": "quiz:start", "data": startEvent}
	err := qm.deps.WSManager.BroadcastEventToQuiz(quizState.Quiz.ID, startFullEvent)
	if err != nil {
		log.Printf("[QuestionManager] ОШИБКА при отправке события quiz:start для викторины #%d: %v",
			quizState.Quiz.ID, err)
		// Продолжаем, несмотря на ошибку
	}

	for i, question := range quizState.Quiz.Questions {
		// Устанавливаем текущий вопрос в состоянии
		quizState.SetCurrentQuestion(&question, i+1)

		// Добавляем задержку перед отправкой вопроса для синхронизации с фронтендом
		time.Sleep(time.Duration(qm.config.QuestionDelayMs) * time.Millisecond)

		// Получить точное время отправки вопроса
		sendTimeMs := time.Now().UnixNano() / int64(time.Millisecond)

		// ===>>> ДОБАВИТЬ ВЫЗОВ <<<===
		quizState.SetCurrentQuestionStartTime(sendTimeMs)
		// ===>>> КОНЕЦ ИЗМЕНЕНИЯ <<<===

		// Отправляем вопрос всем участникам
		questionEvent := map[string]interface{}{
			"question_id":      question.ID,
			"quiz_id":          quizState.Quiz.ID,
			"number":           i + 1,
			"text":             question.Text,
			"options":          helper.ConvertOptionsToObjects(question.Options),
			"time_limit":       question.TimeLimitSec,
			"total_questions":  len(quizState.Quiz.Questions),
			"start_time":       sendTimeMs,
			"server_timestamp": sendTimeMs,
		}

		// Отправка с повторными попытками при ошибке
		if err := qm.sendEventWithRetry(quizCtx, quizState.Quiz.ID, "quiz:question", questionEvent); err != nil {
			// Логируем фатальную ошибку отправки вопроса и выходим
			log.Printf("[QuestionManager] ФАТАЛЬНАЯ ОШИБКА при отправке вопроса #%d для викторины #%d: %v. Прерывание викторины.",
				question.ID, quizState.Quiz.ID, err)
			return err // Прерываем выполнение викторины
		}

		// Сохраняем время начала вопроса для подсчета времени ответа
		questionStartKey := fmt.Sprintf("question:%d:start_time", question.ID)
		// Логируем ошибку Redis, но не прерываем викторину
		if err := qm.deps.CacheRepo.Set(questionStartKey, fmt.Sprintf("%d", sendTimeMs), time.Hour); err != nil {
			log.Printf("[QuestionManager] WARNING: Не удалось сохранить время начала вопроса #%d в Redis: %v", question.ID, err)
		}

		// Запускаем таймер для вопроса
		timeLimit := time.Duration(question.TimeLimitSec) * time.Second
		endTime := time.Now().Add(timeLimit)
		timerWg.Add(1)
		go qm.runQuestionTimer(quizCtx, quizState.Quiz, &question, i+1, endTime, &timerWg)

		// Ждем завершения времени на вопрос
		log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: Ожидание завершения таймера (%v)...", quizState.Quiz.ID, question.ID, timeLimit)
		select {
		case <-time.After(timeLimit):
			// Продолжаем
			log.Printf("[QuestionManager] Викторина #%d, Вопрос #%d (%d из %d): Время истекло. Начинаем проверку не ответивших.",
				quizState.Quiz.ID, question.ID, i+1, len(quizState.Quiz.Questions))
		case <-quizCtx.Done():
			log.Printf("[QuestionManager] Процесс викторины #%d был прерван на вопросе #%d",
				quizState.Quiz.ID, i+1)
			return nil
		}

		// ===>>> ЛОГИКА ВЫБЫВАНИЯ ПРИ ОТСУТСТВИИ ОТВЕТА <<<===
		// Получаем список всех активных (не выбывших) пользователей на данный момент
		log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: Вызов GetActiveSubscribers...", quizState.Quiz.ID, question.ID)
		activeUserIDs, err := qm.deps.WSManager.GetActiveSubscribers(quizState.Quiz.ID)
		log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: GetActiveSubscribers вернул %d ID, ошибка: %v", quizState.Quiz.ID, question.ID, len(activeUserIDs), err)

		if err != nil {
			log.Printf("[QuestionManager] WARNING: Не удалось получить список активных подписчиков для викторины #%d: %v", quizState.Quiz.ID, err)
		} else {
			// Для каждого активного пользователя проверяем, ответил ли он
			for _, userID := range activeUserIDs {
				answerKey := fmt.Sprintf("quiz:%d:user:%d:question:%d", quizState.Quiz.ID, userID, question.ID)
				eliminationKey := fmt.Sprintf("quiz:%d:eliminated:%d", quizState.Quiz.ID, userID)

				log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: Проверка ответа для User #%d (Ключ: %s)", quizState.Quiz.ID, question.ID, userID, answerKey)
				answered, existsErr := qm.deps.CacheRepo.Exists(answerKey)
				if existsErr != nil {
					log.Printf("[QuestionManager][WARN] Ошибка Redis при проверке ключа ответа %s: %v", answerKey, existsErr)
				}

				if !answered {
					// Пользователь не ответил вовремя, проверяем, не выбыл ли он УЖЕ по другой причине
					log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: User #%d НЕ ответил. Проверка ключа выбывания %s...", quizState.Quiz.ID, question.ID, userID, eliminationKey)
					alreadyEliminated, elimExistsErr := qm.deps.CacheRepo.Exists(eliminationKey)
					if elimExistsErr != nil {
						log.Printf("[QuestionManager][WARN] Ошибка Redis при проверке ключа выбывания %s: %v", eliminationKey, elimExistsErr)
					}

					if !alreadyEliminated {
						// Пользователь активен, но не ответил -> выбывание
						eliminationReason := "no_answer_timeout"
						log.Printf("[QuestionManager] Пользователь #%d выбывает из викторины #%d. Причина: %s (Вопрос #%d). Установка ключа %s...", userID, quizState.Quiz.ID, eliminationReason, question.ID, eliminationKey)

						// Устанавливаем статус выбывшего в Redis
						if errSet := qm.deps.CacheRepo.Set(eliminationKey, "1", 24*time.Hour); errSet != nil {
							log.Printf("[QuestionManager] WARNING: Не удалось установить ключ выбывания %s в Redis: %v", eliminationKey, errSet)
						} else {
							log.Printf("[QuestionManager][DEBUG] Успешно установлен ключ выбывания %s для User #%d", eliminationKey, userID)
						}

						// Отправляем уведомление о выбывании (используем метод из AnswerProcessor или создаем аналогичный)
						// Нужно убедиться, что метод sendEliminationNotification доступен или перенести/дублировать логику
						qm.sendEliminationNotification(userID, quizState.Quiz.ID, eliminationReason) // Потребуется добавить этот метод в QuestionManager или сделать его общим

					} else {
						log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: User #%d не ответил, но УЖЕ был выбывший (ключ %s существует).", quizState.Quiz.ID, question.ID, userID, eliminationKey)
					}
				} else {
					log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: User #%d УСПЕЛ ответить (ключ %s существует).", quizState.Quiz.ID, question.ID, userID, answerKey)
				}
			}
		}
		// ===>>> КОНЕЦ ЛОГИКИ ВЫБЫВАНИЯ <<<===

		// Добавляем задержку перед отправкой правильного ответа
		time.Sleep(time.Duration(qm.config.AnswerRevealDelayMs) * time.Millisecond)

		// Отправляем правильный ответ всем оставшимся участникам
		log.Printf("[QuestionManager][DEBUG] Викторина #%d, Вопрос #%d: Отправка события quiz:answer_reveal...", quizState.Quiz.ID, question.ID)
		revealEvent := map[string]interface{}{
			"question_id":    question.ID,
			"correct_option": question.CorrectOption,
		}

		// Отправка с повторными попытками
		// Логируем ошибку, но не прерываем викторину, т.к. ответ уже не критичен
		if err := qm.sendEventWithRetry(quizCtx, quizState.Quiz.ID, "quiz:answer_reveal", revealEvent); err != nil {
			log.Printf("[QuestionManager] WARNING: Не удалось отправить ответ на вопрос #%d: %v", question.ID, err)
		}

		// Увеличиваем паузу между вопросами
		if i < len(quizState.Quiz.Questions)-1 {
			pauseTime := time.Duration(qm.config.InterQuestionDelayMs) * time.Millisecond
			log.Printf("[QuestionManager] Пауза %v между вопросами %d и %d",
				pauseTime, i+1, i+2)

			select {
			case <-time.After(pauseTime):
				// Продолжаем
			case <-quizCtx.Done():
				return nil
			}
		}
	}

	// Дожидаемся завершения всех таймеров перед завершением викторины
	timerWg.Wait()

	// Очищаем текущий вопрос
	quizState.ClearCurrentQuestion()

	// Отправляем сигнал о завершении всех вопросов
	select {
	case qm.questionDoneCh <- struct{}{}:
		log.Printf("[QuestionManager] Сигнал о завершении вопросов для викторины #%d отправлен", quizState.Quiz.ID)
	default:
		log.Printf("[QuestionManager] Сигнал о завершении вопросов уже был отправлен для викторины #%d", quizState.Quiz.ID)
	}

	return nil
}

// Новый метод для отправки уведомления о выбывании из QuestionManager
func (qm *QuestionManager) sendEliminationNotification(userID uint, quizID uint, reason string) {
	eliminationEvent := map[string]interface{}{
		"quiz_id": quizID,
		"user_id": userID,
		"reason":  reason,
		"message": "Вы выбыли из викторины, так как не ответили вовремя.",
	}
	// Убираем неиспользуемый fullEvent
	// Используем WSManager напрямую
	// Исправленный вызов: передаем тип и данные отдельно
	eventType := "quiz:elimination"
	if err := qm.deps.WSManager.SendEventToUser(fmt.Sprintf("%d", userID), eventType, eliminationEvent); err != nil {
		log.Printf("[QuestionManager] Ошибка при отправке уведомления о выбывании (no_answer) пользователю #%d: %v", userID, err)
	}
}

// runQuestionTimer запускает таймер для вопроса и отправляет обновления
func (qm *QuestionManager) runQuestionTimer(
	ctx context.Context,
	quiz *entity.Quiz,
	question *entity.Question,
	questionNumber int,
	endTime time.Time,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	// Создаем отдельный контекст для этого таймера
	timerCtx, timerCancel := context.WithCancel(ctx)
	defer timerCancel()

	// Отправляем обновления таймера каждую секунду
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			remaining := int(time.Until(endTime).Seconds())
			if remaining <= 0 {
				// Время вышло
				log.Printf("[QuestionManager] Время на вопрос #%d (%d из %d) викторины #%d истекло",
					question.ID, questionNumber, len(quiz.Questions), quiz.ID)
				return
			}

			// Отправляем обновление таймера
			timerData := map[string]interface{}{
				"question_id":       question.ID,
				"remaining_seconds": remaining,
				"server_timestamp":  time.Now().UnixNano() / int64(time.Millisecond),
			}
			timerFullEvent := map[string]interface{}{
				"type": "quiz:timer",
				"data": timerData,
			}

			// Просто отправляем событие каждую секунду
			if err := qm.deps.WSManager.BroadcastEventToQuiz(quiz.ID, timerFullEvent); err != nil {
				log.Printf("[QuestionManager] ОШИБКА при отправке таймера для вопроса #%d: %v", question.ID, err)
			} else {
				log.Printf("[QuestionManager] Таймер вопроса #%d (%d из %d): осталось %d секунд",
					question.ID, questionNumber, len(quiz.Questions), remaining)
			}

		case <-timerCtx.Done():
			log.Printf("[QuestionManager] Таймер для вопроса #%d отменен", question.ID)
			return
		}
	}
}

// --- Вспомогательная функция для отправки событий с ретраями ---

// sendEventWithRetry пытается отправить событие через WSManager с заданным количеством попыток.
// Возвращает ошибку, если все попытки неудачны.
func (qm *QuestionManager) sendEventWithRetry(ctx context.Context, quizID uint, eventType string, data map[string]interface{}) error {
	var sendErr error

	// Создаем полное событие для передачи
	fullEvent := map[string]interface{}{
		"type": eventType,
		"data": data,
	}

	for attempts := 0; attempts < qm.config.MaxRetries; attempts++ {
		// Проверяем контекст перед каждой попыткой
		select {
		case <-ctx.Done():
			log.Printf("[QuestionManager] Отправка события %s для викторины #%d отменена контекстом (попытка %d)", eventType, quizID, attempts+1)
			return ctx.Err()
		default:
		}

		sendErr = qm.deps.WSManager.BroadcastEventToQuiz(quizID, fullEvent)
		if sendErr == nil {
			log.Printf("[QuestionManager] Событие %s для викторины #%d успешно отправлено с %d попытки",
				eventType, quizID, attempts+1)
			return nil // Успешно отправлено
		}
		log.Printf("[QuestionManager] ОШИБКА при отправке события %s для викторины #%d (попытка %d): %v",
			eventType, quizID, attempts+1, sendErr)

		// Ожидание перед следующей попыткой с учетом отмены контекста
		select {
		case <-time.After(qm.config.RetryInterval):
			// Продолжаем следующую попытку
		case <-ctx.Done():
			log.Printf("[QuestionManager] Ожидание перед ретраем отправки события %s для викторины #%d отменено контекстом", eventType, quizID)
			return ctx.Err()
		}
	}
	// Если все попытки не удались
	return fmt.Errorf("не удалось отправить событие %s для викторины #%d после %d попыток: %w",
		eventType, quizID, qm.config.MaxRetries, sendErr)
}
