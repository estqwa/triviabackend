package quizmanager

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/yourusername/trivia-api/internal/domain/entity"
)

// Scheduler отвечает за планирование и отмену викторин
type Scheduler struct {
	// Настройки
	config *Config

	// Зависимости
	deps *Dependencies

	// Внутреннее состояние
	quizCancels sync.Map // map[uint]context.CancelFunc

	// Канал для сигнализации о запуске викторины
	quizStartCh chan uint
}

// NewScheduler создает новый планировщик викторин
func NewScheduler(config *Config, deps *Dependencies) *Scheduler {
	return &Scheduler{
		config:      config,
		deps:        deps,
		quizStartCh: make(chan uint, 10), // Буферизованный канал для событий запуска
	}
}

// GetQuizStartChannel возвращает канал для уведомлений о запуске викторин
func (s *Scheduler) GetQuizStartChannel() <-chan uint {
	return s.quizStartCh
}

// ScheduleQuiz планирует запуск викторины в заданное время
func (s *Scheduler) ScheduleQuiz(ctx context.Context, quizID uint, scheduledTime time.Time) error {
	// Сразу проверяем, что время в будущем
	if scheduledTime.Before(time.Now()) {
		return fmt.Errorf("ошибка: scheduled time is in the past")
	}

	// Получаем викторину
	quiz, err := s.deps.QuizRepo.GetWithQuestions(quizID)
	if err != nil {
		return err
	}

	// Проверяем, что у викторины есть вопросы
	if len(quiz.Questions) == 0 {
		return fmt.Errorf("quiz has no questions")
	}

	// Устанавливаем время запуска
	quiz.ScheduledTime = scheduledTime
	quiz.Status = "scheduled"

	// Сохраняем изменения
	if err := s.deps.QuizRepo.Update(quiz); err != nil {
		return err
	}

	// Создаем новый контекст для этой викторины с возможностью отмены
	quizCtx, quizCancel := context.WithCancel(ctx)

	// Сохраняем функцию отмены
	s.quizCancels.Store(quizID, quizCancel)

	// Запускаем последовательность событий в фоновом режиме
	go s.runQuizSequence(quizCtx, quiz)

	log.Printf("[Scheduler] Викторина #%d запланирована на %v", quizID, scheduledTime)
	return nil
}

// CancelQuiz отменяет запланированную викторину
func (s *Scheduler) CancelQuiz(quizID uint) error {
	// Получаем викторину
	quiz, err := s.deps.QuizRepo.GetByID(quizID)
	if err != nil {
		return err
	}

	// Проверяем, что викторина запланирована
	if !quiz.IsScheduled() {
		return fmt.Errorf("quiz is not in scheduled state")
	}

	// Получаем функцию отмены из map
	cancel, ok := s.quizCancels.Load(quizID)
	if !ok {
		log.Printf("[Scheduler] Предупреждение: функция отмены для викторины #%d не найдена", quizID)
		// Продолжаем, чтобы обновить статус в БД
	} else {
		// Вызываем функцию отмены
		cancel.(context.CancelFunc)()
		// Удаляем из map
		s.quizCancels.Delete(quizID)
		log.Printf("[Scheduler] Таймеры для викторины #%d отменены", quizID)
	}

	// Обновляем статус в БД
	if err := s.deps.QuizRepo.UpdateStatus(quizID, "cancelled"); err != nil {
		return err
	}

	// Отправляем уведомление пользователям
	cancelEvent := map[string]interface{}{
		"quiz_id": quizID,
		"message": "Quiz has been cancelled",
	}
	s.deps.WSManager.BroadcastEvent("quiz:cancelled", cancelEvent)

	log.Printf("[Scheduler] Викторина #%d отменена", quizID)
	return nil
}

// runQuizSequence выполняет последовательность событий викторины
func (s *Scheduler) runQuizSequence(ctx context.Context, quiz *entity.Quiz) {
	defer func() {
		// Удаляем функцию отмены из map при завершении последовательности
		s.quizCancels.Delete(quiz.ID)
	}()

	// Таймауты для каждого события
	autoFillTime := quiz.ScheduledTime.Add(-time.Duration(s.config.AutoFillThreshold) * time.Minute)
	announcementTime := quiz.ScheduledTime.Add(-time.Duration(s.config.AnnouncementMinutes) * time.Minute)
	waitingRoomTime := quiz.ScheduledTime.Add(-time.Duration(s.config.WaitingRoomMinutes) * time.Minute)
	countdownTime := quiz.ScheduledTime.Add(-time.Duration(s.config.CountdownSeconds) * time.Second)

	// Планируем автозаполнение вопросов, если время еще не наступило
	if autoFillTime.After(time.Now()) {
		timeToAutoFill := time.Until(autoFillTime)
		log.Printf("[Scheduler] Викторина #%d: планирую автозаполнение через %v", quiz.ID, timeToAutoFill)

		select {
		case <-time.After(timeToAutoFill):
			// Запускаем автозаполнение
			s.triggerAutoFill(ctx, quiz.ID)
		case <-ctx.Done():
			log.Printf("[Scheduler] Викторина #%d: автозаполнение отменено", quiz.ID)
			return
		}
	}

	// Планируем анонс, если время еще не наступило
	if announcementTime.After(time.Now()) {
		timeToAnnouncement := time.Until(announcementTime)
		log.Printf("[Scheduler] Викторина #%d: планирую анонс через %v", quiz.ID, timeToAnnouncement)

		select {
		case <-time.After(timeToAnnouncement):
			// Отправляем анонс
			s.triggerAnnouncement(ctx, quiz)
		case <-ctx.Done():
			log.Printf("[Scheduler] Викторина #%d: анонс отменен", quiz.ID)
			return
		}
	}

	// Планируем открытие зала ожидания, если время еще не наступило
	if waitingRoomTime.After(time.Now()) {
		timeToWaitingRoom := time.Until(waitingRoomTime)
		log.Printf("[Scheduler] Викторина #%d: планирую открытие зала ожидания через %v", quiz.ID, timeToWaitingRoom)

		select {
		case <-time.After(timeToWaitingRoom):
			// Открываем зал ожидания
			s.triggerWaitingRoom(ctx, quiz)
		case <-ctx.Done():
			log.Printf("[Scheduler] Викторина #%d: открытие зала ожидания отменено", quiz.ID)
			return
		}
	}

	// Планируем обратный отсчет, если время еще не наступило
	if countdownTime.After(time.Now()) {
		timeToCountdown := time.Until(countdownTime)
		log.Printf("[Scheduler] Викторина #%d: планирую обратный отсчет через %v", quiz.ID, timeToCountdown)

		select {
		case <-time.After(timeToCountdown):
			// Запускаем обратный отсчет
			s.triggerCountdown(ctx, quiz)
		case <-ctx.Done():
			log.Printf("[Scheduler] Викторина #%d: обратный отсчет отменен", quiz.ID)
			return
		}
	} else if time.Until(quiz.ScheduledTime) > 0 {
		// Если время для отсчета уже прошло, но викторина еще не должна начаться,
		// ждем точного времени начала
		timeToStart := time.Until(quiz.ScheduledTime)
		log.Printf("[Scheduler] Викторина #%d: слишком поздно для отсчета, ожидание начала (%v)", quiz.ID, timeToStart)

		select {
		case <-time.After(timeToStart):
			// Сигнализируем о начале викторины
			s.triggerQuizStart(ctx, quiz)
		case <-ctx.Done():
			log.Printf("[Scheduler] Викторина #%d: запуск отменен", quiz.ID)
			return
		}
	} else {
		// Если время уже прошло, сразу запускаем викторину
		log.Printf("[Scheduler] Викторина #%d: время начала уже прошло, запускаю немедленно", quiz.ID)
		s.triggerQuizStart(ctx, quiz)
	}
}

// triggerAutoFill запускает автозаполнение вопросов
func (s *Scheduler) triggerAutoFill(ctx context.Context, quizID uint) {
	log.Printf("[Scheduler] Запуск автозаполнения вопросов для викторины #%d", quizID)

	// Этот метод будет реализован в QuestionManager
	// Здесь выполняем только оповещение других компонентов
	autoFillEvent := map[string]interface{}{
		"quiz_id": quizID,
		"action":  "auto_fill",
	}
	s.deps.WSManager.BroadcastEvent("admin:quiz_action", autoFillEvent)
}

// triggerAnnouncement отправляет анонс о предстоящей викторине
func (s *Scheduler) triggerAnnouncement(ctx context.Context, quiz *entity.Quiz) {
	log.Printf("[Scheduler] Отправка анонса для викторины #%d", quiz.ID)

	// Рассчитываем оставшееся время до старта викторины
	timeToStart := time.Until(quiz.ScheduledTime)

	announcementData := map[string]interface{}{
		"quiz_id":          quiz.ID,
		"title":            quiz.Title,
		"description":      quiz.Description,
		"scheduled_time":   quiz.ScheduledTime,
		"question_count":   quiz.QuestionCount,
		"minutes_to_start": int(timeToStart.Minutes()),
	}

	// Используем новую сигнатуру
	fullEvent := map[string]interface{}{ // Или websocket.Event
		"type": "quiz:announcement",
		"data": announcementData,
	}
	s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, fullEvent)
}

// triggerWaitingRoom открывает зал ожидания для викторины
func (s *Scheduler) triggerWaitingRoom(ctx context.Context, quiz *entity.Quiz) {
	log.Printf("[Scheduler] Открытие зала ожидания для викторины #%d", quiz.ID)

	// Рассчитываем оставшееся время до старта викторины
	timeToStart := time.Until(quiz.ScheduledTime)

	waitingRoomData := map[string]interface{}{
		"quiz_id":           quiz.ID,
		"title":             quiz.Title,
		"description":       quiz.Description,
		"scheduled_time":    quiz.ScheduledTime,
		"question_count":    quiz.QuestionCount,
		"starts_in_seconds": int(timeToStart.Seconds()),
	}

	// Используем новую сигнатуру
	fullEvent := map[string]interface{}{ // Или websocket.Event
		"type": "quiz:waiting_room",
		"data": waitingRoomData,
	}
	s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, fullEvent)
}

// triggerCountdown запускает обратный отсчет для викторины
func (s *Scheduler) triggerCountdown(ctx context.Context, quiz *entity.Quiz) {
	log.Printf("[Scheduler] Запуск обратного отсчета для викторины #%d", quiz.ID)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			remainingTime := time.Until(quiz.ScheduledTime)
			secondsLeft := int(remainingTime.Seconds())

			if secondsLeft <= 0 {
				log.Printf("[Scheduler] Обратный отсчет завершен для викторины #%d, запуск викторины", quiz.ID)
				s.triggerQuizStart(ctx, quiz)
				return
			}

			log.Printf("[Scheduler] Обратный отсчет викторины #%d: %d сек.", quiz.ID, secondsLeft)
			countdownData := map[string]interface{}{
				"quiz_id":      quiz.ID,
				"seconds_left": secondsLeft,
			}
			// s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, "quiz:countdown", countdownData)
			// Используем новую сигнатуру
			fullEvent := map[string]interface{}{ // Или websocket.Event
				"type": "quiz:countdown",
				"data": countdownData,
			}
			s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, fullEvent)

		case <-ctx.Done():
			log.Printf("[Scheduler] Обратный отсчет для викторины #%d отменен", quiz.ID)
			return
		}
	}
}

// triggerQuizStart запускает викторину
func (s *Scheduler) triggerQuizStart(ctx context.Context, quiz *entity.Quiz) {
	log.Printf("[Scheduler] Запуск викторины #%d", quiz.ID)

	// Обновляем статус викторины в БД
	if err := s.deps.QuizRepo.UpdateStatus(quiz.ID, "in_progress"); err != nil {
		log.Printf("[Scheduler] Ошибка при обновлении статуса викторины #%d на in_progress: %v", quiz.ID, err)
		// Продолжаем, т.к. отмена уже невозможна
	}

	// Отправляем событие запуска
	startEvent := map[string]interface{}{
		"quiz_id":        quiz.ID,
		"title":          quiz.Title,
		"question_count": quiz.QuestionCount,
	}
	// s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, "quiz:start", startEvent)
	// Используем новую сигнатуру
	fullEvent := map[string]interface{}{ // Или websocket.Event
		"type": "quiz:start",
		"data": startEvent,
	}
	s.deps.WSManager.BroadcastEventToQuiz(quiz.ID, fullEvent)
	log.Printf("[Scheduler] Уведомление о запуске викторины #%d отправлено", quiz.ID)

	// Сигнализируем QuizManager о запуске викторины
	// Используем неблокирующую отправку на случай, если канал переполнен
	select {
	case s.quizStartCh <- quiz.ID:
		log.Printf("[Scheduler] Сигнал о запуске викторины #%d отправлен в QuizManager", quiz.ID)
	default:
		log.Printf("[Scheduler] Предупреждение: не удалось отправить сигнал о запуске викторины #%d в QuizManager (канал переполнен?)", quiz.ID)
	}
}
