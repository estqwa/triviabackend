package postgres

import (
	"errors"
	"log"

	"gorm.io/gorm"

	"github.com/yourusername/trivia-api/internal/domain/entity"
	apperrors "github.com/yourusername/trivia-api/internal/pkg/errors"
)

// ResultRepo реализует repository.ResultRepository
type ResultRepo struct {
	db *gorm.DB
}

// NewResultRepo создает новый репозиторий результатов
func NewResultRepo(db *gorm.DB) *ResultRepo {
	return &ResultRepo{db: db}
}

// SaveUserAnswer сохраняет ответ пользователя
func (r *ResultRepo) SaveUserAnswer(answer *entity.UserAnswer) error {
	return r.db.Create(answer).Error
}

// GetUserAnswers возвращает все ответы пользователя для конкретной викторины
func (r *ResultRepo) GetUserAnswers(userID uint, quizID uint) ([]entity.UserAnswer, error) {
	var answers []entity.UserAnswer
	err := r.db.Where("user_id = ? AND quiz_id = ?", userID, quizID).
		Order("created_at").
		Find(&answers).Error
	return answers, err
}

// SaveResult сохраняет итоговый результат пользователя
func (r *ResultRepo) SaveResult(result *entity.Result) error {
	return r.db.Create(result).Error
}

// GetQuizResults возвращает все результаты для викторины, отсортированные по очкам, с пагинацией
// ИЗМЕНЕНО: Принимает limit, offset, возвращает total
func (r *ResultRepo) GetQuizResults(quizID uint, limit, offset int) ([]entity.Result, int64, error) {
	var results []entity.Result
	var total int64

	// Используем транзакцию для согласованности чтения данных и общего количества
	tx := r.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()
	if tx.Error != nil {
		return nil, 0, tx.Error
	}

	// Сначала получаем общее количество результатов для данной викторины
	err := tx.Model(&entity.Result{}).Where("quiz_id = ?", quizID).Count(&total).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// Затем получаем результаты для текущей страницы
	// ИЗМЕНЕНИЕ: Сортируем по rank ASC после его расчета
	err = tx.Where("quiz_id = ?", quizID).
		Order("rank ASC, score DESC"). // Сортируем по рангу, затем по очкам для одинаковых рангов
		Limit(limit).
		Offset(offset).
		Find(&results).Error
	if err != nil {
		tx.Rollback()
		return nil, 0, err
	}

	// Коммитим транзакцию
	if err := tx.Commit().Error; err != nil {
		return nil, 0, err
	}

	return results, total, nil
}

// GetAllQuizResults возвращает ВСЕ результаты для викторины, отсортированные по очкам.
// Используется для внутренней логики, где нужна полная картина.
// ИЗМЕНЕНИЕ: Теперь сортирует по rank ASC
func (r *ResultRepo) GetAllQuizResults(quizID uint) ([]entity.Result, error) {
	var results []entity.Result
	// Просто получаем все записи, отсортированные по рангу
	err := r.db.Where("quiz_id = ?", quizID).
		Order("rank ASC, score DESC"). // Сначала ранг, потом очки
		Find(&results).Error
	// Здесь не нужно проверять на ErrRecordNotFound, пустой слайс - валидный результат
	return results, err
}

// GetUserResult возвращает результат пользователя для конкретной викторины
func (r *ResultRepo) GetUserResult(userID uint, quizID uint) (*entity.Result, error) {
	var result entity.Result
	err := r.db.Where("user_id = ? AND quiz_id = ?", userID, quizID).
		First(&result).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperrors.ErrNotFound
		}
		return nil, err
	}
	return &result, nil
}

// GetUserResults возвращает все результаты пользователя с пагинацией
func (r *ResultRepo) GetUserResults(userID uint, limit, offset int) ([]entity.Result, error) {
	var results []entity.Result
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&results).Error
	return results, err
}

// CalculateRanks вычисляет и сохраняет ранги всех участников викторины, используя SQL.
// ВНИМАНИЕ: Эта функция больше НЕ определяет победителей и НЕ рассчитывает призы.
// Она только вычисляет и сохраняет ранг, основываясь на 'score' и 'correct_answers'.
// ИЗМЕНЕНО: Принимает транзакцию tx *gorm.DB
func (r *ResultRepo) CalculateRanks(tx *gorm.DB, quizID uint) error {
	// Используем сырой SQL-запрос для эффективности
	sql := `
	WITH RankedResults AS (
	    SELECT
	        id,
	        RANK() OVER (ORDER BY score DESC, correct_answers DESC) as calculated_rank
	    FROM results
	    WHERE quiz_id = ?
	)
	UPDATE results r
	SET rank = rr.calculated_rank
	FROM RankedResults rr
	WHERE r.id = rr.id AND r.quiz_id = ?;`

	// Выполняем запрос В ПЕРЕДАННОЙ ТРАНЗАКЦИИ
	if err := tx.Exec(sql, quizID, quizID).Error; err != nil {
		log.Printf("Error executing rank calculation SQL for quiz %d within transaction: %v", quizID, err)
		// Не делаем Rollback здесь, т.к. транзакция управляется извне
		return err
	}

	log.Printf("[ResultRepo] Ranks successfully calculated and updated for quiz %d within transaction", quizID)
	return nil // Транзакция будет закоммичена или отменена снаружи
}

// GetQuizUserAnswers возвращает все ответы пользователей для конкретной викторины
func (r *ResultRepo) GetQuizUserAnswers(quizID uint) ([]entity.UserAnswer, error) {
	var answers []entity.UserAnswer
	err := r.db.Where("quiz_id = ?", quizID).Find(&answers).Error
	return answers, err
}

// GetQuizWinners возвращает список победителей викторины
func (r *ResultRepo) GetQuizWinners(quizID uint) ([]entity.Result, error) {
	var winners []entity.Result
	err := r.db.Where("quiz_id = ? AND is_winner = true", quizID).
		Order("rank ASC, score DESC"). // Сортируем победителей по рангу
		Find(&winners).Error
	return winners, err
}

// FindAndUpdateWinners находит победителей, рассчитывает приз и обновляет их статус в БД ВНУТРИ ПЕРЕДАННОЙ ТРАНЗАКЦИИ.
// ИЗМЕНЕНО: Принимает транзакцию tx *gorm.DB.
// ИЗМЕНЕНО: Возвращает слайс ID победителей, приз на человека и ошибку.
func (r *ResultRepo) FindAndUpdateWinners(tx *gorm.DB, quizID uint, questionCount int64, totalPrizeFund int64) ([]uint, int64, error) {
	var winnerCount int64
	var prizePerWinner int64
	winnerIDs := []uint{} // Инициализируем слайс

	// Шаг 1: Найти ID победителей В ПЕРЕДАННОЙ ТРАНЗАКЦИИ
	// Ищем ID победителей (правильные ответы == кол-ву вопросов и не выбыли)
	// Используем Pluck для получения только user_id
	if err := tx.Model(&entity.Result{}).
		Where("quiz_id = ? AND correct_answers = ? AND is_eliminated = false", quizID, questionCount).
		Pluck("user_id", &winnerIDs).Error; err != nil { // Получаем user_id, а не id результата
		log.Printf("Error finding winner user IDs for quiz %d within transaction: %v", quizID, err)
		// Не откатываем, транзакция управляется извне
		return nil, 0, err
	}

	winnerCount = int64(len(winnerIDs))

	// Шаг 2: Рассчитать приз
	if winnerCount > 0 && totalPrizeFund > 0 {
		prizePerWinner = totalPrizeFund / winnerCount // Целочисленное деление
	}

	log.Printf("[ResultRepo] FindAndUpdateWinners: Quiz %d, Winners found: %d, Prize per winner: %d (within transaction)", quizID, winnerCount, prizePerWinner)

	// Шаг 3: Обновить статус победителей (если они есть) В ПЕРЕДАННОЙ ТРАНЗАКЦИИ
	// Обновляем по user_id
	if winnerCount > 0 {
		if err := tx.Model(&entity.Result{}).
			Where("quiz_id = ? AND user_id IN ?", quizID, winnerIDs). // Используем user_id
			Updates(map[string]interface{}{"is_winner": true, "prize_fund": prizePerWinner}).Error; err != nil {
			log.Printf("Error updating winner status for quiz %d within transaction: %v", quizID, err)
			// Не откатываем
			return nil, 0, err
		}
	}

	// Шаг 4: Сбросить статус для не-победителей В ПЕРЕДАННОЙ ТРАНЗАКЦИИ
	// Обновляем всех, у кого quiz_id совпадает, но user_id нет в списке победителей
	if err := tx.Model(&entity.Result{}).
		Where("quiz_id = ? AND user_id NOT IN ?", quizID, winnerIDs).
		Updates(map[string]interface{}{"is_winner": false, "prize_fund": 0}).Error; err != nil {
		// Эту ошибку можно залогировать, но не прерывать основной процесс
		log.Printf("[ResultRepo] WARNING: Error resetting non-winner status for quiz %d within transaction: %v", quizID, err)
		// Не возвращаем ошибку, т.к. победители уже обновлены
	}

	// Шаг 5: Возвращаем результат (транзакция коммитится/откатывается снаружи)
	return winnerIDs, prizePerWinner, nil
}
