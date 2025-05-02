package errors

import "errors"

// Общие ошибки приложения
var (
	// ErrNotFound используется, когда запись или ресурс не найдены.
	ErrNotFound = errors.New("record not found")

	// ErrUnauthorized используется для ошибок авторизации (неверный токен, нет прав).
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden используется, когда у пользователя недостаточно прав для действия.
	ErrForbidden = errors.New("forbidden")

	// ErrValidation используется для ошибок валидации входных данных.
	ErrValidation = errors.New("validation failed")

	// ErrExpiredToken используется, когда токен (например, refresh) истек.
	ErrExpiredToken = errors.New("token is expired")

	// ErrConflict используется для конфликтов состояния (например, попытка запланировать уже запущенную викторину).
	// Заменяет service.ErrQuizNotSchedulable для большей общности.
	ErrConflict = errors.New("resource state conflict")
)

// TODO: Перенести сюда другие общие ошибки, если необходимо
// например, ErrInvalidInput, ErrUnauthorized и т.д.
