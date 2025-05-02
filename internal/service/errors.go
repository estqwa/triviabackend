package service

import "errors"

// Определяем кастомные ошибки для сервисов
var (
	// ErrQuizNotFound       = errors.New("quiz not found")
	ErrQuizNotSchedulable = errors.New("quiz cannot be scheduled in its current state")
	// ErrValidation         = errors.New("validation failed")
	// ErrUserNotFound       = errors.New("user not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	// Добавьте другие специфичные ошибки по мере необходимости, если они не являются общими
)
