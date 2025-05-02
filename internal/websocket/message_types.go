package websocket

// Типы сообщений для викторины
const (
	// QUIZ_START сообщает о начале викторины
	QUIZ_START = "QUIZ_START"

	// QUIZ_END сообщает о завершении викторины
	QUIZ_END = "QUIZ_END"

	// QUESTION_START сообщает о начале нового вопроса
	QUESTION_START = "QUESTION_START"

	// QUESTION_END сообщает о завершении текущего вопроса
	QUESTION_END = "QUESTION_END"

	// USER_ANSWER сообщает об ответе пользователя
	USER_ANSWER = "USER_ANSWER"

	// RESULT_UPDATE сообщает об обновлении результатов
	RESULT_UPDATE = "RESULT_UPDATE"
)

// Типы сообщений, связанные с авторизацией
const (
	// TOKEN_EXPIRE_SOON уведомляет о скором истечении срока action-токена
	TOKEN_EXPIRE_SOON = "TOKEN_EXPIRE_SOON"

	// TOKEN_EXPIRED уведомляет об истечении срока действия токена
	TOKEN_EXPIRED = "TOKEN_EXPIRED"
)
