package entity

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQuestion_IsCorrect_CorrectAnswer(t *testing.T) {
	// Arrange
	question := &Question{
		ID:            1,
		QuizID:        1,
		Text:          "Какой язык используется в Go?",
		Options:       StringArray{"Python", "Go", "Java", "Rust"},
		CorrectOption: 1, // "Go" — индекс 1
		TimeLimitSec:  30,
		PointValue:    10,
	}

	// Act & Assert
	assert.True(t, question.IsCorrect(1), "IsCorrect должен вернуть true для правильного ответа")
}

func TestQuestion_IsCorrect_IncorrectAnswer(t *testing.T) {
	// Arrange
	question := &Question{
		ID:            1,
		CorrectOption: 2,
	}

	// Act & Assert
	assert.False(t, question.IsCorrect(0), "IsCorrect должен вернуть false для неправильного ответа")
	assert.False(t, question.IsCorrect(1), "IsCorrect должен вернуть false для неправильного ответа")
	assert.False(t, question.IsCorrect(3), "IsCorrect должен вернуть false для неправильного ответа")
}

func TestQuestion_IsValidOption(t *testing.T) {
	// Arrange
	question := &Question{
		Options: StringArray{"A", "B", "C", "D"},
	}

	// Act & Assert: валидные опции
	assert.True(t, question.IsValidOption(0), "Индекс 0 должен быть валидным")
	assert.True(t, question.IsValidOption(1), "Индекс 1 должен быть валидным")
	assert.True(t, question.IsValidOption(2), "Индекс 2 должен быть валидным")
	assert.True(t, question.IsValidOption(3), "Индекс 3 должен быть валидным")

	// Assert: невалидные опции
	assert.False(t, question.IsValidOption(-1), "Отрицательный индекс должен быть невалидным")
	assert.False(t, question.IsValidOption(4), "Индекс вне диапазона должен быть невалидным")
	assert.False(t, question.IsValidOption(100), "Индекс далеко за пределами должен быть невалидным")
}

func TestQuestion_CalculatePoints_CorrectAnswer(t *testing.T) {
	// Arrange
	question := &Question{
		PointValue: 10,
	}

	// Act: правильный ответ
	points := question.CalculatePoints(true, 5000)

	// Assert: по текущей логике возвращает 1 за правильный ответ
	assert.Equal(t, 1, points, "CalculatePoints должен вернуть 1 за правильный ответ")
}

func TestQuestion_CalculatePoints_IncorrectAnswer(t *testing.T) {
	// Arrange
	question := &Question{
		PointValue: 10,
	}

	// Act: неправильный ответ
	points := question.CalculatePoints(false, 5000)

	// Assert: неправильный ответ = 0 очков
	assert.Equal(t, 0, points, "CalculatePoints должен вернуть 0 за неправильный ответ")
}

func TestQuestion_OptionsCount(t *testing.T) {
	// Arrange
	testCases := []struct {
		name     string
		options  StringArray
		expected int
	}{
		{"4 варианта", StringArray{"A", "B", "C", "D"}, 4},
		{"2 варианта", StringArray{"Да", "Нет"}, 2},
		{"0 вариантов", StringArray{}, 0},
		{"nil варианты", nil, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			question := &Question{Options: tc.options}
			assert.Equal(t, tc.expected, question.OptionsCount())
		})
	}
}

func TestQuestion_TableName(t *testing.T) {
	question := Question{}
	assert.Equal(t, "questions", question.TableName(), "TableName должен возвращать 'questions'")
}

// Тесты для StringArray (JSONB сериализация)

func TestStringArray_Scan_ValidJSON(t *testing.T) {
	// Arrange
	jsonBytes := []byte(`["Option 1", "Option 2", "Option 3"]`)
	var arr StringArray

	// Act
	err := arr.Scan(jsonBytes)

	// Assert
	require.NoError(t, err, "Scan не должен возвращать ошибку для валидного JSON")
	assert.Len(t, arr, 3, "Должно быть 3 элемента")
	assert.Equal(t, "Option 1", arr[0])
	assert.Equal(t, "Option 2", arr[1])
	assert.Equal(t, "Option 3", arr[2])
}

func TestStringArray_Scan_NullValue(t *testing.T) {
	// Arrange
	var arr StringArray

	// Act
	err := arr.Scan(nil)

	// Assert
	require.NoError(t, err, "Scan не должен возвращать ошибку для nil")
	assert.Len(t, arr, 0, "Для nil должен вернуться пустой массив")
}

func TestStringArray_Scan_EmptyBytes(t *testing.T) {
	// Arrange
	var arr StringArray

	// Act
	err := arr.Scan([]byte{})

	// Assert
	require.NoError(t, err, "Scan не должен возвращать ошибку для пустого массива байт")
	assert.Len(t, arr, 0, "Для пустых байт должен вернуться пустой массив")
}

func TestStringArray_Scan_InvalidType(t *testing.T) {
	// Arrange
	var arr StringArray

	// Act: передаём неподдерживаемый тип
	err := arr.Scan("not a byte slice")

	// Assert
	assert.Error(t, err, "Scan должен возвращать ошибку для неподдерживаемого типа")
}

func TestStringArray_Value_NonEmpty(t *testing.T) {
	// Arrange
	arr := StringArray{"A", "B", "C"}

	// Act
	val, err := arr.Value()

	// Assert
	require.NoError(t, err, "Value не должен возвращать ошибку")

	bytes, ok := val.([]byte)
	require.True(t, ok, "Value должен возвращать []byte")
	assert.Equal(t, `["A","B","C"]`, string(bytes), "JSON должен быть корректным")
}

func TestStringArray_Value_Empty(t *testing.T) {
	// Arrange
	arr := StringArray{}

	// Act
	val, err := arr.Value()

	// Assert
	require.NoError(t, err, "Value не должен возвращать ошибку для пустого массива")

	bytes, ok := val.([]byte)
	require.True(t, ok, "Value должен возвращать []byte")
	assert.Equal(t, "[]", string(bytes), "Пустой массив должен сериализоваться в []")
}

func TestStringArray_Value_Nil(t *testing.T) {
	// Arrange
	var arr StringArray = nil

	// Act
	val, err := arr.Value()

	// Assert
	require.NoError(t, err, "Value не должен возвращать ошибку для nil")

	bytes, ok := val.([]byte)
	require.True(t, ok, "Value должен возвращать []byte")
	assert.Equal(t, "[]", string(bytes), "nil должен сериализоваться в []")
}
