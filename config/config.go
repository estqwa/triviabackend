package config

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

// RedisConfig содержит общую конфигурацию Redis для всех режимов
// Добавляем теги валидатора
type RedisConfig struct {
	Mode               string        `yaml:"mode" validate:"required,oneof=single sentinel cluster"`
	Addr               string        `yaml:"addr" validate:"required_if=Mode single,excluded_unless=Mode single,omitempty,hostname_port"`
	Addrs              []string      `yaml:"addrs" validate:"required_if=Mode cluster,required_if=Mode sentinel,excluded_unless=Mode cluster,excluded_unless=Mode sentinel,omitempty,dive,hostname_port"`
	MasterName         string        `yaml:"masterName" validate:"required_if=Mode sentinel,excluded_unless=Mode sentinel"`
	Password           string        `yaml:"password"`
	DB                 int           `yaml:"db" validate:"gte=0"`
	MaxRetries         int           `yaml:"maxRetries" validate:"gte=0"`
	MinRetryBackoff    time.Duration `yaml:"minRetryBackoff" validate:"gte=0"`
	MaxRetryBackoff    time.Duration `yaml:"maxRetryBackoff" validate:"gte=0"`
	DialTimeout        time.Duration `yaml:"dialTimeout" validate:"gte=0"`
	ReadTimeout        time.Duration `yaml:"readTimeout" validate:"gte=0"`
	WriteTimeout       time.Duration `yaml:"writeTimeout" validate:"gte=0"`
	PoolSize           int           `yaml:"poolSize" validate:"gt=0"`
	MinIdleConns       int           `yaml:"minIdleConns" validate:"gte=0"`
	PoolTimeout        time.Duration `yaml:"poolTimeout" validate:"gte=0"`
	IdleTimeout        time.Duration `yaml:"idleTimeout" validate:"gte=0"`
	IdleCheckFrequency time.Duration `yaml:"idleCheckFrequency" validate:"gte=0"`
}

// ServerConfig содержит конфигурацию HTTP сервера
type ServerConfig struct {
	Host         string        `yaml:"host"`
	Port         string        `yaml:"port" validate:"required,numeric"`
	ReadTimeout  time.Duration `yaml:"readTimeout" validate:"gte=0"`
	WriteTimeout time.Duration `yaml:"writeTimeout" validate:"gte=0"`
}

// DatabaseConfig содержит конфигурацию базы данных
type DatabaseConfig struct {
	DSN             string        `yaml:"dsn" validate:"required"`
	MaxOpenConns    int           `yaml:"maxOpenConns" validate:"gt=0"`
	MaxIdleConns    int           `yaml:"maxIdleConns" validate:"gte=0"`
	ConnMaxLifetime time.Duration `yaml:"connMaxLifetime" validate:"gte=0"`
}

// JWTConfig содержит конфигурацию JWT
type JWTConfig struct {
	Secret              string        `yaml:"secret" validate:"required,min=32"` // Важно: секрет должен быть достаточно длинным
	AccessTokenTTL      time.Duration `yaml:"accessTokenTtl" validate:"gt=0"`
	RefreshTokenTTL     time.Duration `yaml:"refreshTokenTtl" validate:"gt=0"`
	MaxRefreshTokens    int           `yaml:"maxRefreshTokens" validate:"gt=0"` // Лимит сессий
	UseKeyRotation      bool          `yaml:"useKeyRotation"`
	KeyRotationInterval time.Duration `yaml:"keyRotationInterval" validate:"required_if=UseKeyRotation true,gt=0"`
}

// WebSocketConfig содержит конфигурацию WebSocket
type WebSocketConfig struct {
	Enabled         bool                   `yaml:"enabled"`
	CheckOrigin     bool                   `yaml:"checkOrigin"`
	AllowedOrigins  []string               `yaml:"allowedOrigins" validate:"required_if=CheckOrigin true"` // Требуется, если checkOrigin=true
	ReadBufferSize  int                    `yaml:"readBufferSize" validate:"gt=0"`
	WriteBufferSize int                    `yaml:"writeBufferSize" validate:"gt=0"`
	WriteWait       time.Duration          `yaml:"writeWait" validate:"gt=0"`
	PongWait        time.Duration          `yaml:"pongWait" validate:"gt=0"`
	PingPeriod      time.Duration          `yaml:"pingPeriod" validate:"gt=0"`
	MaxMessageSize  int64                  `yaml:"maxMessageSize" validate:"gt=0"`
	Cluster         WebSocketClusterConfig `yaml:"cluster" validate:"required_if=Enabled true"`
}

// WebSocketClusterConfig содержит конфигурацию кластеризации WebSocket
type WebSocketClusterConfig struct {
	Enabled bool `yaml:"enabled"`
	// ProviderType string `yaml:"providerType" validate:"required_if=Enabled true,oneof=redis nats"` // Убрали, т.к. используется Redis
	// ProviderConfig RedisConfig `yaml:"providerConfig"` // Конфигурация Redis теперь общая
}

// AppConfig содержит общую конфигурацию приложения
type AppConfig struct {
	Env      string `yaml:"env" validate:"required,oneof=development production test"`
	LogLevel string `yaml:"logLevel" validate:"oneof=debug info warn error fatal panic"`
}

// CORSConfig содержит конфигурацию CORS
type CORSConfig struct {
	Enabled          bool     `yaml:"enabled"`
	AllowedOrigins   []string `yaml:"allowedOrigins" validate:"required_if=Enabled true"`
	AllowedMethods   []string `yaml:"allowedMethods" validate:"required_if=Enabled true,dive,oneof=GET POST PUT DELETE PATCH OPTIONS"`
	AllowedHeaders   []string `yaml:"allowedHeaders" validate:"required_if=Enabled true"`
	ExposedHeaders   []string `yaml:"exposedHeaders"`
	AllowCredentials bool     `yaml:"allowCredentials"`
	MaxAge           int      `yaml:"maxAge" validate:"gte=0"`
}

// QuizManagerConfig содержит конфигурацию QuizManager
type QuizManagerConfig struct {
	MaxQuestionsPerQuiz  int           `yaml:"maxQuestionsPerQuiz" validate:"gt=0"`
	AutoFillThreshold    int           `yaml:"autoFillThreshold" validate:"gte=0"`    // Минуты до старта для автозаполнения
	AnnouncementMinutes  int           `yaml:"announcementMinutes" validate:"gte=0"`  // Минуты до старта для анонса
	WaitingRoomMinutes   int           `yaml:"waitingRoomMinutes" validate:"gte=0"`   // Минуты до старта для зала ожидания
	CountdownSeconds     int           `yaml:"countdownSeconds" validate:"gte=0"`     // Секунды до старта для отсчета
	EliminationTimeMs    int64         `yaml:"eliminationTimeMs" validate:"gt=0"`     // Время в мс для выбывания при долгом ответе
	QuestionDelayMs      int           `yaml:"questionDelayMs" validate:"gte=0"`      // Задержка перед отправкой вопроса
	AnswerRevealDelayMs  int           `yaml:"answerRevealDelayMs" validate:"gte=0"`  // Задержка перед показом ответа
	InterQuestionDelayMs int           `yaml:"interQuestionDelayMs" validate:"gte=0"` // Пауза между вопросами
	MaxRetries           int           `yaml:"maxRetries" validate:"gte=0"`           // Макс. попыток отправки WS события
	RetryInterval        time.Duration `yaml:"retryInterval" validate:"gte=0"`        // Интервал между попытками
}

// Config - корневая структура конфигурации
type Config struct {
	App         AppConfig         `yaml:"app" validate:"required"`
	Server      ServerConfig      `yaml:"server" validate:"required"`
	Database    DatabaseConfig    `yaml:"database" validate:"required"`
	Redis       RedisConfig       `yaml:"redis" validate:"required"`
	JWT         JWTConfig         `yaml:"jwt" validate:"required"`
	WebSocket   WebSocketConfig   `yaml:"websocket" validate:"required"`
	CORS        CORSConfig        `yaml:"cors" validate:"required"`
	QuizManager QuizManagerConfig `yaml:"quizManager" validate:"required"`
}

// Load загружает конфигурацию из YAML файла
func Load(path string) (*Config, error) {
	log.Printf("Загрузка конфигурации из файла: %s", path)

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ошибка чтения файла конфигурации '%s': %w", path, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("ошибка парсинга YAML конфигурации: %w", err)
	}

	// Установка значений по умолчанию, если они не заданы в YAML
	// setDefaultValues(&config)

	// --- Валидация с использованием go-playground/validator ---
	validate := validator.New()

	// Регистрируем пользовательскую валидацию для RedisConfig, если нужно
	// validate.RegisterStructValidation(redisConfigValidation, RedisConfig{}) // Пример

	if err := validate.Struct(config); err != nil {
		var invalidValidationError *validator.InvalidValidationError
		if errors.As(err, &invalidValidationError) {
			log.Printf("Внутренняя ошибка валидатора: %v", err)
			return nil, fmt.Errorf("внутренняя ошибка валидатора конфигурации")
		}

		// Формируем понятное сообщение об ошибке
		var errorMessages []string
		for _, err := range err.(validator.ValidationErrors) {
			// Получаем более читаемое имя поля
			fieldName := err.Namespace()
			// Формируем сообщение
			message := fmt.Sprintf("Поле '%s' не прошло валидацию '%s' (значение: '%v')", fieldName, err.Tag(), err.Value())
			errorMessages = append(errorMessages, message)
		}
		log.Printf("Ошибки валидации конфигурации:\n- %s", strings.Join(errorMessages, "\n- "))
		return nil, fmt.Errorf("ошибки валидации конфигурации:\n- %s", strings.Join(errorMessages, "\n- "))
	}

	log.Println("Конфигурация успешно загружена и валидирована.")
	return &config, nil
}

// Пример пользовательской валидации для RedisConfig (если стандартных тегов не хватает)
/*
func redisConfigValidation(sl validator.StructLevel) {
	rc := sl.Current().Interface().(RedisConfig)

	switch rc.Mode {
	case "single":
		if rc.Addr == "" {
			sl.ReportError(rc.Addr, "Addr", "addr", "required_if_mode_single", "")
		}
	case "sentinel":
		if len(rc.Addrs) == 0 {
			sl.ReportError(rc.Addrs, "Addrs", "addrs", "required_if_mode_sentinel", "")
		}
		if rc.MasterName == "" {
			sl.ReportError(rc.MasterName, "MasterName", "masterName", "required_if_mode_sentinel", "")
		}
	case "cluster":
		if len(rc.Addrs) == 0 {
			sl.ReportError(rc.Addrs, "Addrs", "addrs", "required_if_mode_cluster", "")
		}
	}
}
*/

/* Старая ручная валидация
// Валидация конфигурации
func validateConfig(config *Config) error {
	if config.Server.Port == "" {
		return errors.New("server port is required")
	}
	if config.Database.DSN == "" {
		return errors.New("database DSN is required")
	}
	if config.JWT.Secret == "" {
		return errors.New("JWT secret is required")
	}
	// Добавить проверки для Redis
	switch config.Redis.Mode {
	case "single":
		if config.Redis.Addr == "" {
			return errors.New("Redis address (addr) is required for single mode")
		}
	case "sentinel":
		if len(config.Redis.Addrs) == 0 {
			return errors.New("Redis addresses (addrs) are required for sentinel mode")
		}
		if config.Redis.MasterName == "" {
			return errors.New("Redis master name (masterName) is required for sentinel mode")
		}
	case "cluster":
		if len(config.Redis.Addrs) == 0 {
			return errors.New("Redis addresses (addrs) are required for cluster mode")
		}
	case "": // Если режим не указан
		return errors.New("Redis mode is required (single, sentinel, or cluster)")
	default:
		return fmt.Errorf("invalid Redis mode: %s", config.Redis.Mode)
	}
	return nil
}
*/
