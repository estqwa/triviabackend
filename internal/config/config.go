package config

import (
	"fmt"
	"time"

	"github.com/spf13/viper"
)

// Config хранит все настройки приложения
type Config struct {
	Server    ServerConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	JWT       JWTConfig
	Auth      AuthConfig
	WebSocket WebSocketConfig
}

// ServerConfig содержит настройки HTTP сервера
type ServerConfig struct {
	Port         string
	ReadTimeout  int
	WriteTimeout int
}

// DatabaseConfig содержит настройки подключения к PostgreSQL
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// RedisConfig содержит унифицированные настройки подключения к Redis
// Поддерживает режимы: single, sentinel, cluster
type RedisConfig struct {
	// Mode: Режим работы Redis ("single", "sentinel", "cluster"). По умолчанию "single".
	Mode string `mapstructure:"mode"`

	// Addrs: Список адресов Redis (хост:порт). Используется для всех режимов.
	// Для 'single', если не пуст, используется первый адрес из списка.
	Addrs []string `mapstructure:"addrs"`

	// Addr: Альтернативный адрес для режима 'single' (для обратной совместимости).
	// Используется, если Mode="single" и Addrs пустой.
	Addr string `mapstructure:"addr"`

	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`

	// MasterName: Имя мастер-сервера Redis (только для режима "sentinel")
	MasterName string `mapstructure:"master_name"`

	// MaxRetries: Максимальное количество попыток переподключения (-1 - бесконечно). По умолчанию 0 (без ретраев).
	MaxRetries int `mapstructure:"max_retries"`

	// MinRetryBackoff: Минимальный интервал между попытками (в миллисекундах). По умолчанию 8ms.
	MinRetryBackoff int `mapstructure:"min_retry_backoff"`

	// MaxRetryBackoff: Максимальный интервал между попытками (в миллисекундах). По умолчанию 512ms.
	MaxRetryBackoff int `mapstructure:"max_retry_backoff"`
}

// JWTConfig содержит настройки JWT
type JWTConfig struct {
	Secret            string
	ExpirationHrs     int
	WSTicketExpirySec int           `mapstructure:"wsTicketExpirySec"` // Время жизни тикета для WebSocket в секундах
	CleanupInterval   time.Duration `mapstructure:"cleanup_interval"`  // Интервал очистки кеша
}

// AuthConfig содержит настройки аутентификации
type AuthConfig struct {
	SessionLimit         int
	RefreshTokenLifetime int
}

// WebSocketConfig содержит настройки WebSocket-подсистемы
type WebSocketConfig struct {
	Sharding ShardingConfig
	Buffers  BuffersConfig
	Priority PriorityConfig
	Ping     PingConfig
	Cluster  ClusterConfig
	Limits   LimitsConfig
}

// ShardingConfig содержит настройки шардирования
type ShardingConfig struct {
	Enabled            bool
	ShardCount         int
	MaxClientsPerShard int
}

// BuffersConfig содержит настройки буферов
type BuffersConfig struct {
	ClientSendBuffer int
	BroadcastBuffer  int
	RegisterBuffer   int
	UnregisterBuffer int
}

// PriorityConfig содержит настройки приоритизации сообщений
type PriorityConfig struct {
	Enabled              bool
	HighPriorityBuffer   int
	NormalPriorityBuffer int
	LowPriorityBuffer    int
}

// PingConfig содержит настройки пингов
type PingConfig struct {
	Interval int
	Timeout  int
}

// ClusterConfig содержит настройки кластеризации
type ClusterConfig struct {
	Enabled          bool
	InstanceID       string
	BroadcastChannel string
	DirectChannel    string
	MetricsChannel   string
	MetricsInterval  int
}

// LimitsConfig содержит настройки ограничений
type LimitsConfig struct {
	MaxMessageSize      int
	WriteWait           int
	PongWait            int
	MaxConnectionsPerIP int
	CleanupInterval     int
}

// PostgresConnectionString формирует строку подключения к PostgreSQL
func (d *DatabaseConfig) PostgresConnectionString() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode,
	)
}

// Load загружает конфигурацию из файла
func Load(configPath string) (*Config, error) {
	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var cfg Config

	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Проверка обязательных параметров
	if cfg.JWT.Secret == "" {
		return nil, fmt.Errorf("JWT secret is required in config")
	}

	if cfg.Database.Host == "" || cfg.Database.DBName == "" {
		return nil, fmt.Errorf("database configuration (host, dbname) is incomplete in config")
	}

	return &cfg, nil
}
