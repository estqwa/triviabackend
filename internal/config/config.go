package config

import (
	"fmt"
	"log"
	"os"
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
	ExpirationHrs         int           `mapstructure:"expirationHrs"`
	WSTicketExpirySec     int           `mapstructure:"wsTicketExpirySec"`         // Время жизни тикета для WebSocket в секундах
	CleanupInterval       time.Duration `mapstructure:"cleanup_interval"`          // Интервал очистки кеша
	DBJWTKeyEncryptionKey string        `mapstructure:"db_jwt_key_encryption_key"` // Ключ для шифрования JWT ключей в БД
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
	vip := viper.New() // Используем новый экземпляр Viper, чтобы избежать глобального состояния

	// 1. Устанавливаем значения по умолчанию (если они нужны)
	// vip.SetDefault("database.host", "localhost")

	// 2. Привязываем переменные окружения ЯВНО
	// Привязка для секции Database
	vip.BindEnv("database.host", "DATABASE_HOST")
	vip.BindEnv("database.port", "DATABASE_PORT")
	vip.BindEnv("database.user", "DATABASE_USER")
	vip.BindEnv("database.password", "DATABASE_PASSWORD")
	vip.BindEnv("database.dbname", "DATABASE_DBNAME")
	vip.BindEnv("database.sslmode", "DATABASE_SSLMODE")

	// Привязка для секции Redis
	vip.BindEnv("redis.mode", "REDIS_MODE")
	vip.BindEnv("redis.addrs", "REDIS_ADDRS") // Для массива строк
	vip.BindEnv("redis.addr", "REDIS_ADDR")   // Для одиночной строки
	vip.BindEnv("redis.password", "REDIS_PASSWORD")
	vip.BindEnv("redis.db", "REDIS_DB")
	vip.BindEnv("redis.master_name", "REDIS_MASTER_NAME")

	// Привязка для секции JWT
	vip.BindEnv("jwt.expirationHrs", "JWT_EXPIRATIONHRS")
	vip.BindEnv("jwt.wsTicketExpirySec", "JWT_WSTICKETEXPIRYSEC")
	vip.BindEnv("jwt.cleanup_interval", "JWT_CLEANUP_INTERVAL")
	vip.BindEnv("jwt.db_jwt_key_encryption_key", "DB_JWT_KEY_ENCRYPTION_KEY")

	// Привязка для секции Auth
	vip.BindEnv("auth.sessionLimit", "AUTH_SESSIONLIMIT")
	vip.BindEnv("auth.refreshTokenLifetime", "AUTH_REFRESHTOKENLIFETIME")

	// Привязка для Server
	vip.BindEnv("server.port", "SERVER_PORT")

	// Привязка для WebSocket Cluster
	vip.BindEnv("websocket.cluster.enabled", "WEBSOCKET_CLUSTER_ENABLED")

	// Заменяем '.' на '_' в именах переменных окружения для AutomaticEnv (если используется)
	// vip.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// vip.AutomaticEnv() // Можно оставить или убрать, т.к. BindEnv уже сделан

	// 3. Устанавливаем путь к файлу конфигурации
	if configPath != "" {
		vip.SetConfigFile(configPath)
		// 4. Пытаемся прочитать файл конфигурации (не страшно, если его нет, т.к. есть BindEnv)
		if err := vip.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Printf("Файл конфигурации '%s' не найден, используются переменные окружения/умолчания.", configPath)
			} else {
				log.Printf("Предупреждение: не удалось прочитать файл конфигурации '%s': %v", configPath, err)
			}
		}
	}

	// 5. Анмаршалим конфигурацию (Viper объединит значения из файла и привязанных env vars)
	var cfg Config
	if err := vip.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 6. Логирование конфигурации (только в debug режиме)
	if os.Getenv("GIN_MODE") != "release" {
		log.Printf("--- Загруженные значения конфигурации ---")
		log.Printf("Database Host: %s", cfg.Database.Host)
		log.Printf("Database Port: %s", cfg.Database.Port)
		log.Printf("Database User: %s", cfg.Database.User)
		log.Printf("Database Name: %s", cfg.Database.DBName)
		log.Printf("Database SSLMode: %s", cfg.Database.SSLMode)
		log.Printf("Redis Addr: %s", cfg.Redis.Addr)
		log.Printf("Redis Mode: %s", cfg.Redis.Mode)
		log.Printf("JWT Expiration Hours: %d", cfg.JWT.ExpirationHrs)
		log.Printf("DB JWT Key Encryption Key Set: %t", cfg.JWT.DBJWTKeyEncryptionKey != "")
		log.Printf("Server Port: %s", cfg.Server.Port)
		log.Printf("Websocket Cluster Enabled: %t", cfg.WebSocket.Cluster.Enabled)
		log.Printf("-----------------------------------------")
	}

	// 7. Проверка обязательных параметров
	if cfg.JWT.DBJWTKeyEncryptionKey == "" {
		return nil, fmt.Errorf("DB JWT key encryption key is required in config (check DB_JWT_KEY_ENCRYPTION_KEY env var)")
	}
	if cfg.Database.Host == "" || cfg.Database.DBName == "" || cfg.Database.User == "" {
		return nil, fmt.Errorf("database configuration (host, dbname, user) is incomplete in config (check DATABASE_HOST, DATABASE_DBNAME, DATABASE_USER env vars)")
	}
	// Проверяем пароли для БД и Redis, если приложение не в режиме разработки (например, в production)
	// Для этого нам нужен способ определить режим. Предположим, мы можем получить его из переменной окружения GIN_MODE.
	ginMode := vip.GetString("GIN_MODE") // Попробуем получить GIN_MODE, если он установлен как env var
	if ginMode != "debug" {              // Если не debug (т.е. release, test и т.д.), считаем production-like
		if cfg.Database.Password == "" {
			return nil, fmt.Errorf("database password is required in production mode (check DATABASE_PASSWORD env var)")
		}
		if cfg.Redis.Password == "" && cfg.Redis.Mode != "single" && len(cfg.Redis.Addrs) > 0 {
			// Пароль для Redis может быть не нужен, если Redis не настроен или это локальный инстанс без пароля.
			// Более точная проверка может зависеть от того, как используется Redis.
			// Здесь проверяем, что если Redis сконфигурирован (addrs не пуст и не single mode по умолчанию без адреса), то пароль должен быть.
			// Для простоты, если REDIS_PASSWORD пуст, но REDIS_ADDRS задан, будем требовать пароль в non-debug.
			// Если cfg.Redis.Addrs не пуст или cfg.Redis.Addr не пуст - значит Redis используется.
			isRedisConfigured := len(cfg.Redis.Addrs) > 0 || cfg.Redis.Addr != ""
			if isRedisConfigured && cfg.Redis.Password == "" {
				log.Println("Warning: Redis is configured but REDIS_PASSWORD is not set in a non-debug environment.")
				// Можно сделать это фатальной ошибкой, если требуется:
				// return nil, fmt.Errorf("Redis password is required in non-debug mode when Redis is configured (check REDIS_PASSWORD env var)")
			}
		}
	}

	return &cfg, nil
}
