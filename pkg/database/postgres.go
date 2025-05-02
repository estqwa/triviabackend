package database

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	migrateV4 "github.com/golang-migrate/migrate/v4"
	migratePostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	gormPostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// NewPostgresDB создает новое подключение к PostgreSQL
func NewPostgresDB(dsn string) (*gorm.DB, error) {
	db, err := gorm.Open(gormPostgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Настройка пула соединений
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}

	// Максимальное число открытых соединений
	sqlDB.SetMaxOpenConns(25)

	// Максимальное число простаивающих соединений
	sqlDB.SetMaxIdleConns(10)

	// Максимальное время жизни соединения
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// MigrateDB применяет SQL-миграции из папки 'migrations'
func MigrateDB(db *gorm.DB) error {
	log.Println("Запуск применения миграций базы данных...")

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("не удалось получить *sql.DB из *gorm.DB: %w", err)
	}

	// Убедимся, что подключение к БД активно
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("не удалось проверить подключение к БД перед миграцией: %w", err)
	}

	// Создаем драйвер базы данных для migrate
	driver, err := migratePostgres.WithInstance(sqlDB, &migratePostgres.Config{})
	if err != nil {
		return fmt.Errorf("не удалось создать драйвер postgres для migrate: %w", err)
	}

	// Создаем источник миграций (из папки migrations)
	// Путь "file://migrations" указывает на папку migrations
	// в рабочем каталоге приложения (в Docker это будет /root/migrations)
	m, err := migrateV4.NewWithDatabaseInstance(
		"file://migrations",
		"postgres", // Имя базы данных (для логирования в migrate)
		driver,
	)
	if err != nil {
		return fmt.Errorf("не удалось создать экземпляр migrate: %w", err)
	}

	// Применяем миграции "вверх"
	log.Println("Применяем миграции 'up'...")
	err = m.Up()
	if err != nil && !errors.Is(err, migrateV4.ErrNoChange) {
		// Если ошибка НЕ "нет изменений", то это реальная проблема
		log.Printf("Ошибка применения миграций: %v", err)
		return fmt.Errorf("ошибка применения миграций 'up': %w", err)
	} else if errors.Is(err, migrateV4.ErrNoChange) {
		log.Println("Изменений в миграциях не найдено, база данных уже актуальна.")
	} else {
		log.Println("Миграции успешно применены.")
	}

	log.Println("Миграции базы данных завершены.")
	return nil // Возвращаем nil, если все прошло успешно или не было изменений
}

// GetSQLDB возвращает базовый *sql.DB из *gorm.DB
func GetSQLDB(gormDB *gorm.DB) (*sql.DB, error) {
	sqlDB, err := gormDB.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get sql.DB: %w", err)
	}
	return sqlDB, nil
}
