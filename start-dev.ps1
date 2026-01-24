# Скрипт для быстрого запуска бэкенда в режиме разработки
# Запускать как: .\start-dev.ps1

# 1. Настройка переменных окружения (как в docker-compose, но для localhost)
$env:DATABASE_HOST="localhost"
$env:DATABASE_PASSWORD="123456"
$env:REDIS_ADDR="localhost:6379"
# 32 байта в HEX (64 символа)
$env:DB_JWT_KEY_ENCRYPTION_KEY="000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
$env:GIN_MODE="debug"

Write-Host "Starting Trivia API in development mode..." -ForegroundColor Green
Write-Host "Database: localhost:5432" -ForegroundColor Gray
Write-Host "Redis:    localhost:6379" -ForegroundColor Gray

# 2. Запуск сервера
# go run компилирует и запускает программу "на лету".
# Это удобно для разработки, так как не нужно делать build после каждого изменения.
go run ./cmd/api
