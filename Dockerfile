FROM golang:1.24-alpine AS builder

# Устанавливаем зависимости
RUN apk add --no-cache git

# Устанавливаем рабочую директорию
WORKDIR /app

# Копируем go.mod и go.sum
COPY go.mod go.sum ./

# Загружаем зависимости
RUN go mod download

# Копируем исходный код
COPY . .

# Собираем приложение
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o trivia-api ./cmd/api

# Используем минимальный образ для запуска
FROM alpine:latest

# Устанавливаем зависимости
RUN apk --no-cache add ca-certificates tzdata

# Устанавливаем рабочую директорию
WORKDIR /root/

# Копируем бинарный файл и конфигурацию
COPY --from=builder /app/trivia-api .
COPY --from=builder /app/config ./config
COPY --from=builder /app/migrations ./migrations

# Предоставляем порт
EXPOSE 8080

# Запускаем приложение
CMD ["./trivia-api"]