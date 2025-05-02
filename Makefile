.PHONY: build run test clean docker-build docker-up docker-down migrate-up migrate-down

# Переменные проекта
BINARY_NAME=trivia-api
DOCKER_COMPOSE=docker-compose

# Основные команды
build:
	go build -o ${BINARY_NAME} ./cmd/api

run:
	go run ./cmd/api

test:
	go test -v ./...

clean:
	go clean
	rm -f ${BINARY_NAME}

# Docker команды
docker-build:
	${DOCKER_COMPOSE} build

docker-up:
	${DOCKER_COMPOSE} up -d

docker-down:
	${DOCKER_COMPOSE} down

# Миграции базы данных
# Удалены команды migrate-up и migrate-down

# Инициализация проекта
init:
	go mod tidy
	go mod download

