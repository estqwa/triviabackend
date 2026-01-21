package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/yourusername/trivia-api/internal/config"
	"github.com/yourusername/trivia-api/internal/handler"
	"github.com/yourusername/trivia-api/internal/middleware"
	pgRepo "github.com/yourusername/trivia-api/internal/repository/postgres"
	redisRepo "github.com/yourusername/trivia-api/internal/repository/redis"
	"github.com/yourusername/trivia-api/internal/service"
	"github.com/yourusername/trivia-api/internal/service/quizmanager"
	ws "github.com/yourusername/trivia-api/internal/websocket"
	"github.com/yourusername/trivia-api/pkg/auth"
	"github.com/yourusername/trivia-api/pkg/auth/manager"
	"github.com/yourusername/trivia-api/pkg/database"
)

func main() {
	// Загружаем конфигурацию
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config/config.yaml"
	}
	log.Printf("Загрузка конфигурации из %s", configPath)

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Printf("Failed to load config: %v", err)
		os.Exit(1)
	}

	// Инициализируем подключение к PostgreSQL
	db, err := database.NewPostgresDB(cfg.Database.PostgresConnectionString())
	if err != nil {
		log.Printf("Failed to connect to database: %v", err)
		os.Exit(1)
	}

	// Применяем миграции
	if err := database.MigrateDB(db); err != nil {
		log.Printf("Failed to migrate database: %v", err)
		os.Exit(1)
	}

	// Инициализируем подключение к Redis с использованием унифицированной конфигурации
	redisClient, err := database.NewUniversalRedisClient(cfg.Redis)
	if err != nil {
		log.Printf("Failed to connect to Redis: %v", err)
		os.Exit(1)
	}
	log.Println("Successfully connected to Redis")

	// Инициализируем репозитории
	userRepo := pgRepo.NewUserRepo(db)
	quizRepo := pgRepo.NewQuizRepo(db)
	questionRepo := pgRepo.NewQuestionRepo(db)
	resultRepo := pgRepo.NewResultRepo(db)

	cacheRepo, err := redisRepo.NewCacheRepo(redisClient)
	if err != nil {
		log.Printf("Failed to initialize CacheRepo: %v", err)
		os.Exit(1)
	}

	// Инициализируем репозиторий для инвалидированных токенов
	invalidTokenRepo := pgRepo.NewInvalidTokenRepo(db)

	// Инициализируем репозиторий для refresh-токенов
	refreshTokenRepo, err := pgRepo.NewRefreshTokenRepo(db)
	if err != nil {
		log.Printf("Failed to initialize RefreshTokenRepo: %v", err)
		os.Exit(1)
	}

	// Инициализируем репозиторий для JWT ключей
	jwtKeyRepo, err := pgRepo.NewPostgresJWTKeyRepository(db, cfg.JWT.DBJWTKeyEncryptionKey)
	if err != nil {
		log.Printf("Failed to initialize JWTKeyRepository: %v", err)
		os.Exit(1)
	}

	// --- Инициализация конфигурации для QuizManager ---
	quizConfig := quizmanager.DefaultConfig()

	// --- Инициализация TokenManager и JWTService ---

	// 1. Создаем TokenManager
	tokenManager, err := manager.NewTokenManager(refreshTokenRepo, userRepo, jwtKeyRepo)
	if err != nil {
		log.Printf("Failed to initialize TokenManager: %v", err)
		os.Exit(1)
	}
	// Устанавливаем параметры TokenManager из конфигурации
	tokenManager.SetAccessTokenExpiry(time.Duration(cfg.JWT.ExpirationHrs) * time.Hour)
	tokenManager.SetRefreshTokenExpiry(time.Duration(cfg.Auth.RefreshTokenLifetime) * time.Hour)
	tokenManager.SetMaxRefreshTokensPerUser(cfg.Auth.SessionLimit)

	isProduction := gin.Mode() == gin.ReleaseMode
	tokenManager.SetProductionMode(isProduction) // Устанавливаем режим для Secure кук

	// ВНИМАНИЕ: SameSiteNoneMode требует Secure=true. Убедитесь, что isProduction устанавливается корректно.
	// Для локальной разработки без HTTPS, SameSiteLaxMode или SameSiteDefaultMode может быть более подходящим.
	// Если isProduction=false (HTTP), SameSite=None не будет работать корректно в большинстве браузеров.
	sameSitePolicy := http.SameSiteLaxMode // По умолчанию Lax
	if isProduction {
		sameSitePolicy = http.SameSiteNoneMode // None только для HTTPS
	}
	tokenManager.SetCookieAttributes(
		"/",            // Path
		"",             // Domain
		isProduction,   // Secure (true для прода)
		true,           // HttpOnly
		sameSitePolicy, // Используем вычисленную политику
	)

	// Создаем контекст с отменой для корректного завершения работы горутин
	// Этот контекст будет использоваться для управления жизненным циклом горутин в сервисах
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// --- Инициализация WebSocket (PubSubProvider создается здесь) ---
	var wsHub ws.HubInterface
	var pubSubProvider ws.PubSubProvider = &ws.NoOpPubSub{} // Провайдер по умолчанию

	// Создаем PubSubProvider только если кластеризация включена
	if cfg.WebSocket.Cluster.Enabled {
		log.Println("Инициализация Redis PubSub для кластеризации WebSocket...")
		redisPubSubClient, errPubSub := database.NewUniversalRedisClient(cfg.Redis)
		if errPubSub != nil {
			log.Printf("Ошибка при инициализации Redis клиента для PubSub: %v. Кластеризация WS будет неактивна.", errPubSub)
			pubSubProvider = &ws.NoOpPubSub{}
		} else {
			redisProvider, errProv := ws.NewRedisPubSub(redisPubSubClient)
			if errProv != nil {
				log.Printf("Ошибка при создании Redis PubSub провайдера: %v. Кластеризация WS будет неактивна.", errProv)
				redisPubSubClient.Close()
				pubSubProvider = &ws.NoOpPubSub{}
			} else {
				log.Println("Redis PubSub провайдер успешно инициализирован")
				pubSubProvider = redisProvider
			}
		}
	}
	// --- Конец инициализации WebSocket ---

	// 2. Создаем JWTService, передавая ему tokenManager как KeyProvider, pubSubProvider и ctx
	jwtService, err := auth.NewJWTService(
		cfg.JWT.ExpirationHrs,
		invalidTokenRepo,
		cfg.JWT.WSTicketExpirySec,
		cfg.JWT.CleanupInterval,
		tokenManager,   // tokenManager реализует KeyProvider
		pubSubProvider, // <<< ПЕРЕДАЕМ СЮДА
		ctx,            // <<< ПЕРЕДАЕМ СЮДА КОРНЕВОЙ КОНТЕКСТ ПРИЛОЖЕНИЯ
	)
	if err != nil {
		log.Printf("Failed to initialize JWTService: %v", err)
		os.Exit(1)
	}

	// 3. Устанавливаем jwtService в tokenManager
	tokenManager.SetJWTService(jwtService)

	// --- Конец измененной инициализации TokenManager и JWTService ---

	// Передаем TokenManager в AuthService
	authService, err := service.NewAuthService(userRepo, jwtService, tokenManager, refreshTokenRepo, invalidTokenRepo)
	if err != nil {
		log.Printf("Failed to initialize AuthService: %v", err)
		os.Exit(1)
	}

	// Запускаем фоновую задачу для очистки истекших CSRF токенов и других ресурсов
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		log.Println("Запуск механизма периодической очистки CSRF токенов и истекших refresh-токенов (каждый час)")

		for {
			select {
			case <-ticker.C:
				log.Println("Выполняю периодическую очистку CSRF токенов и истекших refresh-токенов...")
				if err := tokenManager.CleanupExpiredTokens(); err != nil {
					log.Printf("Ошибка при очистке токенов: %v", err)
				} else {
					log.Println("Очистка токенов выполнена успешно")
				}
			case <-ctx.Done():
				log.Println("Завершение работы горутины очистки токенов")
				return
			}
		}
	}()

	// Инициализация WebSocket Hub
	if cfg.WebSocket.Sharding.Enabled {
		log.Println("WebSocket: включено шардирование")
		// Передаем конфигурацию WebSocket, PubSubProvider и CacheRepo в ShardedHub
		shardedHub := ws.NewShardedHub(cfg.WebSocket, pubSubProvider, cacheRepo)
		go shardedHub.Run() // Запускаем обработчик шардов
		wsHub = shardedHub
	}

	wsManager := ws.NewManager(wsHub)

	// Инициализируем сервисы
	quizService := service.NewQuizService(quizRepo, questionRepo, cacheRepo, quizConfig, db)
	resultService := service.NewResultService(resultRepo, userRepo, quizRepo, questionRepo, cacheRepo, db, wsManager, quizConfig)
	userService := service.NewUserService(userRepo)
	quizManagerService := service.NewQuizManager(quizRepo, questionRepo, resultRepo, resultService, cacheRepo, wsManager, db)

	// Инициализируем обработчики
	authHandler := handler.NewAuthHandler(authService, tokenManager, wsHub)
	quizHandler := handler.NewQuizHandler(quizService, resultService, quizManagerService)
	wsHandler := handler.NewWSHandler(wsHub, wsManager, quizManagerService, jwtService)
	userHandler := handler.NewUserHandler(userService)

	// Инициализируем middleware
	authMiddleware := middleware.NewAuthMiddlewareWithManager(jwtService, tokenManager)

	// Инициализируем роутер Gin
	router := gin.Default()

	// Настройка CORS
	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://triviafront.vercel.app", "https://triviafrontadmin.vercel.app", "http://localhost:5173", "http://localhost:8000", "http://localhost:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Статические файлы для админ-панели
	router.StaticFS("/admin", http.Dir("./static/admin"))

	// Настраиваем маршруты API
	api := router.Group("/api")
	{
		// Аутентификация
		authGroup := api.Group("/auth") // Переименовано для ясности
		{
			authGroup.POST("/register", authHandler.Register)
			authGroup.POST("/login", authHandler.Login)
			authGroup.POST("/refresh", authHandler.RefreshToken)
			authGroup.POST("/check-refresh", authHandler.CheckRefreshToken)
			authGroup.POST("/token-info", authHandler.GetTokenInfo)

			// Маршруты, требующие аутентификации
			authedAuth := authGroup.Group("/")
			authedAuth.Use(authMiddleware.RequireAuth())
			{
				// Эндпоинт для получения CSRF токена (хеша)
				authedAuth.GET("/csrf", authHandler.GetCSRFToken)

				// Маршруты, требующие и аутентификации, и CSRF токена
				csrfProtected := authedAuth.Group("/")
				csrfProtected.Use(authMiddleware.RequireCSRF())
				{
					csrfProtected.POST("/logout", authHandler.Logout)
					csrfProtected.POST("/logout-all", authHandler.LogoutAllDevices)
					csrfProtected.GET("/sessions", authHandler.GetActiveSessions)
					csrfProtected.POST("/revoke-session", authHandler.RevokeSession)
					csrfProtected.POST("/change-password", authHandler.ChangePassword)
					csrfProtected.POST("/ws-ticket", authHandler.GenerateWsTicket)
				}
			}

			// Маршрут для сброса инвалидаций токенов (только для администраторов)
			adminAuth := authGroup.Group("/admin")
			adminAuth.Use(authMiddleware.RequireAuth(), authMiddleware.AdminOnly())
			adminAuth.Use(authMiddleware.RequireCSRF())
			{
				adminAuth.POST("/reset-auth", authHandler.ResetAuth)
				adminAuth.POST("/debug-token", authHandler.DebugToken)
				adminAuth.POST("/reset-password", authHandler.AdminResetPassword)
			}
		}

		// Пользователи
		users := api.Group("/users")
		users.Use(authMiddleware.RequireAuth())
		{
			users.GET("/me", authHandler.GetMe)
			users.PUT("/me", authMiddleware.RequireCSRF(), authHandler.UpdateProfile)
		}

		// Лидерборд (публичный маршрут)
		api.GET("/leaderboard", userHandler.GetLeaderboard)

		// Викторины
		quizzes := api.Group("/quizzes")
		{
			quizzes.GET("", quizHandler.ListQuizzes)
			quizzes.GET("/active", quizHandler.GetActiveQuiz)
			quizzes.GET("/scheduled", quizHandler.GetScheduledQuizzes)

			// Группа маршрутов, требующих quizID
			quizWithID := quizzes.Group("/:id")
			quizWithID.Use(middleware.ExtractUintParam("id", "quizID")) // Применяем middleware
			{
				quizWithID.GET("", quizHandler.GetQuiz)
				quizWithID.GET("/with-questions", quizHandler.GetQuizWithQuestions)
				quizWithID.GET("/results", quizHandler.GetQuizResults)

				// Маршруты для аутентифицированных пользователей
				authedQuizzes := quizWithID.Group("") // Наследует middleware
				authedQuizzes.Use(authMiddleware.RequireAuth())
				{
					authedQuizzes.GET("/my-result", quizHandler.GetUserQuizResult)
				}

				// Маршруты для администраторов
				adminQuizzes := quizWithID.Group("") // Наследует middleware
				adminQuizzes.Use(authMiddleware.RequireAuth(), authMiddleware.AdminOnly())
				adminQuizzes.Use(authMiddleware.RequireCSRF())
				{
					adminQuizzes.POST("/questions", quizHandler.AddQuestions)
					adminQuizzes.PUT("/schedule", quizHandler.ScheduleQuiz)
					adminQuizzes.PUT("/cancel", quizHandler.CancelQuiz)
					adminQuizzes.POST("/duplicate", quizHandler.DuplicateQuiz)
				}
			}

			// Маршрут создания викторины (не требует ID)
			adminCreateQuiz := quizzes.Group("")
			adminCreateQuiz.Use(authMiddleware.RequireAuth(), authMiddleware.AdminOnly())
			adminCreateQuiz.Use(authMiddleware.RequireCSRF())
			{
				adminCreateQuiz.POST("", quizHandler.CreateQuiz)
			}
		}
	}

	// WebSocket маршрут
	router.GET("/ws", wsHandler.HandleConnection)

	// Запланированные викторины
	// После перезапуска сервера нужно заново запланировать активные викторины
	go func() {
		scheduledQuizzes, err := quizService.GetScheduledQuizzes()
		if err != nil {
			log.Printf("Failed to get scheduled quizzes: %v", err)
			return
		}

		for _, quiz := range scheduledQuizzes {
			if err := quizManagerService.ScheduleQuiz(quiz.ID, quiz.ScheduledTime); err != nil {
				log.Printf("Failed to reschedule quiz %d: %v", quiz.ID, err)
			}
		}
	}()

	// Настраиваем HTTP сервер с тайм-аутами для защиты от slow client attacks
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
	}

	// Запускаем сервер в горутине
	go func() {
		log.Printf("Starting server on port %s", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("Failed to start server: %v", err)
		}
	}()

	log.Printf("Server started on port %s", cfg.Server.Port)

	// В обработчике сигналов остановки
	// После получения сигнала SIGINT или SIGTERM вызываем cancel() для завершения горутин
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Отправляем сигнал завершения для всех горутин
	cancel()

	// Закрываем PubSubProvider, если он был создан
	if pubSubProvider != nil {
		if err := pubSubProvider.Close(); err != nil {
			log.Printf("Error closing PubSub provider: %v", err)
		}
	}

	// Создаем контекст с таймаутом для graceful shutdown сервера
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
		os.Exit(1)
	}

	log.Println("Server exited properly")
}
