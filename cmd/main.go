package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/joho/godotenv"
	"github.com/vhvplatform/go-auth-service/internal/handler"
	"github.com/vhvplatform/go-auth-service/internal/repository"
	"github.com/vhvplatform/go-auth-service/internal/service"
	"github.com/vhvplatform/go-shared/config"
	"github.com/vhvplatform/go-shared/jwt"
	"github.com/vhvplatform/go-shared/logger"
	"github.com/vhvplatform/go-shared/pkg/mtls"
	"github.com/vhvplatform/go-shared/redis"

	pb "github.com/vhvplatform/go-auth-service/internal/pb/auth/v1"
	"go.uber.org/zap"
	grpcLib "google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	// Step 1: Load environment configuration from .env.{environment} file
	// Priority: APP_ENV environment variable > Default (local)
	// Use godotenv to read file and set only missing environment variables
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "local"
	}
	envFile := fmt.Sprintf(".env.%s", appEnv)
	// Temporary logger for early-stage diagnostics
	tmpLog, _ := logger.New("debug")
	tmpLog.Info("Attempting to load env file", zap.String("file", envFile))
	if m, err := godotenv.Read(envFile); err == nil {
		for k, v := range m {
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
				tmpLog.Debug("Set env from file", zap.String("key", k))
			} else {
				tmpLog.Debug("Skipped env var (already set)", zap.String("key", k), zap.String("value", os.Getenv(k)))
			}
		}
		tmpLog.Info("Env file processed", zap.String("file", envFile))
	} else {
		tmpLog.Warn("Could not read env file; proceeding with existing environment", zap.String("file", envFile), zap.Error(err))
	}

	// Diagnostic: Log Redis environment variables after loading
	tmpLog.Info("Redis env vars after loading",
		zap.String("REDIS_ENABLED", os.Getenv("REDIS_ENABLED")),
		zap.String("REDIS_HOST", os.Getenv("REDIS_HOST")),
		zap.String("REDIS_PORT", os.Getenv("REDIS_PORT")),
		zap.String("REDIS_PASSWORD", os.Getenv("REDIS_PASSWORD")))

	// Step 2: Load configuration from environment variables (now populated from .env file and OS)
	// config.Load() reads from os.Getenv()
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	// Initialize logger
	log, err := logger.New(cfg.LogLevel)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize logger: %v", err))
	}
	defer log.Sync()

	log.Info("Starting Auth Service", zap.String("environment", cfg.Environment))

	// Initialize YugabyteDB (primary database)
	// Build connection string from config
	dbURL := fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=%s&search_path=%s",
		cfg.Yugabyte.User,
		cfg.Yugabyte.Password,
		cfg.Yugabyte.Host,
		cfg.Yugabyte.Port,
		cfg.Yugabyte.Database,
		cfg.Yugabyte.SSLMode,
		cfg.Yugabyte.Schema,
	)

	pgDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal("Failed to connect to YugabyteDB", zap.Error(err))
	}
	defer pgDB.Close()

	// Configure connection pool from config
	pgDB.SetMaxOpenConns(cfg.Yugabyte.MaxOpenConns)
	pgDB.SetMaxIdleConns(cfg.Yugabyte.MaxIdleConns)

	// Parse ConnMaxLifetime from string to duration
	connLifetime := 3600 // default 1 hour in seconds
	if lifetime, err := strconv.ParseInt(cfg.Yugabyte.ConnMaxLifetime, 10, 64); err == nil {
		connLifetime = int(lifetime)
	}
	pgDB.SetConnMaxLifetime(time.Duration(connLifetime) * time.Second)

	// Test connection - FAIL FAST if DB is unavailable
	if err := pgDB.Ping(); err != nil {
		log.Fatal("❌ CRITICAL: Failed to connect to YugabyteDB. Service cannot start without database.",
			zap.Error(err),
			zap.String("host", cfg.Yugabyte.Host),
			zap.String("port", cfg.Yugabyte.Port),
			zap.String("database", cfg.Yugabyte.Database),
		)
	}
	log.Info("✓ Connected to YugabyteDB successfully")

	// Initialize Redis (optional)
	var redisClient *redis.Client

	// Debug: Log Redis config
	log.Info("Redis configuration",
		zap.Bool("enabled", cfg.Redis.Enabled),
		zap.String("host", cfg.Redis.Host),
		zap.String("port", cfg.Redis.Port),
		zap.String("addr", cfg.Redis.GetRedisAddr()))

	if cfg.Redis.Enabled {
		log.Info("Initializing Redis connection...")
		redisClient, err = redis.NewClient(redis.Config{
			Addr:     cfg.Redis.GetRedisAddr(),
			Password: cfg.Redis.Password,
			DB:       cfg.Redis.DB,
		})
		if err != nil {
			log.Warn("⚠️  Failed to connect to Redis - falling back to JWT mode", zap.Error(err))
			redisClient = nil // Ensure nil so tokenManager won't be created
		} else {
			defer redisClient.Close()
			log.Info("✅ Redis connected successfully")
		}
	} else {
		log.Warn("⚠️  Redis is disabled - will use JWT fallback mode (NOT Opaque Token)")
	}

	// Initialize JWT manager
	jwtManager := jwt.NewManager(cfg.JWT.Secret, cfg.JWT.Expiration, cfg.JWT.RefreshExpiration)

	// Initialize YugabyteDB repositories (NEW ARCHITECTURE)
	authIdentifierRepo := repository.NewAuthIdentifierRepository(pgDB)
	userIdentityRepo := repository.NewUserIdentityRepository(pgDB)
	userRepo := repository.NewUserRepository(pgDB)
	tenantRepo := repository.NewTenantRepository(pgDB)
	tenantMemberRepo := repository.NewTenantMemberRepository(pgDB)
	refreshTokenRepo := repository.NewRefreshTokenRepository(pgDB)
	emailVerificationRepo := repository.NewEmailVerificationRepository(pgDB)

	// Initialize services
	authService := service.NewAuthService(
		authIdentifierRepo,
		userIdentityRepo,
		userRepo,
		tenantRepo,
		tenantMemberRepo,
		refreshTokenRepo,
		emailVerificationRepo,
		jwtManager,
		redisClient,
		log,
	)

	// Start gRPC server
	grpcPort := os.Getenv("AUTH_SERVICE_PORT")
	if grpcPort == "" {
		log.Fatal("AUTH_SERVICE_PORT environment variable is required")
	}
	go startGRPCServer(authService, log, grpcPort, cfg)

	// Start HTTP server (minimal health check only)
	httpPort := os.Getenv("AUTH_SERVICE_HTTP_PORT")
	if httpPort == "" {
		log.Fatal("AUTH_SERVICE_HTTP_PORT environment variable is required")
	}
	startHTTPServer(log, httpPort)
}

func startGRPCServer(authService *service.AuthService, log *logger.Logger, port string, cfg *config.Config) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		log.Fatal("Failed to listen", zap.Error(err))
	}

	var opts []grpcLib.ServerOption

	// Enable mTLS if configured
	if cfg.TLS.Enabled {
		creds, err := mtls.NewServerCredentials(mtls.Config{
			CertFile: cfg.TLS.CertFile,
			KeyFile:  cfg.TLS.KeyFile,
			CAFile:   cfg.TLS.CAFile,
		})
		if err != nil {
			log.Fatal("Failed to load TLS credentials", zap.Error(err))
		}
		opts = append(opts, grpcLib.Creds(creds))
	}

	grpcSrv := grpcLib.NewServer(opts...)
	authGrpcHandler := handler.NewAuthHandler(authService, log)
	pb.RegisterAuthServiceServer(grpcSrv, authGrpcHandler)

	// Register health check service
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	log.Info("gRPC server listening", zap.String("port", port))
	if err := grpcSrv.Serve(lis); err != nil {
		log.Fatal("Failed to serve gRPC", zap.Error(err))
	}
}

func startHTTPServer(log *logger.Logger, port string) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Health check endpoints only
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Configure HTTP server with timeouts for better performance and resource management
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           router,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Start server in goroutine
	go func() {
		log.Info("HTTP server listening", zap.String("port", port))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start HTTP server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal to gracefully shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server forced to shutdown", zap.Error(err))
	}

	log.Info("Server exited")
}
