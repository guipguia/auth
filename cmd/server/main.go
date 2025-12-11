package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/guipguia/auth/api/proto/auth/v1"
	"github.com/guipguia/auth/internal/config"
	"github.com/guipguia/auth/internal/crypto"
	"github.com/guipguia/auth/internal/database"
	"github.com/guipguia/auth/internal/logging"
	"github.com/guipguia/auth/internal/repository"
	"github.com/guipguia/auth/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize structured logging
	if err := logging.Init("info", false); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}
	defer logging.Sync()

	logging.Logger.Info("Starting Auth Service", zap.String("address", cfg.Server.Address))

	// Initialize database
	db, err := database.New(&cfg.Database)
	if err != nil {
		logging.Logger.Fatal("Failed to initialize database", zap.Error(err))
	}
	defer func() { _ = db.Close() }()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		logging.Logger.Fatal("Failed to run migrations", zap.Error(err))
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		logging.Logger.Fatal("Failed to ping database", zap.Error(err))
	}

	logging.Logger.Info("Database connection established successfully")

	// Initialize cache service for stateless horizontal scaling
	cacheService, err := service.NewCacheService(&cfg.Cache)
	if err != nil {
		logging.Logger.Fatal("Failed to initialize cache service", zap.Error(err))
	}
	defer func() { _ = cacheService.Close() }()

	if cfg.Cache.Enabled {
		logging.Logger.Info("Cache service initialized", zap.String("type", cfg.Cache.Type))
	} else {
		logging.Logger.Info("Cache disabled - running in stateless mode")
	}

	// Initialize encryption
	var encryptor *crypto.Encryptor
	if cfg.EncryptionKey != "" {
		encryptor, err = crypto.NewEncryptor(cfg.EncryptionKey)
		if err != nil {
			logging.Logger.Fatal("Failed to initialize encryptor", zap.Error(err))
		}
		logging.Logger.Info("Field-level encryption enabled for sensitive data")
	} else {
		logging.Logger.Warn("Encryption key not configured - sensitive data will not be encrypted at rest")
	}

	// Initialize repositories (with caching if enabled)
	userRepo := repository.NewUserRepository(db.DB, encryptor)
	var sessionRepo repository.SessionRepository
	var otpRepo repository.OTPRepository

	if cfg.Cache.Enabled {
		sessionRepo = repository.NewCachedSessionRepository(db.DB, cacheService, cfg.Cache.TTLSeconds)
		otpRepo = repository.NewCachedOTPRepository(db.DB, cacheService, cfg.Cache.TTLSeconds, encryptor)
	} else {
		sessionRepo = repository.NewSessionRepository(db.DB)
		otpRepo = repository.NewOTPRepository(db.DB, encryptor)
	}

	// Initialize compliance repositories
	auditLogRepo := repository.NewAuditLogRepository(db.DB)
	loginAttemptRepo := repository.NewLoginAttemptRepository(db.DB)
	lockoutRepo := repository.NewAccountLockoutRepository(db.DB)
	passwordHistoryRepo := repository.NewPasswordHistoryRepository(db.DB)

	// Initialize membership repository for team management
	membershipRepo := repository.NewMembershipRepository(db.DB)

	// Initialize services
	passwordService := service.NewPasswordService()
	totpService := service.NewTOTPService()
	passwordlessService := service.NewPasswordlessService(otpRepo)
	oauthService := service.NewOAuthService(&cfg.OAuth)
	jwtService := service.NewJWTService(&cfg.JWT)
	emailService := service.NewEmailService(&cfg.Email, cfg.Server.AppURL)

	// Initialize compliance services
	auditService := service.NewAuditService(auditLogRepo)
	loginProtectionService := service.NewLoginProtectionService(
		loginAttemptRepo,
		lockoutRepo,
		userRepo,
		service.DefaultLoginProtectionConfig(),
	)
	passwordHistoryService := service.NewPasswordHistoryService(
		passwordHistoryRepo,
		service.DefaultPasswordHistoryConfig(),
	)

	// Session configuration from config (HIPAA compliance is configurable)
	sessionConfig := service.SessionConfig{
		SessionExpiry:         cfg.Session.SessionExpiry,
		IdleTimeout:           cfg.Session.IdleTimeout,
		MaxConcurrentSessions: cfg.Session.MaxConcurrentSessions,
		HIPAACompliant:        cfg.Session.HIPAACompliant,
	}

	if cfg.Session.HIPAACompliant {
		logging.Logger.Info("HIPAA compliance mode enabled",
			zap.Duration("idle_timeout", cfg.Session.IdleTimeout),
			zap.Int("max_concurrent_sessions", cfg.Session.MaxConcurrentSessions))
	} else {
		logging.Logger.Info("Standard session mode (HIPAA compliance disabled)",
			zap.Duration("session_expiry", cfg.Session.SessionExpiry))
	}

	// Initialize logger
	logger := service.NewDefaultLogger(service.LogLevelInfo)

	// Initialize auth service
	authService := service.NewAuthService(
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
		auditService,
		loginProtectionService,
		passwordHistoryService,
		sessionConfig,
		logger,
	)

	// Initialize membership service for team management
	membershipService := service.NewMembershipService(
		membershipRepo,
		userRepo,
		emailService,
		auditService,
		cfg.Server.AppURL,
		logger,
	)

	// Initialize tenant client (optional - for getting tenant names)
	tenantClient, err := service.NewTenantClient(&service.TenantClientConfig{
		Address: cfg.Tenant.Address,
		Timeout: cfg.Tenant.Timeout,
	})
	if err != nil {
		logging.Logger.Warn("Failed to initialize tenant client - team features may be limited", zap.Error(err))
	}

	// Create TeamAuthService that wraps AuthService with team functionality
	teamAuthService := service.NewTeamAuthService(authService, membershipService, tenantClient)

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(service.UnaryAuthInterceptor()),
	)

	// Register service - use teamAuthService which includes both auth and team functionality
	authv1.RegisterAuthServiceServer(grpcServer, teamAuthService)

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	// Set initial health status - verify database connectivity
	if err := db.Ping(); err != nil {
		logging.Logger.Warn("Database health check failed", zap.Error(err))
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		healthServer.SetServingStatus("auth.v1.AuthService", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	} else {
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		healthServer.SetServingStatus("auth.v1.AuthService", grpc_health_v1.HealthCheckResponse_SERVING)
	}

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start server
	listener, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		logging.Logger.Fatal("Failed to listen", zap.Error(err))
	}

	logging.Logger.Info("Auth service listening", zap.String("address", cfg.Server.Address))

	// Graceful shutdown
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			logging.Logger.Fatal("Failed to serve", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logging.Logger.Info("Shutting down server...")
	grpcServer.GracefulStop()
}
