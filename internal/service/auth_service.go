package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vhvplatform/go-auth-service/internal/domain"
	"github.com/vhvplatform/go-auth-service/internal/repository"
	"github.com/vhvplatform/go-shared/errors"
	"github.com/vhvplatform/go-shared/jwt"
	"github.com/vhvplatform/go-shared/logger"
	"github.com/vhvplatform/go-shared/redis"
	"github.com/vhvplatform/go-shared/token"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"
)

// AuthService handles authentication business logic following the new architecture
type AuthService struct {
	authIdentifierRepo    *repository.AuthIdentifierRepository
	userIdentityRepo      *repository.UserIdentityRepository
	userRepo              *repository.UserRepository
	tenantRepo            *repository.TenantRepository
	tenantMemberRepo      *repository.TenantMemberRepository
	refreshTokenRepo      *repository.RefreshTokenRepository
	emailVerificationRepo *repository.EmailVerificationRepository
	jwtManager            *jwt.Manager
	tokenManager          *token.Manager
	redisCache            *redis.Cache
	logger                *logger.Logger
}

// NewAuthService creates a new auth service
func NewAuthService(
	authIdentifierRepo *repository.AuthIdentifierRepository,
	userIdentityRepo *repository.UserIdentityRepository,
	userRepo *repository.UserRepository,
	tenantRepo *repository.TenantRepository,
	tenantMemberRepo *repository.TenantMemberRepository,
	refreshTokenRepo *repository.RefreshTokenRepository,
	emailVerificationRepo *repository.EmailVerificationRepository,
	jwtManager *jwt.Manager,
	redisClient *redis.Client,
	log *logger.Logger,
) *AuthService {
	var redisCache *redis.Cache
	var tokenMgr *token.Manager

	if redisClient != nil {
		redisCache = redis.NewCache(redisClient, redis.CacheConfig{
			DefaultTTL: 24 * time.Hour,
			KeyPrefix:  "auth",
		})

		// Initialize opaque token manager
		// Access token: 15 minutes, Refresh token: 30 days
		tokenMgr = token.NewManager(redisClient, 15*time.Minute, 30*24*time.Hour)
	}

	return &AuthService{
		authIdentifierRepo:    authIdentifierRepo,
		userIdentityRepo:      userIdentityRepo,
		userRepo:              userRepo,
		tenantRepo:            tenantRepo,
		tenantMemberRepo:      tenantMemberRepo,
		refreshTokenRepo:      refreshTokenRepo,
		emailVerificationRepo: emailVerificationRepo,
		jwtManager:            jwtManager,
		tokenManager:          tokenMgr,
		redisCache:            redisCache,
		logger:                log,
	}
}

// Login implements the authentication flow as described in authentication_flow.md
// Steps:
// 1. Normalize input (email lowercase, phone E.164)
// 2. Hash identifiers (SHA256)
// 3. Point lookup in auth_identifiers table
// 4. Verify credential in user_identities table
// 5. Generate JWT tokens
func (s *AuthService) Login(ctx context.Context, tenantID uuid.UUID, identifier, password string) (*domain.LoginResponse, error) {
	s.logger.Info("Login attempt",
		zap.String("tenant_id", tenantID.String()),
		zap.String("identifier", identifier),
	)

	// Step 1: Normalize input
	normalized := s.normalizeIdentifier(identifier)

	// Step 2: Generate hashes for possible identifier types
	// Try email, phone, passport patterns
	hashes := s.generateIdentifierHashes(tenantID.String(), normalized)

	// Step 3: Point lookup in auth_identifiers
	authIdent, err := s.authIdentifierRepo.FindByHashes(ctx, tenantID, hashes)
	if err != nil {
		s.logger.Error("Failed to find auth identifier", zap.Error(err))
		return nil, errors.Internal("Authentication failed")
	}
	if authIdent == nil {
		s.logger.Warn("Invalid identifier", zap.String("identifier", identifier))
		return nil, errors.Unauthorized("Invalid identifier or password")
	}

	// Step 4: Get user identity and verify password
	identity, err := s.userIdentityRepo.FindByID(ctx, authIdent.IdentityID)
	if err != nil {
		s.logger.Error("Failed to find user identity", zap.Error(err))
		return nil, errors.Internal("Authentication failed")
	}
	if identity == nil || identity.IdentityType != "PASSWORD" {
		return nil, errors.Unauthorized("Invalid authentication method")
	}

	// Verify password using Argon2id
	if !s.verifyPassword(password, *identity.CredentialSecret) {
		s.logger.Warn("Invalid password", zap.String("user_id", authIdent.UserID.String()))
		return nil, errors.Unauthorized("Invalid identifier or password")
	}

	// Step 5: Load user profile
	user, err := s.userRepo.FindByID(ctx, authIdent.UserID)
	if err != nil || user == nil {
		s.logger.Error("Failed to find user", zap.Error(err))
		return nil, errors.Internal("Authentication failed")
	}

	// Check user status
	if user.Status != "ACTIVE" {
		return nil, errors.Forbidden(fmt.Sprintf("Account is %s", user.Status))
	}

	// Step 6: Update last login timestamp
	if err := s.userIdentityRepo.UpdateLastLogin(ctx, identity.ID); err != nil {
		s.logger.Error("Failed to update last login", zap.Error(err))
		// Non-fatal, continue
	}

	// Step 7: Load roles and permissions from tenant_members
	roles, err := s.tenantMemberRepo.GetUserRoleCodes(ctx, user.ID, tenantID)
	if err != nil {
		s.logger.Error("Failed to load user roles", zap.Error(err))
		roles = []string{} // Default to empty if error
	}

	permissions, err := s.tenantMemberRepo.GetUserPermissions(ctx, user.ID, tenantID)
	if err != nil {
		s.logger.Error("Failed to load user permissions", zap.Error(err))
		permissions = []string{} // Default to empty if error
	}

	// Step 8: Generate Opaque Tokens with Redis session storage
	var accessToken, refreshToken string

	// Extract client metadata from context
	ipAddress := "unknown"
	userAgent := "unknown"
	traceID := ""

	if ip, ok := ctx.Value("client_ip").(string); ok && ip != "" {
		ipAddress = ip
	}
	if ua, ok := ctx.Value("user_agent").(string); ok && ua != "" {
		userAgent = ua
	}
	if tid, ok := ctx.Value("trace_id").(string); ok && tid != "" {
		traceID = tid
	}

	// Use opaque token manager if available (recommended for web apps)
	if s.tokenManager != nil {
		// Generate opaque access token (stored in Redis)
		accessToken, err = s.tokenManager.GenerateAccessToken(
			ctx,
			user.ID.String(),
			tenantID.String(),
			user.Email,
			roles,
			permissions,
			ipAddress,
			userAgent,
			traceID,
		)
		if err != nil {
			s.logger.Error("Failed to generate opaque access token", zap.Error(err))
			return nil, errors.Internal("Failed to generate token")
		}

		// Generate opaque refresh token (stored in Redis)
		refreshToken, err = s.tokenManager.GenerateRefreshToken(
			ctx,
			user.ID.String(),
			tenantID.String(),
			ipAddress,
			userAgent,
		)
		if err != nil {
			s.logger.Error("Failed to generate opaque refresh token", zap.Error(err))
			return nil, errors.Internal("Failed to generate refresh token")
		}

		s.logger.Info("Generated opaque tokens (stored in Redis)",
			zap.String("user_id", user.ID.String()),
			zap.String("tenant_id", tenantID.String()),
			zap.String("ip", ipAddress),
			zap.String("trace_id", traceID))
	} else {
		// Fallback to JWT tokens if Redis not available
		accessToken, err = s.jwtManager.GenerateToken(
			user.ID.String(),
			tenantID.String(),
			user.Email,
			roles,
			permissions,
		)
		if err != nil {
			return nil, errors.Internal("Failed to generate token")
		}

		refreshToken, _ = s.jwtManager.GenerateRefreshToken(user.ID.String(), tenantID.String())

		s.logger.Warn("Generated JWT tokens (Redis not available, fallback mode)")
	}

	return &domain.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour in seconds (matches JWT config)
		User: domain.UserInfo{
			ID:       user.ID.String(),
			Email:    user.Email,
			TenantID: tenantID.String(),
			Roles:    roles,
		},
	}, nil
}

// Register creates a new user account with password authentication
func (s *AuthService) Register(ctx context.Context, tenantID uuid.UUID, email, password, fullName string, phone *string) (*domain.User, error) {
	s.logger.Info("User registration",
		zap.String("tenant_id", tenantID.String()),
		zap.String("email", email))

	// Step 1: Normalize and validate inputs
	normalizedEmail := s.normalizeIdentifier(email)
	if !strings.Contains(normalizedEmail, "@") {
		return nil, errors.BadRequest("Invalid email format")
	}

	// Step 2: Check if email already exists
	existingUser, err := s.userRepo.FindByEmail(ctx, normalizedEmail)
	if err != nil {
		s.logger.Error("Failed to check existing user", zap.Error(err))
		return nil, errors.Internal("Registration failed")
	}
	if existingUser != nil {
		return nil, errors.Conflict("Email already registered")
	}

	// Step 3: Hash password
	hashedPassword, err := s.hashPassword(password)
	if err != nil {
		s.logger.Error("Failed to hash password", zap.Error(err))
		return nil, errors.Internal("Registration failed")
	}

	// Step 4: Create user record
	user := &domain.User{
		ID:             uuid.Must(uuid.NewV7()),
		Email:          normalizedEmail,
		FullName:       fullName,
		PhoneNumber:    phone,
		Status:         "PENDING", // Requires email verification
		IsSupportStaff: false,
		MFAEnabled:     false,
		IsVerified:     false,
		Locale:         "vi-VN",
		Metadata:       "{}",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Error("Failed to create user", zap.Error(err))
		return nil, errors.Internal("Registration failed")
	}

	// Step 5: Create user identity (PASSWORD type)
	identity := &domain.UserIdentity{
		ID:               uuid.Must(uuid.NewV7()),
		UserID:           user.ID,
		IdentityType:     "PASSWORD",
		IdentityValue:    normalizedEmail,
		CredentialSecret: &hashedPassword,
		Metadata:         "{}",
		IsVerified:       false,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
		Version:          1,
	}

	if err := s.userIdentityRepo.Create(ctx, identity); err != nil {
		s.logger.Error("Failed to create identity", zap.Error(err))
		// Rollback: delete user (or use transaction)
		return nil, errors.Internal("Registration failed")
	}

	// Step 6: Create auth_identifier for email
	emailHash := sha256.Sum256([]byte("email:" + normalizedEmail))
	authIdentifier := &domain.AuthIdentifier{
		TenantID:       tenantID,
		IdentifierHash: emailHash[:],
		UserID:         user.ID,
		IdentityID:     identity.ID,
		IdentifierType: "email",
		OriginalValue:  &normalizedEmail,
	}

	if err := s.authIdentifierRepo.Create(ctx, authIdentifier); err != nil {
		s.logger.Error("Failed to create auth identifier", zap.Error(err))
		return nil, errors.Internal("Registration failed")
	}

	// Step 7: If phone provided, create phone identifier
	if phone != nil && *phone != "" {
		normalizedPhone := s.normalizeIdentifier(*phone)
		phoneHash := sha256.Sum256([]byte("phone:" + normalizedPhone))
		phoneIdentifier := &domain.AuthIdentifier{
			TenantID:       tenantID,
			IdentifierHash: phoneHash[:],
			UserID:         user.ID,
			IdentityID:     identity.ID,
			IdentifierType: "phone",
			OriginalValue:  &normalizedPhone,
		}

		if err := s.authIdentifierRepo.Create(ctx, phoneIdentifier); err != nil {
			s.logger.Warn("Failed to create phone identifier", zap.Error(err))
			// Non-fatal, continue
		}
	}

	s.logger.Info("User registered successfully", zap.String("user_id", user.ID.String()))
	return user, nil
}

// LoginWithOAuth handles OAuth callback (Google, GitHub, etc.)
// As described in authentication_flow.md Section B
func (s *AuthService) LoginWithOAuth(ctx context.Context, provider, providerSubjectID, email string) (*domain.LoginResponse, error) {
	s.logger.Info("OAuth login attempt",
		zap.String("provider", provider),
		zap.String("subject_id", providerSubjectID),
	)

	// Query user_identities directly (not via auth_identifiers)
	identity, err := s.userIdentityRepo.FindByOAuth(ctx, provider, providerSubjectID)
	if err != nil {
		s.logger.Error("Failed to find OAuth identity", zap.Error(err))
		return nil, errors.Internal("Authentication failed")
	}

	if identity == nil {
		// User not found - need to create new user + identity
		// For now, return error (registration flow needed)
		return nil, errors.NotFound("User not registered. Please sign up first.")
	}

	// Load user profile
	user, err := s.userRepo.FindByID(ctx, identity.UserID)
	if err != nil || user == nil {
		return nil, errors.Internal("Failed to load user profile")
	}

	// Check user status
	if user.Status != "ACTIVE" {
		return nil, errors.Forbidden(fmt.Sprintf("Account is %s", user.Status))
	}

	// Update last login
	if err := s.userIdentityRepo.UpdateLastLogin(ctx, identity.ID); err != nil {
		s.logger.Error("Failed to update last login", zap.Error(err))
	}

	// Generate tokens (need tenant_id from context or request)
	// TODO: Determine tenant from domain or user selection
	tenantID := uuid.Nil // Placeholder
	roles := []string{}
	permissions := []string{}

	accessToken, err := s.jwtManager.GenerateToken(
		user.ID.String(),
		tenantID.String(),
		user.Email,
		roles,
		permissions,
	)
	if err != nil {
		return nil, errors.Internal("Failed to generate token")
	}

	refreshToken, err := s.jwtManager.GenerateRefreshToken(
		user.ID.String(),
		tenantID.String(),
	)
	if err != nil {
		return nil, errors.Internal("Failed to generate refresh token")
	}

	return &domain.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour in seconds (matches JWT config)
		User: domain.UserInfo{
			ID:       user.ID.String(),
			Email:    user.Email,
			TenantID: tenantID.String(),
			Roles:    roles,
		},
	}, nil
}

// normalizeIdentifier normalizes input according to authentication_flow.md
func (s *AuthService) normalizeIdentifier(input string) string {
	input = strings.TrimSpace(input)

	// Email: trim + lowercase
	if strings.Contains(input, "@") {
		return strings.ToLower(input)
	}

	// Phone: Convert to E.164 format
	if s.isPhoneNumber(input) {
		return s.normalizePhone(input)
	}

	// Passport/Username: already trimmed
	return input
}

// isPhoneNumber checks if input looks like a phone number
func (s *AuthService) isPhoneNumber(input string) bool {
	// Remove common phone separators
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, input)

	// Phone numbers typically have 8-15 digits
	digitCount := strings.Count(digits, "0") + strings.Count(digits, "1") +
		strings.Count(digits, "2") + strings.Count(digits, "3") +
		strings.Count(digits, "4") + strings.Count(digits, "5") +
		strings.Count(digits, "6") + strings.Count(digits, "7") +
		strings.Count(digits, "8") + strings.Count(digits, "9")

	return digitCount >= 8 && digitCount <= 15
}

// normalizePhone converts phone to E.164 format (+84909123456)
func (s *AuthService) normalizePhone(input string) string {
	// Check if has leading +
	hasPlus := strings.HasPrefix(input, "+")

	// Remove all non-digit characters
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, input)

	// If already has country code (starts with +)
	if hasPlus {
		// Special case: +84 (0) 909... format (Vietnam)
		// Check if it's Vietnam (+84) and has (0) prefix
		if strings.HasPrefix(digits, "840") && len(digits) >= 12 {
			// Remove the 0 after 84: 840909123456 -> 84909123456
			digits = digits[:2] + digits[3:]
		}
		return "+" + digits
	}

	// Handle Vietnam phone numbers (default country)
	// 0909123456 -> +84909123456
	if strings.HasPrefix(digits, "0") && len(digits) == 10 {
		return "+84" + digits[1:]
	}

	// Already in international format without +
	if len(digits) >= 11 {
		return "+" + digits
	}

	// Default: assume Vietnam mobile
	return "+84" + digits
}

// generateIdentifierHashes generates SHA256 hashes for all possible identifier types
func (s *AuthService) generateIdentifierHashes(tenantID, normalized string) [][]byte {
	var hashes [][]byte

	// Hash format: tenant_id:identifier
	// This matches the format used in auth_identifiers table
	hashInput := fmt.Sprintf("%s:%s", tenantID, normalized)
	hash := sha256.Sum256([]byte(hashInput))
	hashes = append(hashes, hash[:])

	return hashes
}

// verifyPassword verifies password using Argon2id
// Expected PHC format: $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
func (s *AuthService) verifyPassword(plainPassword, hashedPassword string) bool {
	// Parse PHC string format
	params, salt, hash, err := s.parseArgon2idHash(hashedPassword)
	if err != nil {
		s.logger.Error("Failed to parse password hash", zap.Error(err))
		return false
	}

	// Recompute hash with same parameters
	computedHash := argon2.IDKey(
		[]byte(plainPassword),
		salt,
		params.time,
		params.memory,
		params.threads,
		params.keyLen,
	)

	// Constant-time comparison to prevent timing attacks
	return subtleCompare(hash, computedHash)
}

// hashPassword hashes password using Argon2id with OWASP recommended parameters
func (s *AuthService) hashPassword(plainPassword string) (string, error) {
	// Argon2id parameters (OWASP 2023 recommendations)
	const (
		time    = 3         // Iterations
		memory  = 64 * 1024 // 64 MB
		threads = 4         // Parallelism
		keyLen  = 32        // 256-bit hash
		saltLen = 16        // 128-bit salt
	)

	// Generate cryptographically secure random salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Compute Argon2id hash
	hash := argon2.IDKey([]byte(plainPassword), salt, time, memory, threads, keyLen)

	// Encode salt and hash in base64
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	// Return PHC string format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads, saltB64, hashB64), nil
}

// ValidateToken validates a JWT token
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*domain.ValidateTokenResponse, error) {
	// Try opaque token validation first (if token manager available)
	if s.tokenManager != nil {
		session, err := s.tokenManager.ValidateToken(ctx, token)
		if err == nil && session != nil {
			// Valid opaque token found in Redis
			s.logger.Debug("Validated opaque token from Redis",
				zap.String("user_id", session.UserID),
				zap.String("tenant_id", session.TenantID))

			// Optionally extend session TTL (sliding window)
			_ = s.tokenManager.ExtendSession(ctx, token, 15*time.Minute)

			return &domain.ValidateTokenResponse{
				Valid:       true,
				UserID:      session.UserID,
				TenantID:    session.TenantID,
				Email:       session.Email,
				Roles:       session.Roles,
				Permissions: session.Permissions,
			}, nil
		}
		// If opaque token validation failed, fall through to JWT validation
		s.logger.Debug("Opaque token validation failed, trying JWT", zap.Error(err))
	}

	// Fallback: Try JWT validation (for backward compatibility)
	claims, err := s.jwtManager.ValidateToken(token)
	if err != nil {
		return &domain.ValidateTokenResponse{
			Valid:        false,
			ErrorMessage: "Invalid token",
		}, nil
	}

	return &domain.ValidateTokenResponse{
		Valid:    true,
		UserID:   claims.UserID,
		TenantID: claims.TenantID,
		Email:    claims.Email,
		Roles:    claims.Roles,
	}, nil
}

// RefreshToken handles refresh token rotation
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*domain.LoginResponse, error) {
	s.logger.Info("Refresh token request")

	// Try opaque token refresh first (if token manager available)
	if s.tokenManager != nil {
		session, err := s.tokenManager.ValidateToken(ctx, refreshToken)
		if err == nil && session != nil && session.TokenType == "REFRESH" {
			s.logger.Info("Validating opaque refresh token from Redis",
				zap.String("user_id", session.UserID),
				zap.String("tenant_id", session.TenantID))

			// Load user
			userID, err := uuid.Parse(session.UserID)
			if err != nil {
				return nil, errors.Internal("Invalid user ID in session")
			}

			tenantID, err := uuid.Parse(session.TenantID)
			if err != nil {
				return nil, errors.Internal("Invalid tenant ID in session")
			}

			user, err := s.userRepo.FindByID(ctx, userID)
			if err != nil || user == nil {
				return nil, errors.Internal("Failed to load user")
			}

			// Load roles and permissions
			roles, _ := s.tenantMemberRepo.GetUserRoleCodes(ctx, user.ID, tenantID)
			permissions, _ := s.tenantMemberRepo.GetUserPermissions(ctx, user.ID, tenantID)

			// Revoke old refresh token
			_ = s.tokenManager.RevokeToken(ctx, refreshToken)

			// Extract trace_id from context if available
			traceID := ""
			if tid, ok := ctx.Value("trace_id").(string); ok && tid != "" {
				traceID = tid
			}

			// Generate new access token (opaque)
			newAccessToken, err := s.tokenManager.GenerateAccessToken(
				ctx,
				user.ID.String(),
				tenantID.String(),
				user.Email,
				roles,
				permissions,
				session.IPAddress,
				session.UserAgent,
				traceID, // Use trace_id from context for new session
			)
			if err != nil {
				return nil, errors.Internal("Failed to generate access token")
			}

			// Generate new refresh token (opaque)
			newRefreshToken, err := s.tokenManager.GenerateRefreshToken(
				ctx,
				user.ID.String(),
				tenantID.String(),
				session.IPAddress,
				session.UserAgent,
			)
			if err != nil {
				return nil, errors.Internal("Failed to generate refresh token")
			}

			s.logger.Info("Opaque refresh token rotated successfully",
				zap.String("user_id", user.ID.String()))

			return &domain.LoginResponse{
				AccessToken:  newAccessToken,
				RefreshToken: newRefreshToken,
				TokenType:    "Bearer",
				ExpiresIn:    900, // 15 minutes
				User: domain.UserInfo{
					ID:       user.ID.String(),
					Email:    user.Email,
					TenantID: tenantID.String(),
					Roles:    roles,
				},
			}, nil
		}
		s.logger.Debug("Opaque refresh token validation failed, trying database", zap.Error(err))
	}

	// Fallback: Use database refresh token (legacy)
	newRefreshToken, err := s.refreshTokenRepo.Rotate(ctx, refreshToken, "{}", 30*24*time.Hour)
	if err != nil {
		s.logger.Warn("Refresh token rotation failed", zap.Error(err))
		return nil, errors.Unauthorized("Invalid or expired refresh token")
	}

	// Find token to get user info
	rt, err := s.refreshTokenRepo.FindByToken(ctx, newRefreshToken)
	if err != nil || rt == nil {
		return nil, errors.Internal("Failed to load refresh token")
	}

	// Load user
	user, err := s.userRepo.FindByID(ctx, rt.UserID)
	if err != nil || user == nil {
		return nil, errors.Internal("Failed to load user")
	}

	// Load roles and permissions
	roles, _ := s.tenantMemberRepo.GetUserRoleCodes(ctx, user.ID, rt.TenantID)
	permissions, _ := s.tenantMemberRepo.GetUserPermissions(ctx, user.ID, rt.TenantID)

	// Generate new access token (JWT fallback)
	accessToken, err := s.jwtManager.GenerateToken(
		user.ID.String(),
		rt.TenantID.String(),
		user.Email,
		roles,
		permissions,
	)
	if err != nil {
		return nil, errors.Internal("Failed to generate access token")
	}

	return &domain.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		User: domain.UserInfo{
			ID:       user.ID.String(),
			Email:    user.Email,
			TenantID: rt.TenantID.String(),
			Roles:    roles,
		},
	}, nil
}

// VerifyEmail verifies user's email with verification token
func (s *AuthService) VerifyEmail(ctx context.Context, token string, userID *uuid.UUID) error {
	s.logger.Info("Email verification attempt")

	// Verify token
	evt, err := s.emailVerificationRepo.Verify(ctx, token)
	if err != nil {
		s.logger.Warn("Email verification failed", zap.Error(err))
		// Increment attempts
		_ = s.emailVerificationRepo.IncrementAttempts(ctx, token)
		return errors.BadRequest(err.Error())
	}

	// Optional: validate userID matches
	if userID != nil && evt.UserID != *userID {
		return errors.Forbidden("Token does not belong to this user")
	}

	// Mark user as verified
	if err := s.userRepo.MarkVerified(ctx, evt.UserID); err != nil {
		s.logger.Error("Failed to mark user as verified", zap.Error(err))
		return errors.Internal("Failed to verify email")
	}

	// Update user status to ACTIVE
	if err := s.userRepo.UpdateStatus(ctx, evt.UserID, "ACTIVE"); err != nil {
		s.logger.Error("Failed to update user status", zap.Error(err))
		// Non-fatal, already marked as verified
	}

	s.logger.Info("Email verified successfully", zap.String("user_id", evt.UserID.String()))
	return nil
}

// SendVerificationEmail sends (or resends) email verification token
func (s *AuthService) SendVerificationEmail(ctx context.Context, email, tenantIDStr string) error {
	s.logger.Info("Send verification email", zap.String("email", email))

	// Parse tenant ID (for future use in email template)
	_, err := uuid.Parse(tenantIDStr)
	if err != nil {
		return errors.BadRequest("Invalid tenant ID")
	}

	// Find user by email
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return errors.Internal("Failed to find user")
	}
	if user == nil {
		return errors.NotFound("User not found")
	}

	// Check if already verified
	if user.IsVerified {
		return errors.BadRequest("Email already verified")
	}

	// Invalidate existing tokens
	if err := s.emailVerificationRepo.InvalidateExisting(ctx, user.ID, "REGISTRATION"); err != nil {
		s.logger.Warn("Failed to invalidate existing tokens", zap.Error(err))
	}

	// Create new verification token
	token, err := s.emailVerificationRepo.Create(ctx, user.ID, email, "REGISTRATION", 24*time.Hour, nil, nil)
	if err != nil {
		s.logger.Error("Failed to create verification token", zap.Error(err))
		return errors.Internal("Failed to create verification token")
	}

	// TODO: Send email with token
	// For now, just log it
	s.logger.Info("Verification token created",
		zap.String("user_id", user.ID.String()),
		zap.String("token", token),
		zap.String("email", email))

	// In production, call email service:
	// err = s.emailService.SendVerificationEmail(email, token, tenantID)

	return nil
}

// Logout revokes refresh tokens for a user
func (s *AuthService) Logout(ctx context.Context, userID, tenantID uuid.UUID, logoutAll bool) error {
	if logoutAll {
		// Logout from all devices
		return s.refreshTokenRepo.RevokeAllForUser(ctx, userID, tenantID, "User logout - all devices")
	}

	// For single device logout, need to pass the specific refresh token
	// This would be called from the handler with the actual token
	return nil
}
