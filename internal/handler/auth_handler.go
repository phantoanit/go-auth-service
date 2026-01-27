package handler

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	pb "github.com/vhvplatform/go-auth-service/internal/pb/auth/v1"
	"github.com/vhvplatform/go-auth-service/internal/service"
	"github.com/vhvplatform/go-shared/logger"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthHandler implements the gRPC auth service following the new architecture
type AuthHandler struct {
	pb.UnimplementedAuthServiceServer
	authService *service.AuthService
	logger      *logger.Logger
}

// NewAuthHandler creates a new gRPC auth service handler
func NewAuthHandler(authService *service.AuthService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		logger:      log,
	}
}

// Login authenticates a user following authentication_flow.md
func (h *AuthHandler) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Extract tenant_id from gRPC metadata (X-Tenant-Id header)
	// tenant_id MUST come from header, not body
	tenantID := ""
	clientIP := "unknown"
	userAgent := "unknown"
	traceID := ""

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// Extract tenant_id from X-Tenant-Id header
		if tenants := md.Get("x-tenant-id"); len(tenants) > 0 {
			tenantID = tenants[0]
		}

		// Extract IP address (priority: x-real-ip > x-forwarded-for)
		if ips := md.Get("x-real-ip"); len(ips) > 0 {
			clientIP = ips[0]
		} else if ips := md.Get("x-forwarded-for"); len(ips) > 0 {
			clientIP = ips[0]
		}

		// Extract User-Agent
		if agents := md.Get("x-user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		} else if agents := md.Get("user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		} else if agents := md.Get("grpcgateway-user-agent"); len(agents) > 0 {
			userAgent = agents[0]
		}

		// Extract Trace ID
		if traces := md.Get("x-trace-id"); len(traces) > 0 {
			traceID = traces[0]
		}
	}

	h.logger.Info("Login request received",
		zap.String("identifier", req.Identifier),
		zap.String("tenant_id", tenantID))

	// Validate request
	if req.Identifier == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if tenantID == "" {
		return nil, status.Error(codes.InvalidArgument, "X-Tenant-Id header is required")
	}

	// Parse tenant UUID
	tenantUUID, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tenant_id format in X-Tenant-Id header")
	}

	// Store metadata in context for service layer
	ctx = context.WithValue(ctx, "client_ip", clientIP)
	ctx = context.WithValue(ctx, "user_agent", userAgent)
	ctx = context.WithValue(ctx, "trace_id", traceID)

	h.logger.Info("Client metadata extracted",
		zap.String("ip", clientIP),
		zap.String("user_agent", userAgent),
		zap.String("trace_id", traceID))

	// Attempt login using new architecture
	response, err := h.authService.Login(ctx, tenantUUID, req.Identifier, req.Password)
	if err != nil {
		h.logger.Warn("Login failed",
			zap.String("identifier", req.Identifier),
			zap.String("tenant_id", tenantID),
			zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "Invalid credentials")
	}

	// Set HttpOnly cookies via gRPC header metadata (Phantom Token Pattern)
	// grpc-gateway will convert these to Set-Cookie HTTP headers
	expiresIn := response.ExpiresIn
	if expiresIn == 0 {
		expiresIn = 3600 // Default 1 hour
	}
	refreshExpiresIn := int64(7 * 24 * 3600) // 7 days

	cookieMD := metadata.Pairs(
		"set-cookie", fmt.Sprintf("access_token=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax", response.AccessToken, expiresIn),
		"set-cookie", fmt.Sprintf("refresh_token=%s; HttpOnly; Path=/; Max-Age=%d; SameSite=Lax", response.RefreshToken, refreshExpiresIn),
	)
	if err := grpc.SetHeader(ctx, cookieMD); err != nil {
		h.logger.Warn("Failed to set cookie headers", zap.Error(err))
	}

	h.logger.Info("Login successful, cookies set via gRPC metadata",
		zap.String("user_id", response.User.ID),
		zap.Int64("expires_in", expiresIn))

	return &pb.LoginResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		TokenType:    response.TokenType,
		ExpiresIn:    response.ExpiresIn,
		User: &pb.LoginUserInfo{
			UserId:   response.User.ID,
			Email:    response.User.Email,
			TenantId: response.User.TenantID,
			Roles:    response.User.Roles,
		},
	}, nil
}

// LoginWithOAuth handles OAuth provider login (Google, GitHub, etc.)
func (h *AuthHandler) LoginWithOAuth(ctx context.Context, req *pb.OAuthLoginRequest) (*pb.LoginResponse, error) {
	h.logger.Info("OAuth login request received",
		zap.String("provider", req.Provider),
		zap.String("subject_id", req.ProviderSubjectId))

	// Validate request
	if req.Provider == "" {
		return nil, status.Error(codes.InvalidArgument, "provider is required")
	}
	if req.ProviderSubjectId == "" {
		return nil, status.Error(codes.InvalidArgument, "provider_subject_id is required")
	}

	// Call OAuth login service
	response, err := h.authService.LoginWithOAuth(ctx, req.Provider, req.ProviderSubjectId, req.Email)
	if err != nil {
		h.logger.Warn("OAuth login failed",
			zap.String("provider", req.Provider),
			zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}

	return &pb.LoginResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		TokenType:    response.TokenType,
		ExpiresIn:    response.ExpiresIn,
		User: &pb.LoginUserInfo{
			UserId:   response.User.ID,
			Email:    response.User.Email,
			TenantId: response.User.TenantID,
			Roles:    response.User.Roles,
		},
	}, nil
}

// ValidateToken validates a JWT token
func (h *AuthHandler) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	h.logger.Debug("Validate token request received")

	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	response, err := h.authService.ValidateToken(ctx, req.Token)
	if err != nil {
		h.logger.Warn("Token validation failed", zap.Error(err))
		return &pb.ValidateTokenResponse{
			Valid:        false,
			ErrorMessage: "Invalid token",
		}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:       response.Valid,
		UserId:      response.UserID,
		TenantId:    response.TenantID,
		Email:       response.Email,
		Roles:       response.Roles,
		Permissions: response.Permissions,
	}, nil
}

// RefreshToken refreshes an access token
func (h *AuthHandler) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	h.logger.Info("Refresh token request received")

	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh_token is required")
	}

	// Call refresh token service
	response, err := h.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		h.logger.Warn("Token refresh failed", zap.Error(err))
		return nil, status.Error(codes.Unauthenticated, "Invalid or expired refresh token")
	}

	return &pb.RefreshTokenResponse{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		TokenType:    response.TokenType,
		ExpiresIn:    response.ExpiresIn,
	}, nil
}

// Register registers a new user
func (h *AuthHandler) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	h.logger.Info("Register request received",
		zap.String("email", req.Email),
		zap.String("tenant_id", req.TenantId))

	// Validate required fields
	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "password is required")
	}
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Parse tenant UUID
	tenantID, err := uuid.Parse(req.TenantId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid tenant_id format")
	}

	// Prepare full name
	fullName := req.FirstName
	if req.LastName != "" {
		if fullName != "" {
			fullName += " " + req.LastName
		} else {
			fullName = req.LastName
		}
	}
	if fullName == "" {
		fullName = req.Email // Default to email if no name provided
	}

	// Prepare phone (optional)
	var phone *string
	if req.Phone != "" {
		phone = &req.Phone
	}

	// Call registration service
	user, err := h.authService.Register(ctx, tenantID, req.Email, req.Password, fullName, phone)
	if err != nil {
		h.logger.Warn("Registration failed",
			zap.String("email", req.Email),
			zap.Error(err))
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &pb.RegisterResponse{
		UserId:  user.ID.String(),
		Message: "Registration successful. Please verify your email.",
	}, nil
}

// VerifyEmail verifies a user's email address
func (h *AuthHandler) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
	h.logger.Info("Verify email request received")

	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Parse optional user_id
	var userID *uuid.UUID
	if req.UserId != "" {
		uid, err := uuid.Parse(req.UserId)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
		}
		userID = &uid
	}

	// Call verification service
	err := h.authService.VerifyEmail(ctx, req.Token, userID)
	if err != nil {
		h.logger.Warn("Email verification failed", zap.Error(err))
		return &pb.VerifyEmailResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully",
		UserId:  req.UserId,
	}, nil
}

// ResendVerificationEmail resends email verification token
func (h *AuthHandler) ResendVerificationEmail(ctx context.Context, req *pb.ResendVerificationEmailRequest) (*pb.ResendVerificationEmailResponse, error) {
	h.logger.Info("Resend verification email request received",
		zap.String("email", req.Email))

	if req.Email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if req.TenantId == "" {
		return nil, status.Error(codes.InvalidArgument, "tenant_id is required")
	}

	// Call send verification service
	err := h.authService.SendVerificationEmail(ctx, req.Email, req.TenantId)
	if err != nil {
		h.logger.Warn("Failed to send verification email", zap.Error(err))
		return &pb.ResendVerificationEmailResponse{
			Success: false,
			Message: err.Error(),
		}, nil
	}

	return &pb.ResendVerificationEmailResponse{
		Success: true,
		Message: "Verification email sent successfully",
	}, nil
}

// GetCurrentUser retrieves current user info from opaque token
func (h *AuthHandler) GetCurrentUser(ctx context.Context, req *pb.GetCurrentUserRequest) (*pb.GetCurrentUserResponse, error) {
	h.logger.Info("GetCurrentUser request received")

	// Try to get access_token from request first, then from cookie
	accessToken := req.AccessToken
	if accessToken == "" {
		// Extract from cookie via gRPC metadata (grpc-gateway forwards cookies)
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			// grpc-gateway forwards cookies in "grpcgateway-cookie" header
			if cookies := md.Get("grpcgateway-cookie"); len(cookies) > 0 {
				accessToken = extractCookieValue(cookies[0], "access_token")
			}
			// Also try standard cookie header
			if accessToken == "" {
				if cookies := md.Get("cookie"); len(cookies) > 0 {
					accessToken = extractCookieValue(cookies[0], "access_token")
				}
			}
		}
	}

	h.logger.Info("GetCurrentUser: Token resolution",
		zap.Bool("from_request", req.AccessToken != ""),
		zap.Bool("from_cookie", accessToken != "" && req.AccessToken == ""),
		zap.Bool("token_found", accessToken != ""))

	// Create new request with resolved token
	resolvedReq := &pb.GetCurrentUserRequest{
		AccessToken: accessToken,
	}

	// Delegate to service layer
	return h.authService.GetCurrentUser(ctx, resolvedReq)
}

// extractCookieValue extracts a specific cookie value from cookie header string
func extractCookieValue(cookieHeader, name string) string {
	cookies := strings.Split(cookieHeader, ";")
	for _, cookie := range cookies {
		cookie = strings.TrimSpace(cookie)
		if strings.HasPrefix(cookie, name+"=") {
			return strings.TrimPrefix(cookie, name+"=")
		}
	}
	return ""
}
