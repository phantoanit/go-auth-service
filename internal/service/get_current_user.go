package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/vhvplatform/go-auth-service/internal/domain"
	pb "github.com/vhvplatform/go-auth-service/internal/pb/auth/v1"
	"github.com/vhvplatform/go-shared/errors"
	"go.uber.org/zap"
)

// GetCurrentUser retrieves full user information from opaque token
func (s *AuthService) GetCurrentUser(ctx context.Context, req *pb.GetCurrentUserRequest) (*pb.GetCurrentUserResponse, error) {
	s.logger.Info("GetCurrentUser request")

	if req.AccessToken == "" {
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "Access token is required",
		}, errors.BadRequest("Access token is required")
	}

	// Validate opaque token and get session data
	if s.tokenManager == nil {
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "Token manager not available",
		}, errors.Internal("Token manager not initialized")
	}

	session, err := s.tokenManager.ValidateToken(ctx, req.AccessToken)
	if err != nil {
		s.logger.Warn("Invalid or expired token", zap.Error(err))
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "Invalid or expired token",
		}, errors.Unauthorized("Invalid or expired token")
	}

	// Parse UUIDs
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "Invalid user ID in session",
		}, errors.Internal("Invalid user ID")
	}

	tenantID, err := uuid.Parse(session.TenantID)
	if err != nil {
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "Invalid tenant ID in session",
		}, errors.Internal("Invalid tenant ID")
	}

	// Load full user info from database
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil || user == nil {
		s.logger.Error("Failed to load user", zap.Error(err))
		return &pb.GetCurrentUserResponse{
			Success: false,
			Message: "User not found",
		}, errors.NotFound("User not found")
	}

	// Load tenant info
	s.logger.Info("Loading tenant info", zap.String("tenant_id", tenantID.String()))
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID.String())
	if err != nil {
		s.logger.Error("Failed to load tenant",
			zap.String("tenant_id", tenantID.String()),
			zap.Error(err))
		// Continue even if tenant not found
	} else if tenant == nil {
		s.logger.Warn("Tenant not found in database",
			zap.String("tenant_id", tenantID.String()))
	} else {
		s.logger.Info("Tenant loaded successfully",
			zap.String("tenant_id", tenant.ID.String()),
			zap.String("tenant_name", tenant.Name),
			zap.String("tenant_code", tenant.Code))
	}

	// Build user info
	userInfo := &pb.UserInfo{
		Id:       user.ID.String(),
		Username: user.Email, // Use email as username
		FullName: user.FullName,
		Email:    user.Email,
		Role: func() string {
			if len(session.Roles) > 0 {
				return session.Roles[0]
			}
			return "user"
		}(),
		PhoneNumber: func() string {
			if user.PhoneNumber != nil {
				return *user.PhoneNumber
			}
			return ""
		}(),
		AvatarUrl: func() string {
			if user.AvatarURL != nil {
				return *user.AvatarURL
			}
			return ""
		}(),
		Status:         user.Status,
		IsVerified:     user.IsVerified,
		MfaEnabled:     user.MFAEnabled,
		IsSupportStaff: user.IsSupportStaff,
		Locale:         user.Locale,
		Metadata:       user.Metadata,
	}

	// Build tenant info
	tenantInfo := &pb.TenantInfo{}
	if tenant != nil {
		tenantInfo.Id = tenant.ID.String()
		tenantInfo.Name = tenant.Name
		tenantInfo.Code = tenant.Code
		tenantInfo.Status = tenant.Status
		tenantInfo.Plan = "FREE"   // TODO: Get actual plan from tenant
		tenantInfo.Settings = "{}" // TODO: Get actual settings
	}

	// Build response
	response := &pb.GetCurrentUserResponse{
		Success:     true,
		Message:     "User info retrieved successfully",
		User:        userInfo,
		Tenant:      tenantInfo,
		Permissions: session.Permissions,
		IpAddress:   session.IPAddress,
		UserAgent:   session.UserAgent,
	}

	s.logger.Info("GetCurrentUser successful",
		zap.String("user_id", user.ID.String()),
		zap.String("tenant_id", session.TenantID))

	return response, nil
}

// GetCurrentUserDomain is the domain service method (for internal use)
func (s *AuthService) GetCurrentUserDomain(ctx context.Context, accessToken string) (*domain.CurrentUserInfo, error) {
	// Validate opaque token
	if s.tokenManager == nil {
		return nil, errors.Internal("Token manager not initialized")
	}

	session, err := s.tokenManager.ValidateToken(ctx, accessToken)
	if err != nil {
		return nil, errors.Unauthorized("Invalid or expired token")
	}

	// Parse UUIDs
	userID, err := uuid.Parse(session.UserID)
	if err != nil {
		return nil, errors.Internal("Invalid user ID")
	}

	tenantID, err := uuid.Parse(session.TenantID)
	if err != nil {
		return nil, errors.Internal("Invalid tenant ID")
	}

	// Load user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil || user == nil {
		return nil, errors.NotFound("User not found")
	}

	// Load tenant
	tenant, err := s.tenantRepo.FindByID(ctx, tenantID.String())
	if err != nil {
		tenant = nil // Optional
	}

	return &domain.CurrentUserInfo{
		UserID:    user.ID.String(),
		Email:     user.Email,
		Username:  user.Email,
		FirstName: user.FullName,
		LastName:  "",
		Phone: func() string {
			if user.PhoneNumber != nil {
				return *user.PhoneNumber
			}
			return ""
		}(),
		Status:   user.Status,
		TenantID: session.TenantID,
		TenantName: func() string {
			if tenant != nil {
				return tenant.Name
			}
			return ""
		}(),
		TenantCode: func() string {
			if tenant != nil {
				return tenant.Code
			}
			return ""
		}(),
		Roles:       session.Roles,
		Permissions: session.Permissions,
		IPAddress:   session.IPAddress,
		UserAgent:   session.UserAgent,
		IssuedAt:    session.IssuedAt,
		ExpiresAt:   session.ExpiresAt,
	}, nil
}
