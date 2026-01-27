package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a user's global identity in core.users table
type User struct {
	ID             uuid.UUID  `json:"id"`
	Email          string     `json:"email"`
	FullName       string     `json:"full_name"`
	PhoneNumber    *string    `json:"phone_number,omitempty"`
	AvatarURL      *string    `json:"avatar_url,omitempty"`
	Status         string     `json:"status"` // ACTIVE, BANNED, DISABLED, PENDING
	IsSupportStaff bool       `json:"is_support_staff"`
	MFAEnabled     bool       `json:"mfa_enabled"`
	MFASecret      *string    `json:"-"` // Never expose in API
	IsVerified     bool       `json:"is_verified"`
	Locale         string     `json:"locale"`   // Default: vi-VN
	Metadata       string     `json:"metadata"` // JSONB as string
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	DeletedAt      *time.Time `json:"deleted_at,omitempty"`
}

// UserIdentity represents an authentication method in core.user_identities table
type UserIdentity struct {
	ID               uuid.UUID  `json:"id"`
	UserID           uuid.UUID  `json:"user_id"`
	IdentityType     string     `json:"identity_type"`  // PASSWORD, GOOGLE, GITHUB, etc.
	IdentityValue    string     `json:"identity_value"` // Canonical value
	CredentialSecret *string    `json:"-"`              // Password hash (Argon2id) - never expose
	Metadata         string     `json:"metadata"`       // JSONB: OAuth tokens, profile
	IsVerified       bool       `json:"is_verified"`
	VerifiedAt       *time.Time `json:"verified_at,omitempty"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	Version          int        `json:"version"`
}

// AuthIdentifier represents the index table for fast login lookup
type AuthIdentifier struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	IdentifierHash []byte    `json:"-"` // SHA256 hash - never expose
	UserID         uuid.UUID `json:"user_id"`
	IdentityID     uuid.UUID `json:"identity_id"`
	IdentifierType string    `json:"identifier_type"`          // email, phone, username, passport
	OriginalValue  *string   `json:"original_value,omitempty"` // For display/debug only
}

// Tenant represents a tenant (from core.tenants) - read-only for auth service
type Tenant struct {
	ID     uuid.UUID `json:"id"`
	Code   string    `json:"code"`
	Name   string    `json:"name"`
	Status string    `json:"status"` // TRIAL, ACTIVE, SUSPENDED, CANCELLED
}

// TenantMember represents a member in a tenant (from core.tenant_members)
type TenantMember struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	UserID      uuid.UUID  `json:"user_id"`
	DisplayName *string    `json:"display_name,omitempty"`
	Status      string     `json:"status"` // INVITED, ACTIVE, SUSPENDED, RESIGNED
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

// Session represents a user session stored in Redis (unchanged)
type Session struct {
	UserID    string    `json:"user_id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Roles     []string  `json:"roles"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// LoginResponse represents a successful login response
type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int64    `json:"expires_in"`
	User         UserInfo `json:"user"`
}

// UserInfo represents brief user information in login response
type UserInfo struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	TenantID string   `json:"tenant_id"`
	Roles    []string `json:"roles"`
}

// ValidateTokenResponse represents the result of token validation
type ValidateTokenResponse struct {
	Valid        bool              `json:"valid"`
	UserID       string            `json:"user_id"`
	TenantID     string            `json:"tenant_id"`
	Email        string            `json:"email"`
	Roles        []string          `json:"roles"`
	Permissions  []string          `json:"permissions"`
	ErrorMessage string            `json:"error_message,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}
