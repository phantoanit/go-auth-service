package domain

import "time"

// CurrentUserInfo represents complete user information from session
type CurrentUserInfo struct {
	// User info
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Phone     string `json:"phone"`
	Status    string `json:"status"`

	// Tenant info
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	TenantCode string `json:"tenant_code"`

	// Authorization
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`

	// Session info
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}
