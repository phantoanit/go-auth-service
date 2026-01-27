package repository

import (
	"context"

	"github.com/vhvplatform/go-auth-service/internal/domain"
)

// TenantRepositoryInterface định nghĩa contract cho Tenant repository
// Cho phép swap giữa MongoDB và PostgreSQL implementations
type TenantRepositoryInterface interface {
	FindByID(ctx context.Context, id string) (*domain.Tenant, error)
}
