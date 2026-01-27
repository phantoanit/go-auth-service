package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/vhvplatform/go-auth-service/internal/domain"
)

// TenantRepository handles tenant data from YugabyteDB
type TenantRepository struct {
	db *sql.DB
}

// NewTenantRepository creates a tenant repository for YugabyteDB
func NewTenantRepository(db *sql.DB) *TenantRepository {
	return &TenantRepository{db: db}
}

// FindByID finds tenant by UUID from YugabyteDB
func (r *TenantRepository) FindByID(ctx context.Context, id string) (*domain.Tenant, error) {
	query := `
		SELECT id, code, name, status
		FROM core.tenants
		WHERE id = $1 AND deleted_at IS NULL
	`

	var tenant domain.Tenant
	var code sql.NullString
	var name sql.NullString

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&tenant.ID,
		&code,
		&name,
		&tenant.Status,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find tenant: %w", err)
	}

	if code.Valid {
		tenant.Code = code.String
	}
	if name.Valid {
		tenant.Name = name.String
	}

	return &tenant, nil
}

// FindByCode finds tenant by code from YugabyteDB
func (r *TenantRepository) FindByCode(ctx context.Context, code string) (*domain.Tenant, error) {
	query := `
		SELECT id, code, name, status
		FROM core.tenants
		WHERE code = $1 AND deleted_at IS NULL
	`

	var tenant domain.Tenant
	var codeVal sql.NullString
	var name sql.NullString

	err := r.db.QueryRowContext(ctx, query, code).Scan(
		&tenant.ID,
		&codeVal,
		&name,
		&tenant.Status,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find tenant: %w", err)
	}

	if codeVal.Valid {
		tenant.Code = codeVal.String
	}
	if name.Valid {
		tenant.Name = name.String
	}

	return &tenant, nil
}
