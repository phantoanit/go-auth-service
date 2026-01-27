package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// TenantMember represents a user's membership in a tenant
type TenantMember struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	UserID      uuid.UUID
	DisplayName *string
	Status      string
	CustomData  string // JSONB
	JoinedAt    sql.NullTime
	CreatedAt   sql.NullTime
	UpdatedAt   sql.NullTime
	DeletedAt   sql.NullTime
	Version     int
}

// UserRole represents a role assignment for a user in a tenant
type UserRole struct {
	RoleID      uuid.UUID
	RoleCode    string
	RoleName    string
	Permissions []string
}

// TenantMemberRepository handles tenant member operations
type TenantMemberRepository struct {
	db *sql.DB
}

// NewTenantMemberRepository creates a new tenant member repository
func NewTenantMemberRepository(db *sql.DB) *TenantMemberRepository {
	return &TenantMemberRepository{db: db}
}

// FindByUserAndTenant finds a tenant member by user_id and tenant_id
func (r *TenantMemberRepository) FindByUserAndTenant(ctx context.Context, userID, tenantID uuid.UUID) (*TenantMember, error) {
	query := `
		SELECT id, tenant_id, user_id, display_name, status,
			   custom_data, joined_at, created_at, updated_at, deleted_at, version
		FROM core.tenant_members
		WHERE user_id = $1
		AND tenant_id = $2
		AND deleted_at IS NULL
	`

	member := &TenantMember{}
	err := r.db.QueryRowContext(ctx, query, userID, tenantID).Scan(
		&member.ID,
		&member.TenantID,
		&member.UserID,
		&member.DisplayName,
		&member.Status,
		&member.CustomData,
		&member.JoinedAt,
		&member.CreatedAt,
		&member.UpdatedAt,
		&member.DeletedAt,
		&member.Version,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find tenant member: %w", err)
	}

	return member, nil
}

// GetUserRoles retrieves all roles for a user in a specific tenant
func (r *TenantMemberRepository) GetUserRoles(ctx context.Context, userID, tenantID uuid.UUID) ([]UserRole, error) {
	// Query to get roles through user_roles join table
	// Assumes tables: tenant_members, user_roles, roles
	query := `
		SELECT DISTINCT
			r.id as role_id,
			r.code as role_code,
			r.name as role_name,
			COALESCE(
				array_agg(DISTINCT p.code) FILTER (WHERE p.code IS NOT NULL),
				ARRAY[]::text[]
			) as permissions
		FROM core.tenant_members tm
		INNER JOIN core.user_roles ur ON ur.member_id = tm.id
		INNER JOIN core.roles r ON r.id = ur.role_id
		LEFT JOIN core.role_permissions rp ON rp.role_id = r.id
		LEFT JOIN core.permissions p ON p.id = rp.permission_id
		WHERE tm.user_id = $1
		AND tm.tenant_id = $2
		AND tm.deleted_at IS NULL
		AND tm.status = 'ACTIVE'
		AND r.deleted_at IS NULL
		AND (rp.deleted_at IS NULL OR rp.deleted_at IS NULL)
		GROUP BY r.id, r.code, r.name
		ORDER BY r.code
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query user roles: %w", err)
	}
	defer rows.Close()

	var roles []UserRole
	for rows.Next() {
		var role UserRole
		var permissions []string

		err := rows.Scan(
			&role.RoleID,
			&role.RoleCode,
			&role.RoleName,
			&permissions,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		role.Permissions = permissions
		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// GetUserRoleCodes returns just the role codes (simpler, faster query)
func (r *TenantMemberRepository) GetUserRoleCodes(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT r.code
		FROM core.tenant_members tm
		INNER JOIN core.user_roles ur ON ur.member_id = tm.id
		INNER JOIN core.roles r ON r.id = ur.role_id
		WHERE tm.user_id = $1
		AND tm.tenant_id = $2
		AND tm.deleted_at IS NULL
		AND tm.status = 'ACTIVE'
		AND r.deleted_at IS NULL
		ORDER BY r.code
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query role codes: %w", err)
	}
	defer rows.Close()

	var roleCodes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, fmt.Errorf("failed to scan role code: %w", err)
		}
		roleCodes = append(roleCodes, code)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role codes: %w", err)
	}

	return roleCodes, nil
}

// GetUserPermissions returns all permission codes for a user in a tenant
func (r *TenantMemberRepository) GetUserPermissions(ctx context.Context, userID, tenantID uuid.UUID) ([]string, error) {
	query := `
		SELECT DISTINCT p.code
		FROM core.tenant_members tm
		INNER JOIN core.user_roles ur ON ur.member_id = tm.id
		INNER JOIN core.roles r ON r.id = ur.role_id
		INNER JOIN core.role_permissions rp ON rp.role_id = r.id
		INNER JOIN core.permissions p ON p.id = rp.permission_id
		WHERE tm.user_id = $1
		AND tm.tenant_id = $2
		AND tm.deleted_at IS NULL
		AND tm.status = 'ACTIVE'
		AND r.deleted_at IS NULL
		AND rp.deleted_at IS NULL
		ORDER BY p.code
	`

	rows, err := r.db.QueryContext(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to query permissions: %w", err)
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}
		permissions = append(permissions, code)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}

// CheckPermission checks if a user has a specific permission in a tenant
func (r *TenantMemberRepository) CheckPermission(ctx context.Context, userID, tenantID uuid.UUID, permissionCode string) (bool, error) {
	query := `
		SELECT EXISTS (
			SELECT 1
			FROM core.tenant_members tm
			INNER JOIN core.user_roles ur ON ur.member_id = tm.id
			INNER JOIN core.roles r ON r.id = ur.role_id
			INNER JOIN core.role_permissions rp ON rp.role_id = r.id
			INNER JOIN core.permissions p ON p.id = rp.permission_id
			WHERE tm.user_id = $1
			AND tm.tenant_id = $2
			AND p.code = $3
			AND tm.deleted_at IS NULL
			AND tm.status = 'ACTIVE'
			AND r.deleted_at IS NULL
			AND rp.deleted_at IS NULL
		)
	`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, userID, tenantID, permissionCode).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}

	return exists, nil
}
