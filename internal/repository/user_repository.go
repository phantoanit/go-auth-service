package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vhvplatform/go-auth-service/internal/domain"
)

// UserRepository handles users table operations in YugabyteDB
type UserRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new user repository for YugabyteDB
func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create inserts a new user
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	query := `
		INSERT INTO core.users (
			id, email, full_name, phone_number, avatar_url,
			status, is_support_staff, mfa_enabled, mfa_secret,
			is_verified, locale, metadata, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.Email,
		user.FullName,
		user.PhoneNumber,
		user.AvatarURL,
		user.Status,
		user.IsSupportStaff,
		user.MFAEnabled,
		user.MFASecret,
		user.IsVerified,
		user.Locale,
		user.Metadata,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// FindByID finds a user by ID (filters out soft-deleted users)
func (r *UserRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	query := `
		SELECT id, email, full_name, phone_number, avatar_url,
		       status, is_support_staff, mfa_enabled, mfa_secret,
		       is_verified, locale, metadata, created_at, updated_at, deleted_at
		FROM core.users
		WHERE id = $1 AND deleted_at IS NULL
	`

	var user domain.User
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&user.ID,
		&user.Email,
		&user.FullName,
		&user.PhoneNumber,
		&user.AvatarURL,
		&user.Status,
		&user.IsSupportStaff,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.IsVerified,
		&user.Locale,
		&user.Metadata,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by ID: %w", err)
	}

	return &user, nil
}

// FindByEmail finds a user by email (filters out soft-deleted users)
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	query := `
		SELECT id, email, full_name, phone_number, avatar_url,
		       status, is_support_staff, mfa_enabled, mfa_secret,
		       is_verified, locale, metadata, created_at, updated_at, deleted_at
		FROM core.users
		WHERE email = $1 AND deleted_at IS NULL
	`

	var user domain.User
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&user.ID,
		&user.Email,
		&user.FullName,
		&user.PhoneNumber,
		&user.AvatarURL,
		&user.Status,
		&user.IsSupportStaff,
		&user.MFAEnabled,
		&user.MFASecret,
		&user.IsVerified,
		&user.Locale,
		&user.Metadata,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user by email: %w", err)
	}

	return &user, nil
}

// Update updates user information
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = time.Now()

	query := `
		UPDATE core.users
		SET full_name = $1, phone_number = $2, avatar_url = $3,
		    locale = $4, metadata = $5, updated_at = $6
		WHERE id = $7 AND deleted_at IS NULL
	`

	result, err := r.db.ExecContext(ctx, query,
		user.FullName,
		user.PhoneNumber,
		user.AvatarURL,
		user.Locale,
		user.Metadata,
		user.UpdatedAt,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	return nil
}

// SoftDelete performs soft delete on user
func (r *UserRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE core.users
		SET deleted_at = $1, updated_at = $2
		WHERE id = $3 AND deleted_at IS NULL
	`

	now := time.Now()
	result, err := r.db.ExecContext(ctx, query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to soft delete user: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user not found or already deleted")
	}

	return nil
}

// UpdateStatus updates user status (ACTIVE, BANNED, DISABLED, PENDING)
func (r *UserRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) error {
	query := `
		UPDATE core.users
		SET status = $1, updated_at = $2
		WHERE id = $3 AND deleted_at IS NULL
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, status, now, id)
	if err != nil {
		return fmt.Errorf("failed to update user status: %w", err)
	}

	return nil
}

// MarkVerified marks user as verified
func (r *UserRepository) MarkVerified(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE core.users
		SET is_verified = true, updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark user as verified: %w", err)
	}

	return nil
}
