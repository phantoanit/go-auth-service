package repository

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vhvplatform/go-auth-service/internal/domain"
)

// UserIdentityRepository handles user_identities table operations
// This is the STORE TABLE containing credentials and OAuth tokens
type UserIdentityRepository struct {
	db *sql.DB
}

// NewUserIdentityRepository creates a new user identity repository
func NewUserIdentityRepository(db *sql.DB) *UserIdentityRepository {
	return &UserIdentityRepository{db: db}
}

// Create inserts a new user identity
func (r *UserIdentityRepository) Create(ctx context.Context, identity *domain.UserIdentity) error {
	now := time.Now()
	identity.CreatedAt = now
	identity.UpdatedAt = now
	identity.Version = 1

	query := `
		INSERT INTO core.user_identities (
			id, user_id, identity_type, identity_value,
			credential_secret, metadata, is_verified,
			verified_at, last_login_at, created_at, updated_at, version
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err := r.db.ExecContext(ctx, query,
		identity.ID,
		identity.UserID,
		identity.IdentityType,
		identity.IdentityValue,
		identity.CredentialSecret,
		identity.Metadata,
		identity.IsVerified,
		identity.VerifiedAt,
		identity.LastLoginAt,
		identity.CreatedAt,
		identity.UpdatedAt,
		identity.Version,
	)

	if err != nil {
		return fmt.Errorf("failed to create user identity: %w", err)
	}

	return nil
}

// FindByID finds a user identity by its ID
func (r *UserIdentityRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.UserIdentity, error) {
	query := `
		SELECT id, user_id, identity_type, identity_value,
		       credential_secret, metadata, is_verified,
		       verified_at, last_login_at, created_at, updated_at, version
		FROM core.user_identities
		WHERE id = $1
	`

	var identity domain.UserIdentity
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&identity.ID,
		&identity.UserID,
		&identity.IdentityType,
		&identity.IdentityValue,
		&identity.CredentialSecret,
		&identity.Metadata,
		&identity.IsVerified,
		&identity.VerifiedAt,
		&identity.LastLoginAt,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.Version,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user identity: %w", err)
	}

	return &identity, nil
}

// FindByOAuth finds identity by OAuth provider (used for Google/GitHub login callback)
func (r *UserIdentityRepository) FindByOAuth(ctx context.Context, identityType, providerSubjectID string) (*domain.UserIdentity, error) {
	query := `
		SELECT id, user_id, identity_type, identity_value,
		       credential_secret, metadata, is_verified,
		       verified_at, last_login_at, created_at, updated_at, version
		FROM core.user_identities
		WHERE identity_type = $1 AND identity_value = $2
	`

	var identity domain.UserIdentity
	err := r.db.QueryRowContext(ctx, query, identityType, providerSubjectID).Scan(
		&identity.ID,
		&identity.UserID,
		&identity.IdentityType,
		&identity.IdentityValue,
		&identity.CredentialSecret,
		&identity.Metadata,
		&identity.IsVerified,
		&identity.VerifiedAt,
		&identity.LastLoginAt,
		&identity.CreatedAt,
		&identity.UpdatedAt,
		&identity.Version,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find user identity by OAuth: %w", err)
	}

	return &identity, nil
}

// ListByUserID finds all identities for a user (for "My Profile" -> "Linked Accounts")
func (r *UserIdentityRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.UserIdentity, error) {
	query := `
		SELECT id, user_id, identity_type, identity_value,
		       credential_secret, metadata, is_verified,
		       verified_at, last_login_at, created_at, updated_at, version
		FROM core.user_identities
		WHERE user_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list user identities: %w", err)
	}
	defer rows.Close()

	var identities []*domain.UserIdentity
	for rows.Next() {
		var identity domain.UserIdentity
		err := rows.Scan(
			&identity.ID,
			&identity.UserID,
			&identity.IdentityType,
			&identity.IdentityValue,
			&identity.CredentialSecret,
			&identity.Metadata,
			&identity.IsVerified,
			&identity.VerifiedAt,
			&identity.LastLoginAt,
			&identity.CreatedAt,
			&identity.UpdatedAt,
			&identity.Version,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user identity: %w", err)
		}
		identities = append(identities, &identity)
	}

	return identities, nil
}

// UpdateLastLogin updates the last login timestamp
func (r *UserIdentityRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE core.user_identities
		SET last_login_at = $1, updated_at = $2, version = version + 1
		WHERE id = $3
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

// UpdateCredential updates the credential secret (for password change)
func (r *UserIdentityRepository) UpdateCredential(ctx context.Context, id uuid.UUID, credentialSecret string) error {
	query := `
		UPDATE core.user_identities
		SET credential_secret = $1, updated_at = $2, version = version + 1
		WHERE id = $3
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, credentialSecret, now, id)
	if err != nil {
		return fmt.Errorf("failed to update credential: %w", err)
	}

	return nil
}

// MarkVerified marks an identity as verified
func (r *UserIdentityRepository) MarkVerified(ctx context.Context, id uuid.UUID) error {
	query := `
		UPDATE core.user_identities
		SET is_verified = true, verified_at = $1, updated_at = $2, version = version + 1
		WHERE id = $3
	`

	now := time.Now()
	_, err := r.db.ExecContext(ctx, query, now, now, id)
	if err != nil {
		return fmt.Errorf("failed to mark identity as verified: %w", err)
	}

	return nil
}
