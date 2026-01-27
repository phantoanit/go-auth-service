package repository

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
	"github.com/vhvplatform/go-auth-service/internal/domain"
)

// AuthIdentifierRepository handles auth_identifiers table operations
// This is the INDEX TABLE for fast lookup during login
type AuthIdentifierRepository struct {
	db *sql.DB
}

// NewAuthIdentifierRepository creates a new auth identifier repository
func NewAuthIdentifierRepository(db *sql.DB) *AuthIdentifierRepository {
	return &AuthIdentifierRepository{db: db}
}

// Create inserts a new auth identifier (called after creating user_identity)
func (r *AuthIdentifierRepository) Create(ctx context.Context, identifier *domain.AuthIdentifier) error {
	query := `
		INSERT INTO core.auth_identifiers (
			tenant_id, identifier_hash, user_id, identity_id,
			identifier_type, original_value
		) VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err := r.db.ExecContext(ctx, query,
		identifier.TenantID,
		identifier.IdentifierHash,
		identifier.UserID,
		identifier.IdentityID,
		identifier.IdentifierType,
		identifier.OriginalValue,
	)

	if err != nil {
		return fmt.Errorf("failed to create auth identifier: %w", err)
	}

	return nil
}

// FindByHash performs a POINT LOOKUP using the identifier hash
// This is the MAIN LOGIN QUERY - must be < 1ms
func (r *AuthIdentifierRepository) FindByHash(ctx context.Context, tenantID uuid.UUID, identifierHash []byte) (*domain.AuthIdentifier, error) {
	query := `
		SELECT tenant_id, identifier_hash, user_id, identity_id,
		       identifier_type, original_value
		FROM core.auth_identifiers
		WHERE tenant_id = $1 AND identifier_hash = $2
	`

	var identifier domain.AuthIdentifier
	err := r.db.QueryRowContext(ctx, query, tenantID, identifierHash).Scan(
		&identifier.TenantID,
		&identifier.IdentifierHash,
		&identifier.UserID,
		&identifier.IdentityID,
		&identifier.IdentifierType,
		&identifier.OriginalValue,
	)

	if err == sql.ErrNoRows {
		return nil, nil // Not found is not an error
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find auth identifier: %w", err)
	}

	return &identifier, nil
}

// FindByHashes performs multi-value lookup for multiple identifier types
// Used when tenant supports multiple login methods (email, phone, passport)
func (r *AuthIdentifierRepository) FindByHashes(ctx context.Context, tenantID uuid.UUID, hashes [][]byte) (*domain.AuthIdentifier, error) {
	// Convert [][]byte to PostgreSQL array format
	query := `
		SELECT tenant_id, identifier_hash, user_id, identity_id,
		       identifier_type, original_value
		FROM core.auth_identifiers
		WHERE tenant_id = $1 AND identifier_hash = ANY($2)
		LIMIT 1
	`

	var identifier domain.AuthIdentifier
	err := r.db.QueryRowContext(ctx, query, tenantID, hashes).Scan(
		&identifier.TenantID,
		&identifier.IdentifierHash,
		&identifier.UserID,
		&identifier.IdentityID,
		&identifier.IdentifierType,
		&identifier.OriginalValue,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find auth identifier: %w", err)
	}

	return &identifier, nil
}

// DeleteByUserID removes all identifiers for a user (used during user deletion)
func (r *AuthIdentifierRepository) DeleteByUserID(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) error {
	query := `
		DELETE FROM core.auth_identifiers
		WHERE tenant_id = $1 AND user_id = $2
	`

	_, err := r.db.ExecContext(ctx, query, tenantID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete auth identifiers: %w", err)
	}

	return nil
}
