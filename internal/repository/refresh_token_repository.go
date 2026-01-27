package repository

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	ID                uuid.UUID
	TokenHash         []byte
	UserID            uuid.UUID
	TenantID          uuid.UUID
	DeviceInfo        string // JSONB
	TokenFamily       uuid.UUID
	ExpiresAt         time.Time
	RevokedAt         *time.Time
	ReplacedByTokenID *uuid.UUID
	IsRevoked         bool
	RevocationReason  *string
	CreatedAt         time.Time
	LastUsedAt        *time.Time
}

// RefreshTokenRepository handles refresh token operations
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a new refresh token repository
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// GenerateToken creates a cryptographically secure random token
func (r *RefreshTokenRepository) GenerateToken() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Create inserts a new refresh token
func (r *RefreshTokenRepository) Create(ctx context.Context, userID, tenantID uuid.UUID, deviceInfo string, expiresIn time.Duration) (string, error) {
	// Generate random token
	token, err := r.GenerateToken()
	if err != nil {
		return "", err
	}

	// Hash token for storage
	hash := sha256.Sum256([]byte(token))

	// Generate token family ID for first token in family
	tokenFamily := uuid.Must(uuid.NewV7())

	refreshToken := &RefreshToken{
		ID:          uuid.Must(uuid.NewV7()),
		TokenHash:   hash[:],
		UserID:      userID,
		TenantID:    tenantID,
		DeviceInfo:  deviceInfo,
		TokenFamily: tokenFamily,
		ExpiresAt:   time.Now().Add(expiresIn),
		IsRevoked:   false,
		CreatedAt:   time.Now(),
	}

	query := `
		INSERT INTO core.refresh_tokens (
			id, token_hash, userid, tenantid, device_info,
			token_family, expires_at, is_revoked, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err = r.db.ExecContext(ctx, query,
		refreshToken.ID,
		refreshToken.TokenHash,
		refreshToken.UserID,
		refreshToken.TenantID,
		refreshToken.DeviceInfo,
		refreshToken.TokenFamily,
		refreshToken.ExpiresAt,
		refreshToken.IsRevoked,
		refreshToken.CreatedAt,
	)

	if err != nil {
		return "", fmt.Errorf("failed to create refresh token: %w", err)
	}

	return token, nil
}

// FindByToken finds a refresh token by its token string
func (r *RefreshTokenRepository) FindByToken(ctx context.Context, token string) (*RefreshToken, error) {
	hash := sha256.Sum256([]byte(token))

	query := `
		SELECT id, token_hash, userid, tenantid, device_info,
			   token_family, expires_at, revoked_at, replaced_by_token_id,
			   is_revoked, revocation_reason, created_at, last_used_at
		FROM core.refresh_tokens
		WHERE token_hash = $1
	`

	rt := &RefreshToken{}
	err := r.db.QueryRowContext(ctx, query, hash[:]).Scan(
		&rt.ID,
		&rt.TokenHash,
		&rt.UserID,
		&rt.TenantID,
		&rt.DeviceInfo,
		&rt.TokenFamily,
		&rt.ExpiresAt,
		&rt.RevokedAt,
		&rt.ReplacedByTokenID,
		&rt.IsRevoked,
		&rt.RevocationReason,
		&rt.CreatedAt,
		&rt.LastUsedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find refresh token: %w", err)
	}

	return rt, nil
}

// Rotate creates a new refresh token and marks the old one as replaced
func (r *RefreshTokenRepository) Rotate(ctx context.Context, oldToken string, deviceInfo string, expiresIn time.Duration) (string, error) {
	// Find old token
	old, err := r.FindByToken(ctx, oldToken)
	if err != nil {
		return "", err
	}
	if old == nil {
		return "", fmt.Errorf("refresh token not found")
	}

	// Check if token is valid
	if old.IsRevoked {
		// Possible token theft - revoke entire family
		if err := r.RevokeFamily(ctx, old.TokenFamily, "Token reuse detected - possible theft"); err != nil {
			return "", fmt.Errorf("failed to revoke token family: %w", err)
		}
		return "", fmt.Errorf("refresh token has been revoked - token theft detected")
	}

	if time.Now().After(old.ExpiresAt) {
		return "", fmt.Errorf("refresh token has expired")
	}

	// Generate new token
	newToken, err := r.GenerateToken()
	if err != nil {
		return "", err
	}

	newHash := sha256.Sum256([]byte(newToken))
	newID := uuid.Must(uuid.NewV7())

	// Start transaction
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert new token (same family)
	insertQuery := `
		INSERT INTO core.refresh_tokens (
			id, token_hash, userid, tenantid, device_info,
			token_family, expires_at, is_revoked, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err = tx.ExecContext(ctx, insertQuery,
		newID,
		newHash[:],
		old.UserID,
		old.TenantID,
		deviceInfo,
		old.TokenFamily, // Keep same family
		time.Now().Add(expiresIn),
		false,
		time.Now(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to insert new refresh token: %w", err)
	}

	// Mark old token as replaced
	updateQuery := `
		UPDATE core.refresh_tokens
		SET is_revoked = TRUE,
			revoked_at = NOW(),
			replaced_by_token_id = $1,
			revocation_reason = 'Rotated'
		WHERE id = $2
	`

	_, err = tx.ExecContext(ctx, updateQuery, newID, old.ID)
	if err != nil {
		return "", fmt.Errorf("failed to revoke old refresh token: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("failed to commit transaction: %w", err)
	}

	return newToken, nil
}

// Revoke marks a specific token as revoked
func (r *RefreshTokenRepository) Revoke(ctx context.Context, token string, reason string) error {
	hash := sha256.Sum256([]byte(token))

	query := `
		UPDATE core.refresh_tokens
		SET is_revoked = TRUE,
			revoked_at = NOW(),
			revocation_reason = $1
		WHERE token_hash = $2
	`

	result, err := r.db.ExecContext(ctx, query, reason, hash[:])
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("refresh token not found")
	}

	return nil
}

// RevokeFamily revokes all tokens in a token family (for token theft detection)
func (r *RefreshTokenRepository) RevokeFamily(ctx context.Context, tokenFamily uuid.UUID, reason string) error {
	query := `
		UPDATE core.refresh_tokens
		SET is_revoked = TRUE,
			revoked_at = NOW(),
			revocation_reason = $1
		WHERE token_family = $2
		AND is_revoked = FALSE
	`

	_, err := r.db.ExecContext(ctx, query, reason, tokenFamily)
	if err != nil {
		return fmt.Errorf("failed to revoke token family: %w", err)
	}

	return nil
}

// RevokeAllForUser revokes all tokens for a specific user (used for logout all devices)
func (r *RefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID, tenantID uuid.UUID, reason string) error {
	query := `
		UPDATE core.refresh_tokens
		SET is_revoked = TRUE,
			revoked_at = NOW(),
			revocation_reason = $1
		WHERE user_id = $2
		AND tenant_id = $3
		AND is_revoked = FALSE
	`

	_, err := r.db.ExecContext(ctx, query, reason, userID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to revoke all user tokens: %w", err)
	}

	return nil
}

// UpdateLastUsed updates the last_used_at timestamp
func (r *RefreshTokenRepository) UpdateLastUsed(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))

	query := `
		UPDATE core.refresh_tokens
		SET last_used_at = NOW()
		WHERE token_hash = $1
	`

	_, err := r.db.ExecContext(ctx, query, hash[:])
	return err
}

// CleanupExpired removes expired and old revoked tokens
func (r *RefreshTokenRepository) CleanupExpired(ctx context.Context) (int, error) {
	query := `
		DELETE FROM core.refresh_tokens
		WHERE (expires_at < NOW() - INTERVAL '7 days' AND is_revoked = TRUE)
		   OR (expires_at < NOW() - INTERVAL '30 days')
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}
