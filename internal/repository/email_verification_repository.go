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

// EmailVerificationToken represents an email verification token
type EmailVerificationToken struct {
	ID         uuid.UUID
	TokenHash  []byte
	UserID     uuid.UUID
	Email      string
	TokenType  string // REGISTRATION, EMAIL_CHANGE, PASSWORD_RESET
	ExpiresAt  time.Time
	VerifiedAt *time.Time
	IPAddress  *string
	UserAgent  *string
	Attempts   int
	CreatedAt  time.Time
}

// EmailVerificationRepository handles email verification token operations
type EmailVerificationRepository struct {
	db *sql.DB
}

// NewEmailVerificationRepository creates a new email verification repository
func NewEmailVerificationRepository(db *sql.DB) *EmailVerificationRepository {
	return &EmailVerificationRepository{db: db}
}

// GenerateToken creates a cryptographically secure random token
func (r *EmailVerificationRepository) GenerateToken() (string, error) {
	bytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Create inserts a new email verification token
func (r *EmailVerificationRepository) Create(ctx context.Context, userID uuid.UUID, email, tokenType string, expiresIn time.Duration, ipAddress, userAgent *string) (string, error) {
	// Generate random token
	token, err := r.GenerateToken()
	if err != nil {
		return "", err
	}

	// Hash token for storage
	hash := sha256.Sum256([]byte(token))

	evt := &EmailVerificationToken{
		ID:        uuid.Must(uuid.NewV7()),
		TokenHash: hash[:],
		UserID:    userID,
		Email:     email,
		TokenType: tokenType,
		ExpiresAt: time.Now().Add(expiresIn),
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Attempts:  0,
		CreatedAt: time.Now(),
	}

	query := `
		INSERT INTO core.email_verification_tokens (
			id, token_hash, userid, email, token_type,
			expires_at, ip_address, user_agent, attempts, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = r.db.ExecContext(ctx, query,
		evt.ID,
		evt.TokenHash,
		evt.UserID,
		evt.Email,
		evt.TokenType,
		evt.ExpiresAt,
		evt.IPAddress,
		evt.UserAgent,
		evt.Attempts,
		evt.CreatedAt,
	)

	if err != nil {
		return "", fmt.Errorf("failed to create email verification token: %w", err)
	}

	return token, nil
}

// FindByToken finds a verification token by its token string
func (r *EmailVerificationRepository) FindByToken(ctx context.Context, token string) (*EmailVerificationToken, error) {
	hash := sha256.Sum256([]byte(token))

	query := `
		SELECT id, token_hash, userid, email, token_type,
			   expires_at, verified_at, ip_address, user_agent,
			   attempts, created_at
		FROM core.email_verification_tokens
		WHERE token_hash = $1
	`

	evt := &EmailVerificationToken{}
	err := r.db.QueryRowContext(ctx, query, hash[:]).Scan(
		&evt.ID,
		&evt.TokenHash,
		&evt.UserID,
		&evt.Email,
		&evt.TokenType,
		&evt.ExpiresAt,
		&evt.VerifiedAt,
		&evt.IPAddress,
		&evt.UserAgent,
		&evt.Attempts,
		&evt.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find verification token: %w", err)
	}

	return evt, nil
}

// Verify marks a token as verified
func (r *EmailVerificationRepository) Verify(ctx context.Context, token string) (*EmailVerificationToken, error) {
	// Find token first
	evt, err := r.FindByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	if evt == nil {
		return nil, fmt.Errorf("verification token not found")
	}

	// Check if already verified
	if evt.VerifiedAt != nil {
		return nil, fmt.Errorf("token already used")
	}

	// Check if expired
	if time.Now().After(evt.ExpiresAt) {
		return nil, fmt.Errorf("verification token has expired")
	}

	// Check attempts limit
	if evt.Attempts >= 10 {
		return nil, fmt.Errorf("too many verification attempts")
	}

	// Mark as verified
	query := `
		UPDATE core.email_verification_tokens
		SET verified_at = NOW()
		WHERE id = $1
	`

	_, err = r.db.ExecContext(ctx, query, evt.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to mark token as verified: %w", err)
	}

	evt.VerifiedAt = new(time.Time)
	*evt.VerifiedAt = time.Now()

	return evt, nil
}

// IncrementAttempts increments the verification attempt counter
func (r *EmailVerificationRepository) IncrementAttempts(ctx context.Context, token string) error {
	hash := sha256.Sum256([]byte(token))

	query := `
		UPDATE core.email_verification_tokens
		SET attempts = attempts + 1
		WHERE token_hash = $1
	`

	_, err := r.db.ExecContext(ctx, query, hash[:])
	if err != nil {
		return fmt.Errorf("failed to increment attempts: %w", err)
	}

	return nil
}

// InvalidateExisting invalidates any existing unverified tokens for the user
func (r *EmailVerificationRepository) InvalidateExisting(ctx context.Context, userID uuid.UUID, tokenType string) error {
	// Instead of deleting, we'll just let them expire naturally
	// This helps with audit trail
	query := `
		UPDATE core.email_verification_tokens
		SET expires_at = NOW()
		WHERE user_id = $1
		AND token_type = $2
		AND verified_at IS NULL
		AND expires_at > NOW()
	`

	_, err := r.db.ExecContext(ctx, query, userID, tokenType)
	if err != nil {
		return fmt.Errorf("failed to invalidate existing tokens: %w", err)
	}

	return nil
}

// FindActiveByEmail finds an active verification token by email
func (r *EmailVerificationRepository) FindActiveByEmail(ctx context.Context, email, tokenType string) (*EmailVerificationToken, error) {
	query := `
		SELECT id, token_hash, userid, email, token_type,
			   expires_at, verified_at, ip_address, user_agent,
			   attempts, created_at
		FROM core.email_verification_tokens
		WHERE email = $1
		AND token_type = $2
		AND verified_at IS NULL
		AND expires_at > NOW()
		ORDER BY created_at DESC
		LIMIT 1
	`

	evt := &EmailVerificationToken{}
	err := r.db.QueryRowContext(ctx, query, email, tokenType).Scan(
		&evt.ID,
		&evt.TokenHash,
		&evt.UserID,
		&evt.Email,
		&evt.TokenType,
		&evt.ExpiresAt,
		&evt.VerifiedAt,
		&evt.IPAddress,
		&evt.UserAgent,
		&evt.Attempts,
		&evt.CreatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to find active token: %w", err)
	}

	return evt, nil
}

// CleanupExpired removes expired and old verified tokens
func (r *EmailVerificationRepository) CleanupExpired(ctx context.Context) (int, error) {
	query := `
		DELETE FROM core.email_verification_tokens
		WHERE expires_at < NOW() - INTERVAL '7 days'
		OR (verified_at IS NOT NULL AND verified_at < NOW() - INTERVAL '30 days')
	`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired tokens: %w", err)
	}

	rows, _ := result.RowsAffected()
	return int(rows), nil
}
