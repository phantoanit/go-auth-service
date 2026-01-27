-- Migration: Add refresh_tokens and email_verification_tokens tables
-- Version: 002
-- Date: 2024-01-20

SET search_path TO core;

-- =====================================================
-- 1. REFRESH TOKENS TABLE
-- Stores refresh tokens for JWT token rotation
-- =====================================================

CREATE TABLE IF NOT EXISTS refresh_tokens (
    -- Primary identifier
    id UUID PRIMARY KEY,

    -- Token identification
    token_hash BYTEA NOT NULL UNIQUE, -- SHA256 hash of refresh token

    -- User & Tenant context
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Token metadata
    device_info JSONB DEFAULT '{}', -- Device fingerprint, user agent, IP
    token_family UUID NOT NULL,     -- For token rotation tracking

    -- Expiration & Status
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    replaced_by_token_id UUID REFERENCES refresh_tokens(id),

    -- Security flags
    is_revoked BOOLEAN DEFAULT FALSE,
    revocation_reason VARCHAR(100),

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,

    -- Constraints
    CONSTRAINT chk_rt_expires CHECK (expires_at > created_at),
    CONSTRAINT chk_rt_revoked CHECK (
        (is_revoked = FALSE AND revoked_at IS NULL) OR
        (is_revoked = TRUE AND revoked_at IS NOT NULL)
    )
);

-- Indexes for refresh_tokens
CREATE INDEX IF NOT EXISTS idx_rt_user_tenant
    ON refresh_tokens (user_id, tenant_id)
    WHERE is_revoked = FALSE AND expires_at > NOW();

CREATE INDEX IF NOT EXISTS idx_rt_token_hash
    ON refresh_tokens (token_hash)
    WHERE is_revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_rt_family
    ON refresh_tokens (token_family)
    WHERE is_revoked = FALSE;

CREATE INDEX IF NOT EXISTS idx_rt_expires
    ON refresh_tokens (expires_at)
    WHERE is_revoked = FALSE;

-- =====================================================
-- 2. EMAIL VERIFICATION TOKENS TABLE
-- Stores tokens for email verification
-- =====================================================

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    -- Primary identifier
    id UUID PRIMARY KEY,

    -- Token identification
    token_hash BYTEA NOT NULL UNIQUE, -- SHA256 hash of verification token

    -- User context
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,

    -- Token metadata
    token_type VARCHAR(20) NOT NULL DEFAULT 'REGISTRATION', -- REGISTRATION, EMAIL_CHANGE

    -- Expiration & Status
    expires_at TIMESTAMPTZ NOT NULL,
    verified_at TIMESTAMPTZ,

    -- Security
    ip_address INET,
    user_agent TEXT,
    attempts INT DEFAULT 0,

    -- Audit
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Constraints
    CONSTRAINT chk_evt_type CHECK (token_type IN ('REGISTRATION', 'EMAIL_CHANGE', 'PASSWORD_RESET')),
    CONSTRAINT chk_evt_expires CHECK (expires_at > created_at),
    CONSTRAINT chk_evt_verified CHECK (
        (verified_at IS NULL) OR
        (verified_at IS NOT NULL AND verified_at <= expires_at)
    ),
    CONSTRAINT chk_evt_attempts CHECK (attempts >= 0 AND attempts <= 10)
);

-- Indexes for email_verification_tokens
CREATE INDEX IF NOT EXISTS idx_evt_user
    ON email_verification_tokens (user_id)
    WHERE verified_at IS NULL AND expires_at > NOW();

CREATE INDEX IF NOT EXISTS idx_evt_token_hash
    ON email_verification_tokens (token_hash)
    WHERE verified_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_evt_email
    ON email_verification_tokens (email)
    WHERE verified_at IS NULL AND expires_at > NOW();

-- =====================================================
-- 3. CLEANUP FUNCTIONS
-- Auto-delete expired tokens
-- =====================================================

-- Function to cleanup expired refresh tokens
CREATE OR REPLACE FUNCTION cleanup_expired_refresh_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM refresh_tokens
    WHERE expires_at < NOW() - INTERVAL '7 days'
    AND is_revoked = TRUE;

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup expired verification tokens
CREATE OR REPLACE FUNCTION cleanup_expired_verification_tokens()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM email_verification_tokens
    WHERE expires_at < NOW() - INTERVAL '7 days'
    OR verified_at IS NOT NULL AND verified_at < NOW() - INTERVAL '30 days';

    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- =====================================================
-- 4. COMMENTS
-- =====================================================

COMMENT ON TABLE refresh_tokens IS 'Stores refresh tokens for JWT token rotation with security tracking';
COMMENT ON COLUMN refresh_tokens.token_hash IS 'SHA256 hash of the refresh token for secure lookup';
COMMENT ON COLUMN refresh_tokens.token_family IS 'Groups tokens from same login session for detection of token theft';
COMMENT ON COLUMN refresh_tokens.replaced_by_token_id IS 'Points to new token after rotation, helps detect replay attacks';

COMMENT ON TABLE email_verification_tokens IS 'Stores email verification tokens for registration and email changes';
COMMENT ON COLUMN email_verification_tokens.token_hash IS 'SHA256 hash of the verification token';
COMMENT ON COLUMN email_verification_tokens.attempts IS 'Track failed verification attempts to prevent brute force';

-- =====================================================
-- 5. GRANTS (adjust as needed)
-- =====================================================

-- Grant permissions to auth service user
-- GRANT SELECT, INSERT, UPDATE, DELETE ON refresh_tokens TO auth_service_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON email_verification_tokens TO auth_service_user;

COMMIT;
