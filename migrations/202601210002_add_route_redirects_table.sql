-- Migration: Add route_redirects table for path migration with 301 redirects
-- Purpose: Support backward compatibility when tenants change their path_prefix
-- Created: 2026-01-21
-- Priority: MEDIUM

-- Create route_redirects table
CREATE TABLE IF NOT EXISTS core.route_redirects (
    -- I. ĐỊNH DANH
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- II. ROUTING INFO
    tenant_id UUID NOT NULL,
    domain VARCHAR(255) NOT NULL,
    old_path_prefix VARCHAR(255) NOT NULL,
    new_path_prefix VARCHAR(255) NOT NULL,

    -- III. REDIRECT CONFIG
    redirect_type VARCHAR(10) NOT NULL DEFAULT '301', -- 301 (Permanent), 302 (Temporary), 307 (Temp with POST), 308 (Perm with POST)

    -- IV. AUDIT & EXPIRATION
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID,
    expires_at TIMESTAMPTZ, -- NULL = permanent redirect

    -- V. CONSTRAINTS
    CONSTRAINT fk_redirects_tenant FOREIGN KEY (tenant_id) REFERENCES core.tenants(id) ON DELETE CASCADE,
    CONSTRAINT uq_redirect_domain_old_path UNIQUE (domain, old_path_prefix),
    CONSTRAINT chk_redirect_type CHECK (redirect_type IN ('301', '302', '307', '308')),
    CONSTRAINT chk_redirect_paths_different CHECK (old_path_prefix != new_path_prefix)
);

-- Create covering index for fast lookup (includes all needed columns)
CREATE INDEX IF NOT EXISTS idx_redirects_lookup
ON core.route_redirects (domain, old_path_prefix)
INCLUDE (new_path_prefix, redirect_type)
WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at > NOW());

-- Create index for tenant management (list all redirects of a tenant)
CREATE INDEX IF NOT EXISTS idx_redirects_tenant
ON core.route_redirects (tenant_id, created_at DESC)
WHERE deleted_at IS NULL;

-- Add comment
COMMENT ON TABLE core.route_redirects IS 'Stores URL redirects for path migration when tenants change their path_prefix';
COMMENT ON COLUMN core.route_redirects.redirect_type IS '301=Permanent, 302=Temporary, 307=Temp+POST, 308=Perm+POST';
COMMENT ON COLUMN core.route_redirects.expires_at IS 'NULL = permanent redirect. Set date to auto-expire temporary redirects';

-- Verify table created
SELECT tablename, schemaname
FROM pg_tables
WHERE schemaname = 'core'
  AND tablename = 'route_redirects';
