-- Migration: Add covering index for tenant_app_routes lookup
-- Purpose: Optimize tenant routing performance from 350ms to <50ms
-- Created: 2026-01-21
-- Priority: HIGH - Critical for routing performance

-- Check if index exists
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_indexes
        WHERE schemaname = 'core'
          AND tablename = 'tenant_app_routes'
          AND indexname = 'idx_routes_fast_lookup'
    ) THEN
        -- Create covering index for fast lookup
        -- This index includes all columns needed by the router query
        -- Enables index-only scans without accessing heap
        CREATE UNIQUE INDEX idx_routes_fast_lookup
        ON core.tenant_app_routes (domain, path_prefix)
        INCLUDE (tenant_id, app_code, is_custom_domain)
        WHERE deleted_at IS NULL;

        RAISE NOTICE 'Index idx_routes_fast_lookup created successfully';
    ELSE
        RAISE NOTICE 'Index idx_routes_fast_lookup already exists';
    END IF;
END $$;

-- Verify index was created
SELECT
    schemaname,
    tablename,
    indexname,
    indexdef
FROM pg_indexes
WHERE schemaname = 'core'
  AND tablename = 'tenant_app_routes'
  AND indexname = 'idx_routes_fast_lookup';

-- Test query performance
EXPLAIN (ANALYZE, BUFFERS)
SELECT tenant_id, app_code, is_custom_domain, path_prefix
FROM core.tenant_app_routes
WHERE domain = 'platform.saas.vsystem.vn'
  AND '/api/user/v1/users' LIKE path_prefix || '%'
  AND deleted_at IS NULL
ORDER BY LENGTH(path_prefix) DESC
LIMIT 1;
