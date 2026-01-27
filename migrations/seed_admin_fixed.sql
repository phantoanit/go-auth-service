-- SEED ADMIN ACCOUNT BASED ON ACTUAL SCHEMA
-- Email: admin_saas@vsystem.vn | Password: Vhv@2026

BEGIN;

SET search_path TO core;

-- 1. Application
INSERT INTO core.applications (id, code, name, description, is_active, created_at, updated_at)
VALUES (
    '018d1234-5678-7000-8000-000000000001',
    'CORE_ADMIN_APP',
    'Core Admin System',
    'Central SaaS Platform Management',
    true,
    now(),
    now()
) ON CONFLICT (code) DO NOTHING;

-- 2. SaaS Product
INSERT INTO core.saas_products (id, code, name, product_type, is_active, created_at, updated_at)
VALUES (
    '018d1234-5678-7000-8000-000000000002',
    'admin-suite',
    'Admin Suite',
    'APP',
    true,
    now(),
    now()
) ON CONFLICT (code) DO NOTHING;

-- 3. Service Package
INSERT INTO core.service_packages (
    id, saas_product_id, code, name, status, entitlements_config, created_at, updated_at
)
VALUES (
    '018d1234-5678-7000-8000-ffffffffffff',
    '018d1234-5678-7000-8000-000000000002',
    'internal-admin',
    'Internal Admin Package',
    'ACTIVE',
    '{"features": ["full_access"], "limits": {"users": -1}}',
    now(),
    now()
) ON CONFLICT (code) DO NOTHING;

-- 4. Admin Tenant (remove owner_user_id)
INSERT INTO core.tenants (
    id, code, name, tier, status, created_at, updated_at
)
VALUES (
    '018d1234-5678-7000-8000-000000000003',
    'vsystem-admin',
    'VSystem Admin Organization',
    'ENTERPRISE',
    'ACTIVE',
    now(),
    now()
) ON CONFLICT (code) DO NOTHING;

-- 5. Tenant Route
INSERT INTO core.tenant_app_routes (
    id, tenant_id, app_code, domain, path_prefix, is_custom_domain, is_primary, created_at, updated_at
)
SELECT
    '018d1234-5678-7000-8000-000000000004',
    '018d1234-5678-7000-8000-000000000003',
    'CORE_ADMIN_APP',
    'saas-platform.vsystem.vn',
    '/',
    false,
    true,
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.tenant_app_routes
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND domain = 'saas-platform.vsystem.vn'
    AND path_prefix = '/'
);

-- 6. Admin User
INSERT INTO core.users (
    id, email, full_name, status, password_hash, created_at, updated_at
)
SELECT
    '018d1234-5678-7000-8000-000000000005',
    'admin_saas@vsystem.vn',
    'System Administrator',
    'ACTIVE',
    '$argon2id$v=19$m=65536,t=3,p=4$UlZqWcDk7s7SHmsdc+r5sw$HDzPzTAIowK+0fqWsFOfKuctV423myYWOTbpY6SG5lY',
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.users WHERE email = 'admin_saas@vsystem.vn' AND deleted_at IS NULL
);

-- 7. User Identity (Password-based login method)
INSERT INTO core.user_identities (
    id, user_id, identity_type, identity_value, credential_secret, is_verified, created_at, updated_at
)
SELECT
    '018d1234-5678-7000-8000-000000000006',
    '018d1234-5678-7000-8000-000000000005',
    'PASSWORD',
    'admin_saas@vsystem.vn',
    '$argon2id$v=19$m=65536,t=3,p=4$UlZqWcDk7s7SHmsdc+r5sw$HDzPzTAIowK+0fqWsFOfKuctV423myYWOTbpY6SG5lY',
    true,
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.user_identities
    WHERE user_id = '018d1234-5678-7000-8000-000000000005'
    AND identity_type = 'PASSWORD'
);

-- 8. Auth Identifiers (fast login lookup - no created_at column)
INSERT INTO core.auth_identifiers (
    tenant_id, identifier_hash, identifier_type, user_id, identity_id
)
SELECT
    '018d1234-5678-7000-8000-000000000003',
    decode('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'hex'),
    'EMAIL',
    '018d1234-5678-7000-8000-000000000005',
    '018d1234-5678-7000-8000-000000000006'
WHERE NOT EXISTS (
    SELECT 1 FROM core.auth_identifiers
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND identifier_hash = decode('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'hex')
    AND identifier_type = 'EMAIL'
);

INSERT INTO core.auth_identifiers (
    tenant_id, identifier_hash, identifier_type, user_id, identity_id
)
SELECT
    '018d1234-5678-7000-8000-000000000003',
    decode('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'hex'),
    'USERNAME',
    '018d1234-5678-7000-8000-000000000005',
    '018d1234-5678-7000-8000-000000000006'
WHERE NOT EXISTS (
    SELECT 1 FROM core.auth_identifiers
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND identifier_hash = decode('8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'hex')
    AND identifier_type = 'USERNAME'
);

-- 9. Tenant Membership (use status not membership_type, no identity_id)
INSERT INTO core.tenant_members (
    id, tenant_id, user_id, status, joined_at, created_at, updated_at
)
SELECT
    '018d1234-5678-7000-8000-000000000007',
    '018d1234-5678-7000-8000-000000000003',
    '018d1234-5678-7000-8000-000000000005',
    'ACTIVE',
    now(),
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.tenant_members
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND user_id = '018d1234-5678-7000-8000-000000000005'
);

-- 10. Permissions (use app_code, path, is_group instead of resource, action)
INSERT INTO core.permissions (id, app_code, code, name, description, is_group, created_at, updated_at)
SELECT * FROM (VALUES
('018d1234-5678-7000-8000-100000000001'::uuid, 'CORE_ADMIN_APP', 'tenant:read', 'Read Tenant', 'View tenant information', false, now(), now()),
('018d1234-5678-7000-8000-100000000002'::uuid, 'CORE_ADMIN_APP', 'tenant:write', 'Write Tenant', 'Modify tenant data', false, now(), now()),
('018d1234-5678-7000-8000-100000000003'::uuid, 'CORE_ADMIN_APP', 'user:read', 'Read User', 'View user information', false, now(), now()),
('018d1234-5678-7000-8000-100000000004'::uuid, 'CORE_ADMIN_APP', 'user:write', 'Write User', 'Modify user data', false, now(), now()),
('018d1234-5678-7000-8000-100000000005'::uuid, 'CORE_ADMIN_APP', 'role:read', 'Read Role', 'View role information', false, now(), now()),
('018d1234-5678-7000-8000-100000000006'::uuid, 'CORE_ADMIN_APP', 'role:write', 'Write Role', 'Modify role data', false, now(), now()),
('018d1234-5678-7000-8000-100000000007'::uuid, 'CORE_ADMIN_APP', 'system:admin', 'System Admin', 'Full system access', false, now(), now())
) AS new_perms(id, app_code, code, name, description, is_group, created_at, updated_at)
WHERE NOT EXISTS (SELECT 1 FROM core.permissions WHERE permissions.code = new_perms.code);

-- 11. Roles (permission_codes as TEXT[])
INSERT INTO core.roles (id, tenant_id, name, description, type, permission_codes, created_at, updated_at)
SELECT
    '018d1234-5678-7000-8000-200000000001',
    '018d1234-5678-7000-8000-000000000003',
    'Super Administrator',
    'Full system access',
    'SYSTEM',
    ARRAY['tenant:read', 'tenant:write', 'user:read', 'user:write', 'role:read', 'role:write', 'system:admin'],
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.roles
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND name = 'Super Administrator'
);

-- 12. User Roles (use tenant_id, member_id, scope_type, assigned_at)
INSERT INTO core.user_roles (id, tenant_id, member_id, role_id, scope_type, assigned_by, assigned_at)
SELECT
    '018d1234-5678-7000-8000-300000000001',
    '018d1234-5678-7000-8000-000000000003',
    '018d1234-5678-7000-8000-000000000007',
    '018d1234-5678-7000-8000-200000000001',
    'GLOBAL',
    '018d1234-5678-7000-8000-000000000005',
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.user_roles
    WHERE member_id = '018d1234-5678-7000-8000-000000000007'
    AND role_id = '018d1234-5678-7000-8000-200000000001'
    AND scope_type = 'GLOBAL'
);

-- 13. Tenant Subscription
INSERT INTO core.tenant_subscriptions (
    id, tenant_id, package_id, status, start_at, end_at, created_at, updated_at
)
SELECT
    '018d1234-5678-7000-8000-400000000001',
    '018d1234-5678-7000-8000-000000000003',
    '018d1234-5678-7000-8000-ffffffffffff',
    'ACTIVE',
    now(),
    now() + interval '100 years',
    now(),
    now()
WHERE NOT EXISTS (
    SELECT 1 FROM core.tenant_subscriptions
    WHERE tenant_id = '018d1234-5678-7000-8000-000000000003'
    AND package_id = '018d1234-5678-7000-8000-ffffffffffff'
);

COMMIT;

-- Verify
SELECT 'Applications:' as result, count(*)::text as count FROM core.applications WHERE code = 'CORE_ADMIN_APP'
UNION ALL SELECT 'Tenants:', count(*)::text FROM core.tenants WHERE code = 'vsystem-admin'
UNION ALL SELECT 'Routes:', count(*)::text FROM core.tenant_app_routes WHERE domain = 'saas-platform.vsystem.vn'
UNION ALL SELECT 'Users:', count(*)::text FROM core.users WHERE email = 'admin_saas@vsystem.vn'
UNION ALL SELECT 'User Identities:', count(*)::text FROM core.user_identities WHERE user_id = '018d1234-5678-7000-8000-000000000005'
UNION ALL SELECT 'Members:', count(*)::text FROM core.tenant_members WHERE user_id = '018d1234-5678-7000-8000-000000000005'
UNION ALL SELECT 'Roles:', count(*)::text FROM core.roles WHERE name = 'Super Administrator'
UNION ALL SELECT 'User Roles:', count(*)::text FROM core.user_roles WHERE member_id = '018d1234-5678-7000-8000-000000000007'
UNION ALL SELECT 'Permissions:', count(*)::text FROM core.permissions WHERE code LIKE 'system:%'
UNION ALL SELECT 'Subscriptions:', count(*)::text FROM core.tenant_subscriptions WHERE tenant_id = '018d1234-5678-7000-8000-000000000003' AND package_id = '018d1234-5678-7000-8000-ffffffffffff';
