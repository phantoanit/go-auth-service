// MongoDB Indexes and Collections Setup for Multi-Tenant Auth
// Run this script to create necessary collections and indexes

// Use auth database
db = db.getSiblingDB('auth_service');

// 1. Users Collection
db.createCollection('auth_users');

// Create indexes for auth_users
db.auth_users.createIndex({ "email": 1 }, { unique: true, sparse: true });
db.auth_users.createIndex({ "username": 1 }, { unique: true, sparse: true });
db.auth_users.createIndex({ "phone": 1 }, { unique: true, sparse: true });
db.auth_users.createIndex({ "docNumber": 1 }, { unique: true, sparse: true });
db.auth_users.createIndex({ "isActive": 1 });
db.auth_users.createIndex({ "createdAt": -1 });
db.auth_users.createIndex({ "email": 1, "isActive": 1 });

// 2. Tenant Login Configurations Collection
db.createCollection('tenant_login_configs');

// Create indexes for tenant_login_configs
db.tenant_login_configs.createIndex({ "tenantId": 1 }, { unique: true });

// 3. Refresh Tokens Collection
// Used for ALL clients (web, mobile, desktop, 3rd party)
// Allows renewing access tokens without re-login
db.createCollection('refresh_tokens');

// Create indexes for refresh_tokens
db.refresh_tokens.createIndex({ "token": 1 }, { unique: true });
db.refresh_tokens.createIndex({ "userId": 1 });
db.refresh_tokens.createIndex({ "tenantId": 1 });
db.refresh_tokens.createIndex({ "expiresAt": 1 });
db.refresh_tokens.createIndex({ "userId": 1, "tenantId": 1 });
db.refresh_tokens.createIndex({ "revokedAt": 1 }, { sparse: true });

// 4. User Sessions Collection (for opaque tokens)
// If using JWT, this collection may not be needed
// For opaque tokens: stores token -> user mapping
db.createCollection('user_sessions');

// Create indexes for user_sessions
db.user_sessions.createIndex({ "sessionToken": 1 }, { unique: true });
db.user_sessions.createIndex({ "userId": 1 });
db.user_sessions.createIndex({ "tenantId": 1 });
db.user_sessions.createIndex({ "userId": 1, "isActive": 1 });
db.user_sessions.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 }); // TTL index
db.user_sessions.createIndex({ "lastAccessAt": -1 });

// 5. Login Attempts Collection (for audit/analytics only)
// Real-time rate limiting should use Dragonfly/Redis
db.createCollection('login_attempts');

// Create indexes for login_attempts
db.login_attempts.createIndex({ "identifier": 1, "tenantId": 1, "attemptAt": -1 });
db.login_attempts.createIndex({ "attemptAt": 1 }, { expireAfterSeconds: 86400 }); // TTL index: auto-delete after 24 hours
db.login_attempts.createIndex({ "ipAddress": 1, "tenantId": 1, "attemptAt": -1 });

// 6. User Lockouts Collection
db.createCollection('user_lockouts');

// Create indexes for user_lockouts
db.user_lockouts.createIndex({ "userId": 1, "tenantId": 1, "isActive": 1 });
db.user_lockouts.createIndex({ "unlockAt": 1 });
db.user_lockouts.createIndex({ "userId": 1, "isActive": 1 });

// 7. Insert Default Tenant Login Config (System Default)
db.tenant_login_configs.insertOne({
    tenantId: "system",
    allowedIdentifiers: ["email", "username"],
    require2FA: false,
    allowRegistration: true,
    passwordMinLength: 8,
    passwordRequireUpper: true,
    passwordRequireLower: true,
    passwordRequireDigit: true,
    passwordRequireSpec: false,
    sessionTimeout: 1440, // 24 hours
    maxLoginAttempts: 5,
    lockoutDuration: 30, // 30 minutes
    createdAt: new Date(),
    updatedAt: new Date()
});

print("\n✅ MongoDB migration completed successfully!");
print("\n📝 Collections created (Authentication Runtime Data):");
print("   1. auth_users          - Password hashes & login identifiers");
print("   2. tenant_login_configs - Per-tenant login rules");
print("   3. refresh_tokens      - Refresh tokens for ALL clients (not just 3rd party)");
print("   4. user_sessions       - Opaque token storage (if not using JWT)");
print("   5. login_attempts      - Login audit log (use Dragonfly for rate limiting)");
print("   6. user_lockouts       - Temporary account lockouts");
print("");
print("⚠️  Important Notes:");
print("   - User-tenant relationships are in YugabyteDB (tenant_members table)");
print("   - Roles & permissions are in YugabyteDB (roles, permissions tables)");
print("   - Rate limiting: Use Dragonfly/Redis (in-memory), not MongoDB");
print("   - Opaque tokens: Use user_sessions or Dragonfly");
print("   - JWT tokens: user_sessions collection may not be needed");
print("   - Run seed scripts to create test users");
