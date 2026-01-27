// Migration: Add Phase 1 Standard Fields
// Date: 2025-01-XX
// Purpose: Backfill version and deletedAt fields for all collections

// MongoDB connection
const conn = new Mongo();
const db = conn.getDB("auth_service");

print("=== Phase 1: Adding Standard Fields ===");

// ============= Users Collection =============
print("\n1. Migrating users collection...");
const usersResult = db.users.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
        },
    }
);
print(`  ✓ Updated ${usersResult.modifiedCount} users`);

// Create indexes for users
db.users.createIndex({ "deletedAt": 1, "createdAt": -1 });
db.users.createIndex({ "tenants": 1, "deletedAt": 1 });
print("  ✓ Created indexes on users");

// ============= Tenants Collection =============
print("\n2. Migrating tenants collection...");
const tenantsResult = db.tenants.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
        },
    }
);
print(`  ✓ Updated ${tenantsResult.modifiedCount} tenants`);

// Create indexes for tenants
db.tenants.createIndex({ "deletedAt": 1, "createdAt": -1 });
db.tenants.createIndex({ "isActive": 1, "deletedAt": 1 });
print("  ✓ Created indexes on tenants");

// ============= Roles Collection =============
print("\n3. Migrating roles collection...");
const rolesResult = db.roles.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
        },
    }
);
print(`  ✓ Updated ${rolesResult.modifiedCount} roles`);

// Create indexes for roles
db.roles.createIndex({ "tenantId": 1, "deletedAt": 1, "createdAt": -1 });
db.roles.createIndex({ "name": 1, "tenantId": 1, "deletedAt": 1 });
print("  ✓ Created indexes on roles");

// ============= Permissions Collection =============
print("\n4. Migrating permissions collection...");
const permissionsResult = db.permissions.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
        },
    }
);
print(`  ✓ Updated ${permissionsResult.modifiedCount} permissions`);

// Create indexes for permissions
db.permissions.createIndex({ "deletedAt": 1, "createdAt": -1 });
db.permissions.createIndex({ "tenantId": 1, "deletedAt": 1 }, { sparse: true });
print("  ✓ Created indexes on permissions");

// ============= Refresh Tokens Collection =============
print("\n5. Migrating refresh_tokens collection...");
const tokensResult = db.refresh_tokens.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
            updatedAt: new Date(),
        },
    }
);
print(`  ✓ Updated ${tokensResult.modifiedCount} refresh tokens`);

// Create indexes for refresh_tokens
db.refresh_tokens.createIndex({ "userId": 1, "deletedAt": 1, "revokedAt": 1 });
db.refresh_tokens.createIndex({ "deletedAt": 1, "expiresAt": 1 });
print("  ✓ Created indexes on refresh_tokens");

// ============= OAuth Accounts Collection =============
print("\n6. Migrating oauth_accounts collection...");
const oauthResult = db.oauth_accounts.updateMany(
    { version: { $exists: false } },
    {
        $set: {
            version: 1,
            deletedAt: null,
        },
    }
);
print(`  ✓ Updated ${oauthResult.modifiedCount} oauth accounts`);

// Create indexes for oauth_accounts
db.oauth_accounts.createIndex({ "userId": 1, "deletedAt": 1 });
db.oauth_accounts.createIndex({ "provider": 1, "providerId": 1, "deletedAt": 1 });
print("  ✓ Created indexes on oauth_accounts");

print("\n=== Migration Complete ===");
print("\nSummary:");
print(`  - Users:         ${usersResult.modifiedCount} updated`);
print(`  - Tenants:       ${tenantsResult.modifiedCount} updated`);
print(`  - Roles:         ${rolesResult.modifiedCount} updated`);
print(`  - Permissions:   ${permissionsResult.modifiedCount} updated`);
print(`  - RefreshTokens: ${tokensResult.modifiedCount} updated`);
print(`  - OAuthAccounts: ${oauthResult.modifiedCount} updated`);
print("\n✓ All collections migrated successfully!");

// Verification queries
print("\n=== Verification ===");
print("Sample user with new fields:");
printjson(db.users.findOne({}, { version: 1, deletedAt: 1, createdAt: 1, updatedAt: 1 }));

print("\nSample tenant with new fields:");
printjson(db.tenants.findOne({}, { version: 1, deletedAt: 1, createdAt: 1, updatedAt: 1 }));
