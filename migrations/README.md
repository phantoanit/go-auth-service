# Database Migration Guide

## MongoDB Migrations for Multi-Tenant Auth

### Prerequisites
- MongoDB 4.4+ installed
- MongoDB client (`mongo` or `mongosh`)
- Access to MongoDB instance

### Running Migrations

#### Option 1: Using mongo shell
```bash
# Connect to MongoDB
mongo mongodb://localhost:27017/auth_service

# Or with mongosh
mongosh mongodb://localhost:27017/auth_service

# Run the migration script
load("migrations/001_init_multi_tenant.js")
```

#### Option 2: Using mongosh directly
```bash
mongosh mongodb://localhost:27017/auth_service --file migrations/001_init_multi_tenant.js
```

#### Option 3: Using docker
```bash
docker exec -i mongodb mongosh auth_service < migrations/001_init_multi_tenant.js
```

### Migration Scripts

#### 001_init_multi_tenant.js
Creates the following collections and indexes:

**Collections:**
1. `users_auth` - Global user accounts (one password per user)
2. `user_tenants` - User-tenant relationships with roles
3. `tenant_login_configs` - Tenant-specific login configurations
4. `refresh_tokens` - Refresh token storage
5. `roles` - Role definitions
6. `login_attempts` - Failed login tracking (for rate limiting)
7. `user_lockouts` - User lockout tracking

**Indexes:**
- Unique indexes on email, username, phone, document_number
- Compound indexes for multi-tenant queries
- TTL index on login_attempts for auto-cleanup

**Default Data:**
- System tenant login configuration
- Default roles (super_admin, admin, user)
- System admin user (admin@system.local / Admin@123)

### Verify Migration

```javascript
// Connect to MongoDB
use auth_service

// Check collections
show collections

// Check indexes
db.users_auth.getIndexes()
db.user_tenants.getIndexes()
db.tenant_login_configs.getIndexes()

// Check default data
db.tenant_login_configs.findOne({ tenantId: "system" })
db.roles.find({})
db.users_auth.findOne({ username: "admin" })
```

### Rollback (if needed)

```javascript
// Connect to MongoDB
use auth_service

// Drop all collections
db.users_auth.drop()
db.user_tenants.drop()
db.tenant_login_configs.drop()
db.refresh_tokens.drop()
db.roles.drop()
db.login_attempts.drop()
db.user_lockouts.drop()
```

### Production Considerations

1. **Change Default Admin Password**
   ```javascript
   // After first login, change the admin password
   // The system will hash it properly
   ```

2. **Backup Before Migration**
   ```bash
   mongodump --db=auth_service --out=backup_before_migration
   ```

3. **Test in Staging First**
   - Run migration in staging environment
   - Test all authentication flows
   - Verify indexes are created correctly

4. **Monitor Performance**
   - Check index usage: `db.users_auth.aggregate([{$indexStats: {}}])`
   - Monitor query performance
   - Adjust indexes if needed

### Connection Strings

#### Development
```
mongodb://localhost:27017/auth_service
```

#### Docker
```
mongodb://mongodb:27017/auth_service
```

#### Production (with auth)
```
mongodb://username:password@host:27017/auth_service?authSource=admin
```

### Environment Variables

Set these in your `.env` file:

```env
MONGODB_URI=mongodb://localhost:27017/auth_service
MONGODB_DATABASE=auth_service
MONGODB_USERNAME=
MONGODB_PASSWORD=
```

### Next Steps

After running migrations:

1. ✅ Verify all collections exist
2. ✅ Verify indexes are created
3. ✅ Test system admin login
4. ✅ Create first tenant via API
5. ✅ Create tenant-specific login config
6. ✅ Test multi-tenant user registration
7. ✅ Test login with different identifier types

### Troubleshooting

**Error: "Collection already exists"**
- Collections exist, check if migration was already run
- Use rollback script if you need to re-run

**Error: "Duplicate key error"**
- Data already exists with same unique key
- Check existing data before re-running

**Error: "Index build failed"**
- Check MongoDB version (requires 4.4+)
- Ensure sufficient disk space
- Check MongoDB logs for details
