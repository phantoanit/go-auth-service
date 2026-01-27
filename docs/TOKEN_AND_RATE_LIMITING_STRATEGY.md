# Token & Rate Limiting Strategy

## 🎯 Overview

Tài liệu này giải thích chiến lược quản lý tokens và rate limiting trong hệ thống multi-tenant.

---

## 📝 Token Types Comparison

### JWT (JSON Web Token) - Self-contained

```json
{
  "header": {
    "alg": "HS256",
    "typ": "JWT"
  },
  "payload": {
    "sub": "user_uuid",
    "tenant_id": "tenant_uuid",
    "permissions": ["read:profile", "write:posts"],
    "exp": 1737288000,
    "iat": 1737287100
  },
  "signature": "..."
}
```

**Pros:**
- ✅ No database lookup per request (fast)
- ✅ Stateless (scales horizontally)
- ✅ Contains user info (self-contained)

**Cons:**
- ❌ Cannot revoke before expiry (unless use blacklist)
- ❌ Token size larger (300-500 bytes)
- ❌ Cannot update permissions in real-time

**Best for:**
- Public APIs
- Microservices communication
- Short-lived tokens (5-15 minutes)

---

### Opaque Token - Random String

```
a7f3e9b2-4c5d-6e8f-9a0b-1c2d3e4f5a6b
```

**Pros:**
- ✅ Easy to revoke (delete from DB)
- ✅ Smaller size (36-64 bytes)
- ✅ Real-time permission updates
- ✅ More secure (no info leakage)

**Cons:**
- ❌ Database lookup per request (slower)
- ❌ Stateful (requires session storage)

**Best for:**
- Web applications (cookies)
- Long-lived sessions
- Admin panels
- When real-time revocation needed

---

## 🗄️ Token Storage Strategies

### Strategy 1: Dragonfly/Redis (Recommended for Opaque Tokens)

```javascript
// Store session
await dragonfly.set(
    `session:${tokenHash}`,
    JSON.stringify({
        userId: "user_uuid",
        tenantId: "tenant_uuid",
        permissions: ["read:profile"],
        ipAddress: "192.168.1.100",
        userAgent: "Mozilla/5.0..."
    }),
    'EX', 900 // TTL: 15 minutes
);

// Validate session (every request)
const session = await dragonfly.get(`session:${tokenHash}`);
if (!session) {
    throw new UnauthorizedError('Invalid session');
}

// Extend session TTL
await dragonfly.expire(`session:${tokenHash}`, 900);

// Revoke session
await dragonfly.del(`session:${tokenHash}`);
```

**Performance:**
- Read: ~0.1ms (in-memory)
- Write: ~0.2ms
- Throughput: 100K+ ops/sec

---

### Strategy 2: MongoDB (Good for persistence)

```javascript
// user_sessions collection
{
    id: "session_uuid",
    sessionToken: "sha256_hash_of_token", // Never store plain token!
    userId: "user_uuid",
    tenantId: "tenant_uuid",

    // Session metadata
    ipAddress: "192.168.1.100",
    userAgent: "Mozilla/5.0...",
    deviceFingerprint: "...",

    // Security
    expiresAt: ISODate("2026-01-20T10:00:00Z"),
    lastAccessAt: ISODate("2026-01-19T14:30:00Z"),
    isActive: true,

    // Type & permissions
    tokenType: "ACCESS", // ACCESS | REFRESH | API_KEY
    scopes: ["read:profile", "write:posts"],

    createdAt: ISODate("2026-01-19T10:00:00Z")
}

// Indexes
db.user_sessions.createIndex({ "sessionToken": 1 }, { unique: true });
db.user_sessions.createIndex({ "expiresAt": 1 }, { expireAfterSeconds: 0 }); // TTL
db.user_sessions.createIndex({ "userId": 1, "isActive": 1 });
```

**Performance:**
- Read: ~5-10ms (with index)
- Write: ~10-20ms
- Good for: Audit trail, long-term sessions

---

### Strategy 3: Hybrid (Best of Both Worlds)

```
┌──────────────────────────────────────────────────┐
│  REQUEST VALIDATION                               │
├──────────────────────────────────────────────────┤
│                                                   │
│  1. Check Dragonfly (cache)                      │
│     ↓                                             │
│  2. If not found → Query MongoDB                 │
│     ↓                                             │
│  3. Store in Dragonfly (cache for next request)  │
│                                                   │
└──────────────────────────────────────────────────┘

Cache Hit Rate: 95%+ → Most requests served from Dragonfly
```

```javascript
async function validateSession(token) {
    const tokenHash = sha256(token);

    // 1. Try cache first
    let session = await dragonfly.get(`session:${tokenHash}`);

    if (session) {
        return JSON.parse(session); // Cache hit!
    }

    // 2. Cache miss → Query MongoDB
    const sessionDoc = await db.user_sessions.findOne({
        sessionToken: tokenHash,
        isActive: true,
        expiresAt: { $gt: new Date() }
    });

    if (!sessionDoc) {
        throw new UnauthorizedError('Invalid session');
    }

    // 3. Populate cache for next request
    await dragonfly.set(
        `session:${tokenHash}`,
        JSON.stringify(sessionDoc),
        'EX', 900
    );

    return sessionDoc;
}
```

---

## 🔄 Token Lifecycle

### Access Token (Short-lived)

```
┌─────────────────────────────────────────────────┐
│  1. LOGIN                                        │
│     ↓                                            │
│  2. Generate Access Token (15 min TTL)          │
│     ↓                                            │
│  3. Store in Dragonfly: session:{token}         │
│     SET session:{token} ... EX 900              │
│     ↓                                            │
│  4. Client uses token for requests              │
│     Each request: GET session:{token}           │
│     ↓                                            │
│  5. Token expires (TTL = 0)                     │
│     Dragonfly auto-deletes                      │
│     ↓                                            │
│  6. Client uses Refresh Token to get new one    │
└─────────────────────────────────────────────────┘
```

### Refresh Token (Long-lived)

```
┌─────────────────────────────────────────────────┐
│  1. LOGIN                                        │
│     ↓                                            │
│  2. Generate Refresh Token (30 days TTL)        │
│     ↓                                            │
│  3. Store in MongoDB: refresh_tokens            │
│     With TTL index on expiresAt                 │
│     ↓                                            │
│  4. Access token expires                        │
│     ↓                                            │
│  5. Client sends refresh token                  │
│     POST /auth/refresh                          │
│     ↓                                            │
│  6. Validate refresh token                      │
│     Check: exists, not revoked, not expired     │
│     ↓                                            │
│  7. Generate NEW access token                   │
│     Store in Dragonfly                          │
│     ↓                                            │
│  8. Optional: Rotate refresh token              │
│     Delete old, issue new refresh token         │
└─────────────────────────────────────────────────┘
```

---

## 🚦 Rate Limiting Strategy

### ❌ WRONG: MongoDB-based Rate Limiting

```javascript
// DON'T DO THIS - Too slow!
async function checkRateLimit(email) {
    const fifteenMinutesAgo = new Date(Date.now() - 15*60*1000);

    // Insert attempt
    await db.login_attempts.insertOne({
        identifier: email,
        attemptAt: new Date(),
        ipAddress: req.ip
    });

    // Count attempts (SLOW QUERY!)
    const count = await db.login_attempts.countDocuments({
        identifier: email,
        attemptAt: { $gte: fifteenMinutesAgo }
    });

    if (count > 5) {
        throw new Error('Too many attempts');
    }
}

// Problems:
// - Every login = 2 DB operations (insert + count)
// - Count query gets slower as collection grows
// - No atomic operations
// - Race conditions possible
```

---

### ✅ CORRECT: Dragonfly-based Rate Limiting

```javascript
async function checkRateLimit(email) {
    const key = `rate_limit:login:${email}`;

    // Atomic increment
    const attempts = await dragonfly.incr(key);

    // Set TTL on first attempt
    if (attempts === 1) {
        await dragonfly.expire(key, 900); // 15 minutes
    }

    // Check limit
    if (attempts > 5) {
        // Optional: Log to MongoDB for audit
        db.login_attempts.insertOne({
            identifier: email,
            attemptAt: new Date(),
            blocked: true
        }); // Fire and forget

        throw new TooManyRequestsError('Rate limit exceeded');
    }

    return attempts;
}

// Benefits:
// - Single atomic operation (INCR)
// - Sub-millisecond response
// - Auto-cleanup via TTL
// - No race conditions
```

---

### Dual-Layer Strategy (Recommended)

```
┌────────────────────────────────────────────────────┐
│  LAYER 1: Dragonfly (Real-time enforcement)        │
│  Purpose: Block attacks immediately                │
│  TTL: 15 minutes                                   │
│  Keys: rate_limit:login:{email}                    │
│        rate_limit:api:{tenant_id}:{endpoint}       │
└────────────────────────────────────────────────────┘
         ↓ (async logging)
┌────────────────────────────────────────────────────┐
│  LAYER 2: MongoDB (Audit & Analytics)              │
│  Purpose: Long-term analysis, forensics            │
│  TTL: 90 days                                      │
│  Collection: login_attempts                        │
└────────────────────────────────────────────────────┘
         ↓ (daily aggregation)
┌────────────────────────────────────────────────────┐
│  LAYER 3: ClickHouse (Security Intelligence)       │
│  Purpose: Detect patterns, anomalies               │
│  Retention: 1+ years                               │
│  Table: auth_logs                                  │
└────────────────────────────────────────────────────┘
```

---

## 🔧 Implementation Examples

### Login Flow with Rate Limiting

```javascript
async function login(email, password, tenantId) {
    // 1. Check rate limit (Dragonfly)
    const attempts = await dragonfly.incr(`rate_limit:login:${email}`);
    if (attempts === 1) {
        await dragonfly.expire(`rate_limit:login:${email}`, 900);
    }
    if (attempts > 5) {
        throw new TooManyRequestsError('Rate limit exceeded. Try again in 15 minutes.');
    }

    // 2. Get user from MongoDB
    const user = await db.auth_users.findOne({ email, isActive: true });
    if (!user) {
        // Log failed attempt (async)
        logLoginAttempt(email, 'USER_NOT_FOUND', false);
        throw new UnauthorizedError('Invalid credentials');
    }

    // 3. Validate password
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) {
        // Log failed attempt (async)
        logLoginAttempt(email, 'INVALID_PASSWORD', false);
        throw new UnauthorizedError('Invalid credentials');
    }

    // 4. Get user's tenant membership (YugabyteDB)
    const member = await db.query(`
        SELECT tm.*, array_agg(r.permissions) as permissions
        FROM tenant_members tm
        LEFT JOIN user_roles ur ON ur.member_id = tm.id
        LEFT JOIN roles r ON r.id = ur.role_id
        WHERE tm.user_id = $1 AND tm.tenant_id = $2 AND tm.status = 'ACTIVE'
        GROUP BY tm.id
    `, [user.id, tenantId]);

    if (!member) {
        throw new ForbiddenError('Not a member of this tenant');
    }

    // 5. Generate tokens
    const accessToken = crypto.randomBytes(32).toString('hex');
    const refreshToken = crypto.randomBytes(32).toString('hex');

    // 6. Store access token in Dragonfly (opaque token)
    await dragonfly.set(
        `session:${sha256(accessToken)}`,
        JSON.stringify({
            userId: user.id,
            tenantId: tenantId,
            permissions: member.permissions.flat(),
            deviceFingerprint: req.deviceFingerprint
        }),
        'EX', 900 // 15 minutes
    );

    // 7. Store refresh token in MongoDB
    await db.refresh_tokens.insertOne({
        id: generateUUID(),
        token: sha256(refreshToken),
        userId: user.id,
        tenantId: tenantId,
        expiresAt: new Date(Date.now() + 30*24*60*60*1000), // 30 days
        createdAt: new Date()
    });

    // 8. Reset rate limit on success
    await dragonfly.del(`rate_limit:login:${email}`);

    // 9. Log successful login (async)
    logLoginAttempt(email, 'SUCCESS', true);

    return {
        accessToken,
        refreshToken,
        expiresIn: 900,
        tokenType: 'Bearer'
    };
}
```

### Token Validation Middleware

```javascript
async function validateToken(req, res, next) {
    // 1. Extract token from header
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Missing token' });
    }

    const token = authHeader.substring(7);
    const tokenHash = sha256(token);

    // 2. Check Dragonfly cache
    let session = await dragonfly.get(`session:${tokenHash}`);

    if (!session) {
        // 3. Fallback to MongoDB (if using hybrid strategy)
        const sessionDoc = await db.user_sessions.findOne({
            sessionToken: tokenHash,
            isActive: true,
            expiresAt: { $gt: new Date() }
        });

        if (!sessionDoc) {
            return res.status(401).json({ error: 'Invalid or expired token' });
        }

        session = sessionDoc;

        // Cache for next request
        await dragonfly.set(`session:${tokenHash}`, JSON.stringify(sessionDoc), 'EX', 900);
    } else {
        session = JSON.parse(session);
    }

    // 4. Attach to request
    req.user = {
        id: session.userId,
        tenantId: session.tenantId,
        permissions: session.permissions
    };

    // 5. Optional: Extend session TTL (sliding window)
    await dragonfly.expire(`session:${tokenHash}`, 900);

    next();
}
```

---

## 📊 Performance Comparison

| Operation | MongoDB | Dragonfly | ClickHouse |
|-----------|---------|-----------|------------|
| Rate limit check | ~10ms | **~0.1ms** | N/A |
| Session lookup | ~5ms | **~0.1ms** | N/A |
| Token revocation | ~10ms | **~0.1ms** | N/A |
| Audit logging | ~20ms | N/A | **~5ms (batch)** |
| Analytics query | ~500ms | N/A | **~50ms** |

**Recommendation:**
- **Dragonfly**: Real-time operations (rate limit, session)
- **MongoDB**: Persistence (refresh tokens, audit)
- **ClickHouse**: Analytics (security intelligence)

---

## 🔒 Security Best Practices

### 1. Token Hashing
```javascript
// ❌ NEVER store plain tokens
await db.tokens.insertOne({ token: "abc123..." });

// ✅ Always hash tokens
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
await db.tokens.insertOne({ tokenHash });
```

### 2. Rate Limiting Layers
```javascript
// Global rate limit
rate_limit:global:{ip} → 1000 requests/hour

// Authentication rate limit
rate_limit:login:{email} → 5 attempts/15min
rate_limit:login:{ip} → 20 attempts/15min

// API rate limit
rate_limit:api:{tenant_id} → 10000 requests/hour
rate_limit:api:{tenant_id}:{endpoint} → 100 requests/minute
```

### 3. Token Rotation
```javascript
// Rotate refresh tokens after each use
const newRefreshToken = crypto.randomBytes(32).toString('hex');

await db.refresh_tokens.updateOne(
    { id: oldTokenId },
    { $set: { revokedAt: new Date() } }
);

await db.refresh_tokens.insertOne({ token: sha256(newRefreshToken), ... });
```

---

## 📋 Configuration Checklist

- [ ] Choose token type: JWT or Opaque
- [ ] Setup Dragonfly for rate limiting
- [ ] Configure TTLs: access (15m), refresh (30d)
- [ ] Implement token rotation
- [ ] Add audit logging to MongoDB
- [ ] Setup ClickHouse for analytics
- [ ] Configure rate limits per endpoint
- [ ] Test token revocation flow
- [ ] Monitor cache hit rate (target: >95%)

---

**Last Updated**: 2026-01-19
**Version**: 1.0.0
