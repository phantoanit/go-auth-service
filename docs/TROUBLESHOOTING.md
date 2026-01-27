# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Auth Service.

## Table of Contents

- [Connection Issues](#connection-issues)
- [Authentication Failures](#authentication-failures)
- [Token Issues](#token-issues)
- [OAuth2 Problems](#oauth2-problems)
- [Database Issues](#database-issues)
- [Performance Issues](#performance-issues)
- [Common Error Messages](#common-error-messages)
- [Debugging Tools](#debugging-tools)

## Connection Issues

### Service Not Responding

**Symptoms**:
- Unable to connect to service
- Connection timeout errors
- "Connection refused" messages

**Diagnosis**:
```bash
# Check if service is running
ps aux | grep auth-service

# Check listening ports
netstat -tlnp | grep -E '8081|50051'

# Test HTTP endpoint
curl -v http://localhost:8081/health

# Test gRPC endpoint
grpcurl -plaintext localhost:50051 list
```

**Solutions**:

1. **Service not running**:
```bash
# Start the service
make run

# Or with Docker
docker-compose up -d auth-service

# Check logs
tail -f logs/auth-service.log
```

2. **Port already in use**:
```bash
# Find process using port
lsof -i :8081

# Kill the process
kill -9 <PID>

# Or change port in .env
AUTH_SERVICE_HTTP_PORT=8082
AUTH_SERVICE_PORT=50052
```

3. **Firewall blocking**:
```bash
# Check firewall rules
sudo iptables -L

# Allow port (temporary)
sudo iptables -A INPUT -p tcp --dport 8081 -j ACCEPT
```

### Database Connection Failures

**Symptoms**:
- "Failed to connect to MongoDB"
- "MongoDB connection timeout"

**Diagnosis**:
```bash
# Test MongoDB connection
mongosh "mongodb://localhost:27017/saas_framework"

# Check MongoDB service
systemctl status mongod

# Check connection from service host
telnet localhost 27017
```

**Solutions**:

1. **MongoDB not running**:
```bash
# Start MongoDB
sudo systemctl start mongod

# Enable on boot
sudo systemctl enable mongod
```

2. **Wrong connection string**:
```bash
# Check .env file
grep MONGODB_URI .env

# Correct format:
MONGODB_URI=mongodb://username:password@host:port/database?authSource=admin
```

3. **Authentication failed**:
```bash
# Create user in MongoDB
mongosh
use admin
db.createUser({
  user: "auth_service",
  pwd: "secure_password",
  roles: [{ role: "readWrite", db: "saas_framework" }]
})
```

### Redis Connection Issues

**Symptoms**:
- "Failed to connect to Redis"
- Session management not working

**Diagnosis**:
```bash
# Test Redis connection
redis-cli ping

# Check Redis service
systemctl status redis

# Test from service host
telnet localhost 6379
```

**Solutions**:

1. **Redis not running**:
```bash
# Start Redis
sudo systemctl start redis

# Or with Docker
docker run -d -p 6379:6379 redis:7-alpine
```

2. **Password authentication**:
```env
# In .env
REDIS_PASSWORD=your_redis_password

# In redis.conf
requirepass your_redis_password
```

3. **Wrong database number**:
```bash
# Check Redis DB
redis-cli
SELECT 0
KEYS *

# Update .env
REDIS_DB=0
```

## Authentication Failures

### Login Failures

**Error**: "Invalid email or password"

**Diagnosis**:
```bash
# Check user exists
mongosh saas_framework
db.users.findOne({ email: "user@example.com" })

# Check password hash
db.users.findOne(
  { email: "user@example.com" },
  { password_hash: 1 }
)

# Enable debug logging
export LOG_LEVEL=debug
```

**Solutions**:

1. **User doesn't exist**:
```bash
# Register new user
curl -X POST http://localhost:8081/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "tenant_id": "tenant_001"
  }'
```

2. **Wrong password**:
- Verify password meets requirements
- Check for copy-paste errors (extra spaces)
- Try password reset flow

3. **Account inactive**:
```bash
# Activate account in MongoDB
db.users.updateOne(
  { email: "user@example.com" },
  { $set: { is_active: true } }
)
```

### Account Locked

**Error**: "Account locked due to multiple failed attempts"

**Diagnosis**:
```bash
# Check Redis for lockout
redis-cli
GET account_locked:USER_ID
TTL account_locked:USER_ID

# Check failed login attempts
GET failed_login:USER_ID
```

**Solutions**:

1. **Wait for automatic unlock** (default: 15 minutes)

2. **Manual unlock**:
```bash
# Delete lockout keys in Redis
redis-cli
DEL account_locked:USER_ID
DEL failed_login:USER_ID
DEL lockout_count:USER_ID
```

3. **Admin unlock via API**:
```bash
curl -X POST http://localhost:8081/api/v1/admin/unlock-account \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"user_id": "507f1f77bcf86cd799439011"}'
```

## Token Issues

### Invalid Token

**Error**: "Invalid or expired token"

**Diagnosis**:
```bash
# Decode JWT (without verification)
jwt_token="eyJhbGc..."
echo $jwt_token | cut -d'.' -f2 | base64 -d | jq

# Check token in logs
tail -f logs/auth-service.log | grep "token validation"
```

**Solutions**:

1. **Token expired**:
```bash
# Refresh token
curl -X POST http://localhost:8081/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "REFRESH_TOKEN"}'
```

2. **Invalid signature**:
- Check JWT_SECRET matches between deployments
- Verify token wasn't modified
- Ensure using correct environment (dev/prod)

3. **Token format invalid**:
- Check Authorization header format: `Bearer <token>`
- Verify no extra whitespace
- Ensure complete token (not truncated)

### Token Revoked

**Error**: "Token has been revoked"

**Diagnosis**:
```bash
# Check refresh token in database
db.refresh_tokens.findOne({ token: "TOKEN_HASH" })

# Check blacklist in Redis
redis-cli
GET blacklist:TOKEN_JTI
```

**Solutions**:

1. **Re-authenticate**:
```bash
curl -X POST http://localhost:8081/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password"
  }'
```

2. **Clear old tokens** (if you have new ones):
```bash
# No action needed - use new tokens
```

## OAuth2 Problems

### OAuth Redirect URI Mismatch

**Error**: "redirect_uri_mismatch"

**Solutions**:

1. **Check provider configuration**:
   - Go to OAuth provider console (Google/GitHub)
   - Verify redirect URI matches exactly
   - Include protocol (http/https)
   - Include port if non-standard

2. **Update redirect URI**:
```bash
# In .env
GOOGLE_REDIRECT_URL=https://your-domain.com/api/v1/auth/oauth/google/callback

# Restart service
systemctl restart auth-service
```

### OAuth State Mismatch

**Error**: "State token mismatch"

**Diagnosis**:
```bash
# Check Redis for OAuth state
redis-cli
GET oauth_state:STATE_TOKEN
TTL oauth_state:STATE_TOKEN
```

**Solutions**:

1. **State expired** (timeout > 10 minutes):
- Restart OAuth flow
- Reduce time between steps

2. **Cookie/session issues**:
- Enable cookies in browser
- Check CORS configuration
- Verify SameSite cookie settings

### Provider Returns Error

**Error**: "access_denied" or "invalid_grant"

**Solutions**:

1. **User denied permission**:
- User must grant all required permissions
- Review requested scopes
- Try OAuth flow again

2. **Invalid credentials**:
```bash
# Verify OAuth credentials
echo $GOOGLE_CLIENT_ID
echo $GOOGLE_CLIENT_SECRET

# Test with OAuth provider
# Google: https://console.cloud.google.com/apis/credentials
# GitHub: https://github.com/settings/developers
```

## Database Issues

### Slow Queries

**Symptoms**:
- High response times
- Database CPU spikes
- Timeout errors

**Diagnosis**:
```bash
# Enable MongoDB profiling
mongosh
use saas_framework
db.setProfilingLevel(2)

# Check slow queries
db.system.profile.find().sort({ ts: -1 }).limit(10)

# Check indexes
db.users.getIndexes()
db.refresh_tokens.getIndexes()
```

**Solutions**:

1. **Create missing indexes**:
```javascript
// In MongoDB
db.users.createIndex({ email: 1, tenant_id: 1 })
db.users.createIndex({ tenant_id: 1, is_active: 1 })
db.refresh_tokens.createIndex({ user_id: 1 })
db.refresh_tokens.createIndex({ expires_at: 1 })
db.refresh_tokens.createIndex({ token: 1 }, { unique: true })
```

2. **Add query limits**:
```go
// In code - limit result sets
opts := options.Find().SetLimit(100)
cursor, err := collection.Find(ctx, filter, opts)
```

3. **Optimize queries**:
```go
// Use projection to fetch only needed fields
opts := options.FindOne().SetProjection(bson.D{
    {Key: "id", Value: 1},
    {Key: "email", Value: 1},
    {Key: "roles", Value: 1},
})
```

### Connection Pool Exhausted

**Error**: "no available connection in pool"

**Diagnosis**:
```bash
# Check MongoDB connection stats
mongosh
db.serverStatus().connections

# Check application metrics
curl http://localhost:9090/metrics | grep mongo_connections
```

**Solutions**:

1. **Increase pool size**:
```bash
# In .env
MONGODB_MAX_POOL_SIZE=100
MONGODB_MIN_POOL_SIZE=10
```

2. **Fix connection leaks**:
```go
// Ensure connections are released
defer cursor.Close(ctx)

// Use context timeout
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
```

## Performance Issues

### High Memory Usage

**Diagnosis**:
```bash
# Check process memory
ps aux | grep auth-service

# Generate memory profile
curl http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof -http=:8080 heap.prof

# Check for memory leaks
go tool pprof -alloc_space heap.prof
```

**Solutions**:

1. **Increase memory limit**:
```yaml
# In Kubernetes
resources:
  limits:
    memory: "2Gi"
  requests:
    memory: "1Gi"
```

2. **Fix memory leaks**:
- Check for goroutine leaks
- Ensure proper resource cleanup
- Use sync.Pool for frequently allocated objects

### High CPU Usage

**Diagnosis**:
```bash
# Check CPU usage
top -p $(pgrep auth-service)

# Generate CPU profile
curl http://localhost:6060/debug/pprof/profile?seconds=30 > cpu.prof
go tool pprof -http=:8080 cpu.prof
```

**Solutions**:

1. **Optimize hot paths**:
- Cache frequently accessed data
- Use connection pooling
- Implement rate limiting

2. **Scale horizontally**:
```bash
# Add more replicas
kubectl scale deployment auth-service --replicas=5
```

### Slow Response Times

**Diagnosis**:
```bash
# Check response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8081/api/v1/auth/login

# Create curl-format.txt
time_namelookup: %{time_namelookup}\n
time_connect: %{time_connect}\n
time_starttransfer: %{time_starttransfer}\n
time_total: %{time_total}\n
```

**Solutions**:

1. **Enable Redis caching**:
```go
// Cache user data
func (s *AuthService) GetUser(ctx context.Context, userID string) (*User, error) {
    // Check cache first
    cached, _ := s.redis.Get(ctx, fmt.Sprintf("user:%s", userID)).Result()
    if cached != "" {
        var user User
        json.Unmarshal([]byte(cached), &user)
        return &user, nil
    }
    
    // Fetch from database
    user, err := s.userRepo.FindByID(ctx, userID)
    if err != nil {
        return nil, err
    }
    
    // Cache result
    data, _ := json.Marshal(user)
    s.redis.Set(ctx, fmt.Sprintf("user:%s", userID), data, 10*time.Minute)
    
    return user, nil
}
```

2. **Optimize database queries** (see "Slow Queries" section)

3. **Use CDN** for static assets

## Common Error Messages

### "Failed to generate token"

**Cause**: JWT secret not configured or invalid

**Solution**:
```bash
# Generate new JWT secret
openssl rand -base64 64

# Add to .env
JWT_SECRET=your_generated_secret

# Restart service
systemctl restart auth-service
```

### "Session not found"

**Cause**: Session expired or Redis unavailable

**Solutions**:
1. Check Redis connection
2. Verify session TTL configuration
3. Re-authenticate to create new session

### "Rate limit exceeded"

**Cause**: Too many requests from client

**Solutions**:
1. Wait for rate limit window to reset
2. Implement exponential backoff
3. Contact admin to adjust limits

### "CSRF token missing"

**Cause**: CSRF protection enabled, token not provided

**Solution**:
```javascript
// Include CSRF token in requests
fetch('/api/v1/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': getCsrfToken()
  },
  body: JSON.stringify({ email, password })
})
```

## Debugging Tools

### Enable Debug Logging

```bash
# Set log level
export LOG_LEVEL=debug

# Or in .env
LOG_LEVEL=debug
LOG_FORMAT=json

# Restart service
systemctl restart auth-service

# Tail logs
tail -f logs/auth-service.log | jq
```

### Health Check Endpoint

```bash
# Check service health
curl -v http://localhost:8081/health

# Expected response
{
  "status": "healthy",
  "timestamp": "2023-12-25T10:00:00Z",
  "checks": {
    "mongodb": "connected",
    "redis": "connected",
    "version": "1.0.0"
  }
}
```

### Metrics Endpoint

```bash
# Prometheus metrics
curl http://localhost:9090/metrics

# Key metrics to monitor:
# - auth_login_attempts_total
# - auth_failed_logins_total
# - auth_active_sessions
# - http_request_duration_seconds
# - mongodb_connections
# - redis_connections
```

### Request Tracing

```bash
# Enable request ID
# Each request includes X-Request-ID header

# Grep logs by request ID
tail -f logs/auth-service.log | grep "request_id=abc123"

# Distributed tracing (if configured)
# - Jaeger: http://localhost:16686
# - Zipkin: http://localhost:9411
```

### Database Debugging

```bash
# MongoDB queries
mongosh saas_framework

# Find recent users
db.users.find().sort({ created_at: -1 }).limit(10)

# Find expired tokens
db.refresh_tokens.find({ expires_at: { $lt: new Date() } })

# Count active sessions (Redis)
redis-cli
KEYS session:*
DBSIZE
```

### Interactive Debugging

```go
// Add debug endpoints (development only)
router.GET("/debug/users", func(c *gin.Context) {
    users, _ := userRepo.FindAll(c.Request.Context())
    c.JSON(200, users)
})

router.GET("/debug/sessions", func(c *gin.Context) {
    keys, _ := redis.Keys(c.Request.Context(), "session:*").Result()
    c.JSON(200, keys)
})

// Remove in production!
```

## Getting Help

### Collect Diagnostic Information

Before requesting help, collect:

```bash
#!/bin/bash
# diagnostic-info.sh

echo "=== Service Version ===" 
./auth-service --version

echo "=== Configuration ===" 
env | grep -E "JWT_|MONGODB_|REDIS_" | sed 's/=.*/=***/'

echo "=== Service Status ===" 
systemctl status auth-service

echo "=== Recent Logs ===" 
tail -n 100 logs/auth-service.log

echo "=== Database Status ===" 
mongosh --eval "db.serverStatus()" --quiet

echo "=== Redis Status ===" 
redis-cli INFO | grep -E "redis_version|connected_clients|used_memory"

echo "=== Network ===" 
netstat -tlnp | grep -E "8081|50051"
```

### Support Channels

- **Documentation**: https://github.com/vhvplatform/go-auth-service/wiki
- **Issues**: https://github.com/vhvplatform/go-auth-service/issues
- **Discussions**: https://github.com/vhvplatform/go-auth-service/discussions
- **Security**: security@vhvplatform.com

### Creating a Bug Report

Include:
1. Service version
2. Go version
3. Deployment environment (Docker, Kubernetes, bare metal)
4. Steps to reproduce
5. Expected vs actual behavior
6. Relevant logs
7. Configuration (sanitized, no secrets)
8. Diagnostic information from script above
