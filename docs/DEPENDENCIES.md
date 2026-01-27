# Auth Service Dependencies

## Shared Packages (from vhvplatform/go-shared repository)

**Note**: The vhvplatform/go-shared repository currently declares its module path as
`github.com/vhvplatform/go-shared`. Once it updates to `github.com/vhvplatform/go-shared`,
the import paths below will be updated accordingly.

```go
require (
    github.com/vhvplatform/go-shared/config
    github.com/vhvplatform/go-shared/logger
    github.com/vhvplatform/go-shared/mongodb
    github.com/vhvplatform/go-shared/redis
    github.com/vhvplatform/go-shared/jwt
    github.com/vhvplatform/go-shared/errors
    github.com/vhvplatform/go-shared/middleware
    github.com/vhvplatform/go-shared/response
    github.com/vhvplatform/go-shared/validation
)
```

## External Dependencies

### Infrastructure
- **MongoDB**: User data, roles, permissions
  - Collections: `users`, `roles`, `permissions`, `refresh_tokens`, `oauth_accounts`
- **Redis**: Session storage, rate limiting, token blacklist
  - Keys: `session:*`, `refresh_token:*`, `blacklist:*`

### Third-party Libraries
```go
require (
    github.com/gin-gonic/gin v1.10.0
    github.com/golang-jwt/jwt/v5 v5.2.2
    golang.org/x/crypto v0.45.0
    google.golang.org/grpc v1.69.2
    google.golang.org/protobuf v1.36.8
    go.mongodb.org/mongo-driver v1.17.3
    go.uber.org/zap v1.27.0
)
```

## Inter-service Communication

### Services Called by Auth Service
- **User Service** (gRPC: 50052): Create user profile after registration

### Services Calling Auth Service
- **API Gateway**: All authentication/authorization requests
- **All Services**: Token validation and user context

## Environment Variables

```bash
# Server Configuration
AUTH_SERVICE_PORT=50051
AUTH_SERVICE_HTTP_PORT=8081

# Database
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=saas_framework

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_PASSWORD=
REDIS_DB=0

# JWT Configuration
JWT_SECRET=your-secret-key-change-in-production
JWT_ACCESS_TOKEN_EXPIRY=15m
JWT_REFRESH_TOKEN_EXPIRY=168h
JWT_ISSUER=saas-framework

# OAuth2 (Optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
GOOGLE_REDIRECT_URL=http://localhost:8080/auth/google/callback
GITHUB_CLIENT_ID=
GITHUB_CLIENT_SECRET=
GITHUB_REDIRECT_URL=http://localhost:8080/auth/github/callback

# Service Discovery
USER_SERVICE_URL=localhost:50052

# Logging
LOG_LEVEL=info
LOG_FORMAT=json

# CORS
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
```

## Database Schema

### Collections

#### users
```json
{
  "id": "ObjectId",
  "email": "string (unique, indexed)",
  "password_hash": "string",
  "tenant_id": "string (indexed)",
  "roles": ["string"],
  "is_active": "boolean",
  "is_verified": "boolean",
  "email_verified_at": "timestamp",
  "last_login_at": "timestamp",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

**Indexes:**
- `email` (unique)
- `tenant_id`
- `is_active`

#### refresh_tokens
```json
{
  "id": "ObjectId",
  "user_id": "string (indexed)",
  "token_hash": "string (unique, indexed)",
  "expires_at": "timestamp (indexed)",
  "created_at": "timestamp",
  "revoked_at": "timestamp",
  "revoked_by": "string",
  "ip_address": "string",
  "user_agent": "string"
}
```

**Indexes:**
- `user_id`
- `token_hash` (unique)
- `expires_at`

#### oauth_accounts
```json
{
  "id": "ObjectId",
  "user_id": "string (indexed)",
  "provider": "string (google/github)",
  "provider_user_id": "string",
  "email": "string",
  "name": "string",
  "avatar_url": "string",
  "access_token": "string (encrypted)",
  "refresh_token": "string (encrypted)",
  "expires_at": "timestamp",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

**Indexes:**
- `user_id`
- `provider` + `provider_user_id` (compound, unique)

#### roles
```json
{
  "id": "ObjectId",
  "name": "string (unique, indexed)",
  "display_name": "string",
  "description": "string",
  "permissions": ["string"],
  "tenant_id": "string (indexed)",
  "is_system": "boolean",
  "created_at": "timestamp",
  "updated_at": "timestamp"
}
```

**Indexes:**
- `name` (unique)
- `tenant_id`

#### permissions
```json
{
  "id": "ObjectId",
  "name": "string (unique, indexed)",
  "resource": "string",
  "action": "string",
  "description": "string",
  "created_at": "timestamp"
}
```

**Indexes:**
- `name` (unique)
- `resource` + `action` (compound)

## API Endpoints

### gRPC (Port 50051)
- `AuthService.Login`
- `AuthService.Register`
- `AuthService.RefreshToken`
- `AuthService.ValidateToken`
- `AuthService.Logout`
- `AuthService.RevokeToken`

### HTTP/REST (Port 8081)
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/validate`
- `GET /api/v1/auth/oauth/google`
- `GET /api/v1/auth/oauth/google/callback`
- `GET /api/v1/auth/oauth/github`
- `GET /api/v1/auth/oauth/github/callback`
- `GET /health`
- `GET /metrics`

## Resource Requirements

### Development
- CPU: 0.5 cores
- Memory: 512MB
- Storage: 1GB

### Production
- CPU: 2 cores (burst to 4)
- Memory: 2GB
- Storage: 10GB
- Replicas: 3 (minimum for HA)

### Scaling Triggers
- CPU > 70%
- Memory > 80%
- Request rate > 1000 req/s per instance

## Health Checks

### Liveness Probe
- Endpoint: `/health`
- Interval: 10s
- Timeout: 5s
- Failure threshold: 3

### Readiness Probe
- Endpoint: `/health`
- Checks: MongoDB connection, Redis connection
- Interval: 5s
- Timeout: 3s
- Failure threshold: 2

## Performance Considerations

### Caching Strategy
- Token validation results cached in Redis (5 min TTL)
- User roles and permissions cached (10 min TTL)
- OAuth provider configs cached (1 hour TTL)

### Rate Limiting
- Login attempts: 5 per minute per IP
- Registration: 3 per hour per IP
- Token refresh: 10 per minute per user
- OAuth callbacks: 5 per minute per IP

## Security Considerations

- Passwords hashed with bcrypt (cost factor 12)
- JWT tokens signed with HS256 (consider RS256 for production)
- Refresh tokens stored as hashed values
- OAuth tokens encrypted at rest
- Rate limiting to prevent brute force attacks
- Input validation on all endpoints
- SQL injection protection (MongoDB parameterized queries)
- XSS protection (input sanitization)
