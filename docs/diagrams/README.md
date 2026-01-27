# Authentication Service Diagrams

This directory contains PlantUML diagrams that document the authentication service architecture and flows.

## Viewing Diagrams

You can view these diagrams in several ways:

1. **VS Code**: Install the [PlantUML extension](https://marketplace.visualstudio.com/items?itemName=jebbs.plantuml)
2. **IntelliJ IDEA**: Built-in PlantUML support
3. **Online**: Use [PlantUML Online Editor](http://www.plantuml.com/plantuml/uml/)
4. **Command Line**: Install PlantUML and run `plantuml *.puml`

## Diagram Index

### 1. Database ER Diagram (`database-er-diagram.puml`)
**Purpose**: Visual representation of the database schema and entity relationships

**Covers**:
- All database collections/tables (users_auth, refresh_tokens, roles, permissions, oauth_accounts)
- Entity attributes with data types
- Primary keys, foreign keys, and unique constraints
- Relationships with cardinality (1:1, 1:N, N:M)
- Indexes for performance optimization
- Multi-tenancy design patterns
- Data flow between entities

**Key Features**:
- Complete field definitions with required/optional markers
- Index specifications (UNIQUE, TTL)
- Relationship annotations with cardinality
- Security considerations per entity
- Multi-tenant isolation design
- Common query patterns

**Collections Documented**:
1. **users_auth**: User authentication data
2. **refresh_tokens**: JWT refresh token management
3. **roles**: RBAC role definitions
4. **permissions**: Permission catalog
5. **oauth_accounts**: OAuth provider linking

---

### 2. Authentication Flow (`authentication-flow.puml`)
**Purpose**: Documents the complete user authentication lifecycle

**Covers**:
- User registration with email verification
- Email verification process
- User login flow with credential validation
- Failed login attempts and account lockout
- Access token and refresh token generation
- Accessing protected resources
- User logout and token revocation

**Key Features**:
- Bcrypt password hashing
- Rate limiting (5 failed attempts → 15 min lockout)
- Redis session caching
- Token blacklisting on logout
- Last login timestamp tracking

---

### 3. JWT Token Flow (`jwt-token-flow.puml`)
**Purpose**: Details JWT token generation, validation, and refresh mechanisms

**Covers**:
- JWT token structure (header, payload, signature)
- Token generation on login
- Token validation process
- Signature verification
- Expiration checking
- Token blacklist verification
- Permission validation
- Token refresh flow
- Token revocation on logout

**Key Features**:
- HS256/RS256 signing algorithms
- 15-minute access token expiry
- 7-day refresh token expiry
- Session caching for performance
- Automatic TTL management for blacklist

---

### 4. OAuth2 Flow (`oauth2-flow.puml`)
**Purpose**: Demonstrates OAuth2 integration for social login

**Covers**:
- OAuth2 Authorization Code Flow
- State token generation (CSRF protection)
- Redirect to OAuth provider (Google, GitHub)
- Authorization code exchange
- User profile retrieval
- Account linking/creation
- OAuth token storage (encrypted)
- OAuth token refresh
- Client Credentials Flow (service-to-service)

**Key Features**:
- CSRF protection with state parameter
- Encrypted OAuth token storage (AES-256)
- Support for multiple providers
- Automatic user creation on first login
- Token refresh mechanism

---

### 5. MFA Flow (`mfa-flow.puml`)
**Purpose**: Shows Multi-Factor Authentication setup and usage

**Covers**:
- MFA enrollment/setup
- TOTP secret generation
- QR code generation for authenticator apps
- Backup codes generation
- MFA verification during setup
- Login with MFA enabled
- MFA code validation
- Login with backup codes
- MFA disable flow

**Key Features**:
- TOTP (Time-based One-Time Password)
- 6-digit codes, 30-second window
- ±1 time window for clock skew
- 8 single-use backup codes
- Rate limiting (3 attempts per MFA session)
- 15-minute account lockout after failures

---

### 6. Password Reset Flow (`password-reset-flow.puml`)
**Purpose**: Details the forgot password and reset process

**Covers**:
- Forgot password request
- Rate limiting (3 requests per hour)
- Reset token generation and storage
- Email sending with reset link
- Token validation
- Password complexity validation
- Password change with old password verification
- Session invalidation after reset
- Security notifications
- Account recovery options

**Key Features**:
- Email enumeration prevention
- 1-hour token expiration
- One-time use tokens
- Strong password requirements
- Revoke all sessions on reset
- Email notifications on change
- Audit logging

---

### 7. Session Management (`session-management.puml`)
**Purpose**: Explains session lifecycle management

**Covers**:
- Session creation on login
- Session data structure
- Session validation on API requests
- Sliding expiration window (15 minutes)
- Session refresh with token refresh
- Session termination on logout
- Background cleanup jobs
- Multi-session management
- Session revocation

**Key Features**:
- Redis-based session storage
- 15-minute idle timeout
- Activity-based session extension
- Per-user session indexing
- Concurrent session limits (max 5)
- IP and device fingerprinting
- Session hijacking protection

---

### 8. Architecture Diagram (`architecture.puml`)
**Purpose**: Overview of the entire authentication service architecture

**Covers**:
- Component structure (layers)
- API Layer (HTTP/REST, gRPC, WebSocket)
- Middleware pipeline
- Service layer (business logic)
- Repository layer (data access)
- Domain models
- External dependencies (MongoDB, Redis)
- OAuth provider integration
- Email service integration
- Monitoring and observability
- Kubernetes deployment structure

**Key Components**:
- API Gateway with load balancing
- Microservice architecture
- Shared library usage
- Security services (Vault, Secrets Manager)
- Message queue for async operations
- Prometheus metrics
- ELK Stack for logging
- Jaeger for distributed tracing

---

## Common Patterns

### Security Best Practices
All diagrams illustrate these security principles:
1. **Defense in Depth**: Multiple security layers
2. **Least Privilege**: Minimal permissions by default
3. **Secure by Default**: Security-first configuration
4. **Fail Securely**: Graceful error handling
5. **Audit Everything**: Comprehensive logging

### Rate Limiting
Consistently applied across flows:
- Login: 5 attempts per minute per IP
- Registration: 3 per hour per IP
- Password Reset: 3 per hour per email
- MFA: 3 attempts per session
- OAuth: 5 callbacks per minute per IP

### Token Management
Standard token handling:
- **Access Tokens**: Short-lived (15 minutes), in memory
- **Refresh Tokens**: Long-lived (7 days), HTTP-only cookie
- **Reset Tokens**: One-time use (1 hour expiry)
- **MFA Tokens**: Temporary (5 minutes)
- **OAuth Tokens**: Encrypted at rest

### Database Operations
Consistent data handling:
- **MongoDB**: User data, tokens, audit logs
- **Redis**: Sessions, cache, rate limits, blacklist
- **Indexes**: Optimized for common queries
- **TTL**: Automatic cleanup of expired data

## Integration Examples

### Example 1: Complete User Journey
```
authentication-flow.puml → jwt-token-flow.puml → session-management.puml
```
New user signs up, verifies email, logs in, receives JWT, session is created and managed.

### Example 2: Social Login
```
oauth2-flow.puml → jwt-token-flow.puml → session-management.puml
```
User authenticates via Google OAuth, receives JWT, session is created.

### Example 3: Enhanced Security
```
authentication-flow.puml → mfa-flow.puml → jwt-token-flow.puml
```
User logs in, completes MFA challenge, receives JWT tokens.

### Example 4: Account Recovery
```
password-reset-flow.puml → authentication-flow.puml
```
User resets forgotten password, then logs in with new password.

## Generating PNG/SVG

To generate images from PlantUML files:

```bash
# Install PlantUML
brew install plantuml  # macOS
# or
apt-get install plantuml  # Ubuntu/Debian

# Generate PNG
plantuml -tpng *.puml

# Generate SVG
plantuml -tsvg *.puml

# Generate all formats
plantuml *.puml
```

## Contributing

When updating diagrams:
1. Keep consistent styling (use the same theme)
2. Add detailed notes for complex flows
3. Update this README if adding new diagrams
4. Validate PlantUML syntax before committing
5. Generate preview images for documentation

## References

- [PlantUML Documentation](https://plantuml.com/)
- [PlantUML Sequence Diagram Guide](https://plantuml.com/sequence-diagram)
- [PlantUML Component Diagram Guide](https://plantuml.com/component-diagram)
- [OAuth 2.0 Specification](https://oauth.net/2/)
- [JWT Specification](https://jwt.io/)
- [TOTP RFC 6238](https://tools.ietf.org/html/rfc6238)
