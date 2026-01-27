# User Registration Implementation

## Overview
Complete user registration flow with identity creation and identifier indexing.

## Registration Flow

### Step-by-Step Process

1. **Normalize & Validate Inputs**
   - Email: Trim + lowercase
   - Phone: Convert to E.164 format (optional)
   - Validate email format

2. **Check Email Uniqueness**
   - Query `core.users` by normalized email
   - Return 409 Conflict if already exists

3. **Hash Password**
   - Generate Argon2id hash with secure random salt
   - OWASP 2023 parameters (64MB memory, 3 iterations)

4. **Create User Record**
   - Generate UUID v7 for user ID
   - Status: `PENDING` (requires email verification)
   - Store in `core.users` table

5. **Create User Identity**
   - Generate UUID v7 for identity ID
   - Type: `PASSWORD`
   - Store Argon2id hash in `credential_secret`
   - Store in `core.user_identities` table

6. **Create Email Identifier**
   - Hash: SHA256("email:" + normalizedEmail)
   - Store in `core.auth_identifiers` for fast lookup
   - Links to user_id and identity_id

7. **Create Phone Identifier (Optional)**
   - If phone provided, normalize to E.164
   - Hash: SHA256("phone:" + normalizedPhone)
   - Store in `core.auth_identifiers`

## Service Method

### Signature
```go
func (s *AuthService) Register(
    ctx context.Context,
    tenantID uuid.UUID,
    email, password, fullName string,
    phone *string,
) (*domain.User, error)
```

### Parameters
- `ctx`: Request context
- `tenantID`: UUID of tenant user is registering for
- `email`: User's email address (required)
- `password`: Plain text password (required, min 8 chars recommended)
- `fullName`: User's display name (required)
- `phone`: Phone number (optional)

### Returns
- `*domain.User`: Created user object with UUID
- `error`: Validation or database errors

### Error Codes
- `BadRequest`: Invalid email format
- `Conflict`: Email already registered
- `Internal`: Database or hashing errors

## gRPC Handler

### Request
```protobuf
message RegisterRequest {
  string email = 1;           // Required
  string username = 2;         // Optional (not used yet)
  string password = 3;         // Required
  string phone = 4;            // Optional
  string document_number = 5;  // Optional (passport/ID)
  string tenant_id = 6;        // Required
  string first_name = 7;       // Optional
  string last_name = 8;        // Optional
}
```

### Response
```protobuf
message RegisterResponse {
  string user_id = 1;          // UUID of created user
  string message = 2;          // "Registration successful. Please verify your email."
}
```

### Implementation
```go
func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error)
```

## Database Schema

### Users Table (core.users)
```sql
CREATE TABLE core.users (
    id UUID PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    phone_number TEXT,
    avatar_url TEXT,
    status VARCHAR(20) DEFAULT 'PENDING',  -- PENDING, ACTIVE, BANNED, DISABLED
    is_support_staff BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    locale VARCHAR(10) DEFAULT 'vi-VN',
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    deleted_at TIMESTAMP
);
```

### User Identities Table (core.user_identities)
```sql
CREATE TABLE core.user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES core.users(id),
    identity_type VARCHAR(50) NOT NULL,    -- PASSWORD, GOOGLE, GITHUB, etc
    identity_value TEXT NOT NULL,          -- Email, OAuth subject_id
    credential_secret TEXT,                -- Argon2id hash for PASSWORD type
    metadata JSONB DEFAULT '{}',
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    version INTEGER DEFAULT 1
);
```

### Auth Identifiers Table (core.auth_identifiers)
```sql
CREATE TABLE core.auth_identifiers (
    tenant_id UUID NOT NULL,
    identifier_hash BYTEA NOT NULL,        -- SHA256 hash
    user_id UUID NOT NULL REFERENCES core.users(id),
    identity_id UUID NOT NULL REFERENCES core.user_identities(id),
    identifier_type VARCHAR(50) NOT NULL,  -- email, phone, username, passport
    original_value TEXT,                   -- For display/debug only
    PRIMARY KEY (tenant_id, identifier_hash)
);
```

## Usage Examples

### Example 1: Email + Password Only
```go
user, err := authService.Register(
    ctx,
    tenantID,
    "test@example.com",
    "SecurePassword123!",
    "John Doe",
    nil, // no phone
)
```

**Result:**
- User created with status `PENDING`
- 1 identity: `PASSWORD` type
- 1 identifier: `email:test@example.com` (SHA256 hash)

### Example 2: Email + Password + Phone
```go
phone := "+84909123456"
user, err := authService.Register(
    ctx,
    tenantID,
    "test@example.com",
    "SecurePassword123!",
    "John Doe",
    &phone,
)
```

**Result:**
- User created with status `PENDING`
- 1 identity: `PASSWORD` type
- 2 identifiers:
  - `email:test@example.com` (SHA256 hash)
  - `phone:+84909123456` (SHA256 hash)

### Example 3: gRPC Request
```json
{
  "email": "test@example.com",
  "password": "SecurePassword123!",
  "first_name": "John",
  "last_name": "Doe",
  "phone": "0909.123.456",
  "tenant_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

**Response:**
```json
{
  "user_id": "987f6543-e21c-45d6-b789-123456789abc",
  "message": "Registration successful. Please verify your email."
}
```

## Security Considerations

### Password Security
- ✅ Argon2id hashing with OWASP 2023 parameters
- ✅ Secure random salt (crypto/rand)
- ✅ PHC string format for storage
- ✅ Never logged or exposed in responses

### Email Verification
- User status starts as `PENDING`
- Cannot login until verified (future feature)
- Verification email sent after registration (future feature)

### Phone Normalization
- All phones normalized to E.164 format
- Consistent hashing across different input formats
- Optional field - non-fatal if normalization fails

### Identifier Uniqueness
- Email uniqueness enforced at database level
- SHA256 hash prevents duplicate lookups
- Tenant-scoped identifiers (same email across tenants)

## Transaction Safety

### Current Implementation
Sequential operations without explicit transaction:
1. Insert user
2. Insert identity
3. Insert email identifier
4. Insert phone identifier (if provided)

### Rollback Strategy
- Manual rollback on failures (future enhancement)
- Or use database transactions for atomicity

### Recommended Transaction Wrapper
```go
tx, _ := db.BeginTx(ctx, nil)
defer tx.Rollback()

// Create user
// Create identity
// Create identifiers

tx.Commit()
```

## Testing

### Unit Tests
Currently no unit tests for Register method (future work).

### Integration Testing
```bash
# Start auth service
./auth-service.exe

# Test registration via gRPC
grpcurl -plaintext \
  -d '{
    "email": "test@example.com",
    "password": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe",
    "tenant_id": "123e4567-e89b-12d3-a456-426614174000"
  }' \
  localhost:50051 \
  auth.AuthService/Register
```

### Expected Outcomes
- ✅ User created in database
- ✅ Identity created with hashed password
- ✅ Email identifier created for fast lookup
- ✅ Can login immediately after registration

## Error Handling

### Validation Errors
```go
errors.BadRequest("Invalid email format")
errors.BadRequest("Password is required")
errors.BadRequest("Invalid tenant_id format")
```

### Conflict Errors
```go
errors.Conflict("Email already registered")
```

### Internal Errors
```go
errors.Internal("Registration failed")  // Generic message
// Detailed error logged with zap.Error()
```

## Future Enhancements

1. **Transaction support**: Atomic registration with rollback
2. **Email verification**: Send verification email, enforce before login
3. **Password validation**: Min length, complexity requirements
4. **Rate limiting**: Prevent registration spam
5. **Username support**: Allow registration with username instead of email
6. **Passport/ID support**: Store document_number as identifier
7. **Tenant configuration**: Respect tenant's allowed login methods
8. **Audit logging**: Track registration attempts and failures

## Related Documentation

- [Authentication Flow](../../docs/flows/authentication_flow.md)
- [Argon2id Implementation](./ARGON2ID_IMPLEMENTATION.md)
- [Phone Normalization](./PHONE_NORMALIZATION.md)

## Version History

- **2024-01**: Initial implementation
- Email + password registration
- Optional phone support
- Integrated with authentication flow
