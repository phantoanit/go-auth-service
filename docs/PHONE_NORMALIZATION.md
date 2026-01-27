# Phone Normalization Implementation

## Overview
E.164 phone number normalization for consistent identifier hashing and authentication.

## E.164 Format
International standard for phone numbers:
```
+[country code][subscriber number]
Example: +84909123456
```

## Implementation

### Functions

#### `normalizeIdentifier(input string) string`
Main entry point for all identifier normalization:
- **Email**: Trim + lowercase (`Test@Example.COM` → `test@example.com`)
- **Phone**: Convert to E.164 (`0909.123.456` → `+84909123456`)
- **Username/Passport**: Trim whitespace

#### `isPhoneNumber(input string) bool`
Detects if input is a phone number:
- Counts digits (ignoring separators)
- Valid range: 8-15 digits
- Returns false for emails, usernames

#### `normalizePhone(input string) string`
Converts phone to E.164 format:
- Removes separators (dots, dashes, spaces, parentheses)
- Handles Vietnam default country code (+84)
- Supports international formats
- Special case: Removes (0) prefix in +84 (0) 909 format

## Examples

### Vietnam Phone Numbers
```go
Input: "0909123456"          → Output: "+84909123456"
Input: "0909.123.456"        → Output: "+84909123456"
Input: "0909-123-456"        → Output: "+84909123456"
Input: "(090) 912-3456"      → Output: "+84909123456"
Input: "+84 (0) 909 123 456" → Output: "+84909123456"
```

### International Numbers
```go
Input: "+12025551234"  → Output: "+12025551234"  (US)
Input: "+441234567890" → Output: "+441234567890" (UK)
Input: "84909123456"   → Output: "+84909123456"  (no plus)
```

### Non-Phone Inputs
```go
Input: "test@example.com" → Output: "test@example.com" (email)
Input: "john_doe"         → Output: "john_doe"         (username)
Input: "N1234567"         → Output: "N1234567"         (passport)
```

## Vietnam-Specific Rules

### Default Country Code
When no country code detected, assumes Vietnam (+84):
```go
"0909123456"  → "+84909123456"
"909123456"   → "+84909123456"
```

### (0) Prefix Handling
Vietnam carriers often use +84 (0) format for landlines/mobiles:
```
+84 (0) 909 123 456 → +84909123456
```
The (0) is removed as it's not part of E.164 standard.

## Integration with Authentication Flow

### Step 1: User Input
```
User enters: "0909.123.456"
```

### Step 2: Normalization
```go
normalized := s.normalizeIdentifier("0909.123.456")
// Result: "+84909123456"
```

### Step 3: Hashing
```go
hash := sha256.Sum256([]byte("phone:+84909123456"))
```

### Step 4: Database Lookup
```sql
SELECT user_id, identity_id
FROM auth_identifiers
WHERE tenant_id = ? AND identifier_hash = ?
```

## Testing

### Test Coverage
- ✅ 9 phone normalization scenarios
- ✅ 7 phone detection tests
- ✅ 6 identifier normalization tests
- ✅ All tests passing

### Run Tests
```bash
go test ./internal/service/... -run TestPhone -v
go test ./internal/service/... -run TestNormalizeIdentifier -v
```

## Edge Cases Handled

1. **Multiple separators**: `+84 (0) 909-123.456` → `+84909123456`
2. **Leading zeros**: `0909123456` → `+84909123456`
3. **Country code without plus**: `84909123456` → `+84909123456`
4. **Short numbers**: `1234567` → Not detected as phone
5. **Long numbers**: `12345678901234567` → Not detected as phone
6. **Mixed content**: `test@example.com` → Treated as email

## Performance

- **Time complexity**: O(n) where n is input length
- **Space complexity**: O(n) for string building
- **Typical processing**: < 1µs per normalization

## Security Considerations

1. **Consistent hashing**: Same phone, different formats → same hash
2. **No information leakage**: Original format not exposed in logs
3. **Case-insensitive**: All phones normalized to E.164

## Database Schema

### auth_identifiers table
```sql
CREATE TABLE core.auth_identifiers (
    tenant_id UUID NOT NULL,
    identifier_hash BYTEA NOT NULL,  -- SHA256("phone:+84909123456")
    user_id UUID NOT NULL,
    identity_id UUID NOT NULL,
    identifier_type VARCHAR(50),     -- "phone"
    original_value TEXT,             -- "+84909123456"
    PRIMARY KEY (tenant_id, identifier_hash)
);
```

### user_identities table
```sql
CREATE TABLE core.user_identities (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    identity_type VARCHAR(50),       -- "PASSWORD", "GOOGLE", etc
    identity_value TEXT,             -- "+84909123456" or "email@example.com"
    credential_secret TEXT,          -- Argon2id hash for PASSWORD type
    metadata JSONB,
    is_verified BOOLEAN DEFAULT FALSE,
    verified_at TIMESTAMP,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    version INTEGER DEFAULT 1
);
```

## Future Enhancements

1. **Country detection from tenant**: Use tenant's default country code
2. **Validation libraries**: Integrate libphonenumber for stricter validation
3. **Format preservation**: Store original input for display purposes
4. **Multi-country support**: Detect country from leading digits

## References

- [E.164 Standard](https://www.itu.int/rec/T-REC-E.164/)
- [libphonenumber](https://github.com/google/libphonenumber)
- [Authentication Flow](../../docs/flows/authentication_flow.md)

## Version History

- **2024-01**: Initial implementation with Vietnam-specific rules
- Integrated with authentication flow
- Comprehensive test coverage
