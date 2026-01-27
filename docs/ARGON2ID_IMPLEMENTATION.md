# Argon2id Password Hashing Implementation

## Overview
Secure password hashing implementation using Argon2id algorithm with PHC string format, following OWASP 2023 recommendations.

## Implementation Details

### Algorithm: Argon2id v19
- **Memory**: 64 MB (65536 KiB)
- **Time (Iterations)**: 3
- **Parallelism (Threads)**: 4
- **Key Length**: 32 bytes
- **Salt Length**: 16 bytes (cryptographically secure random)

### PHC String Format
```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

Example:
```
$argon2id$v=19$m=65536,t=3,p=4$rq9Wv61eArIsReP7X2GY9A$CJepGpBn9SGw4hcC4k5lTxZPMCe9quYAD0FsN4CARp8
```

## Security Features

### 1. Cryptographically Secure Random Salt
- Uses `crypto/rand.Read()` for unpredictable salts
- 16-byte salt provides 2^128 possible values
- Each password hash has unique salt preventing rainbow table attacks

### 2. Constant-Time Comparison
- `subtleCompare()` function prevents timing attacks
- Uses `subtle.ConstantTimeCompare()` internally
- Execution time independent of where strings differ

### 3. OWASP 2023 Compliance
Parameters meet OWASP Password Storage Cheat Sheet recommendations:
- Memory: 64 MB (exceeds 47 MB minimum)
- Iterations: 3 (meets minimum)
- Parallelism: 4 threads
- Output: 32-byte hash

### 4. PHC String Parser
- Validates format before parsing
- Extracts parameters, salt, and hash from encoded string
- Handles base64 decoding with proper error checking
- Prevents invalid hash acceptance

## Files

### Core Implementation
- `internal/service/auth_service.go`
  - `hashPassword()`: Generates Argon2id hash with random salt
  - `verifyPassword()`: Constant-time verification using PHC parser

### Helper Functions
- `internal/service/password.go`
  - `parseArgon2idHash()`: Parses PHC format string
  - `subtleCompare()`: Constant-time byte comparison
  - `argon2Params`: Parameter struct

### Tests
- `internal/service/password_test.go`
  - 11 test cases covering all scenarios
  - 2 benchmarks for performance testing
  - Tests include:
    - Hash/verify success
    - Wrong password rejection
    - PHC format validation
    - Invalid format handling
    - Salt randomness verification
    - OWASP parameter compliance
    - Timing attack resistance
    - Cross-implementation compatibility

## Usage

### Hashing a Password
```go
service := &AuthService{}
hashedPassword, err := service.hashPassword("user_password_123")
if err != nil {
    // Handle error
}
// Store hashedPassword in database
```

### Verifying a Password
```go
service := &AuthService{}
isValid := service.verifyPassword("user_password_123", storedHash)
if !isValid {
    // Authentication failed
}
```

## Test Results

All 11 tests pass successfully:
```
✅ Hash and Verify Password Success
✅ Verify Wrong Password Fails
✅ PHC Format Validation
✅ Parse Valid Hash
✅ Parse Invalid Hash Formats (5 subtests)
✅ Different Passwords Produce Different Hashes
✅ Same Password Produces Different Hashes (Salt Randomness)
✅ OWASP Parameters
✅ Timing Attack Resistance
✅ Manual Hash Verification (Compatibility)
```

## Performance

Hashing performance on typical hardware:
- **Hash generation**: ~110ms per password
- **Verification**: ~110ms per password
- Total authentication time: ~220ms (acceptable for login flow)

These timings are intentional - Argon2id is designed to be computationally expensive to prevent brute-force attacks.

## Migration Notes

### From MongoDB
- Replace `bcrypt` or plain text passwords with Argon2id
- Store in `core.user_identities.credential_secret` column
- No need to migrate existing hashes immediately - implement on next password change

### Database Schema
```sql
-- In core.user_identities table
credential_secret TEXT -- Stores PHC format hash
```

## Security Recommendations

1. **Never log passwords or hashes** - Use redaction in logging
2. **Use HTTPS** - Passwords transmitted over secure channel
3. **Rate limiting** - Prevent brute-force attempts at login endpoint
4. **Account lockout** - After N failed attempts
5. **Password requirements** - Minimum 8 characters, complexity rules
6. **Salted hashing only** - Never use unsalted hashes

## References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [PHC String Format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
- [golang.org/x/crypto/argon2](https://pkg.go.dev/golang.org/x/crypto/argon2)

## Version History

- **2024-01**: Initial implementation with Argon2id
- Replaced MongoDB bcrypt implementation
- Added comprehensive test suite
- Integrated with authentication_flow.md
