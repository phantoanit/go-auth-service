# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of go-auth-service seriously. If you discover a security vulnerability, please follow these steps:

### 1. Do Not Disclose Publicly

Please do not create a public GitHub issue for security vulnerabilities. This helps protect users who haven't yet upgraded to a patched version.

### 2. Report Privately

Email security details to: **security@vhvplatform.com**

Include the following information:
- Type of vulnerability (e.g., SQL injection, XSS, authentication bypass)
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### 3. Response Timeline

- **Initial Response**: Within 48 hours of receiving your report
- **Validation**: We'll validate and investigate the vulnerability within 5 business days
- **Fix Development**: Critical vulnerabilities will be prioritized and fixed within 7 days
- **Disclosure**: We'll coordinate disclosure timing with you after a fix is available

## Security Best Practices

### For Developers

#### 1. Authentication & Authorization
- Always use bcrypt or Argon2id for password hashing (never store plain text passwords)
- Implement proper JWT token validation on all protected endpoints
- Use secure random token generation for refresh tokens and verification codes
- Implement token expiration and rotation policies
- Never log sensitive data (passwords, tokens, API keys)

#### 2. Input Validation & Sanitization
```go
// Always validate and sanitize user input
func validateEmail(email string) error {
    if !regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`).MatchString(email) {
        return errors.New("invalid email format")
    }
    return nil
}

// Use parameterized queries to prevent injection attacks
filter := bson.M{"email": email} // MongoDB automatically escapes
```

#### 3. Rate Limiting
```go
// Implement rate limiting for authentication endpoints
// Example: 5 login attempts per minute per IP
rateLimit := middleware.RateLimit{
    Requests:  5,
    Duration:  time.Minute,
    KeyFunc:   func(c *gin.Context) string { return c.ClientIP() },
}
```

#### 4. Session Management
- Use secure, HTTP-only cookies for refresh tokens
- Implement proper session expiration
- Clear sessions on logout
- Use Redis for distributed session storage

#### 5. Cryptography
- Use TLS 1.2+ for all communications
- Use strong JWT signing algorithms (RS256 recommended, HS256 minimum)
- Rotate JWT signing keys regularly
- Encrypt sensitive data at rest (OAuth tokens, API keys)

#### 6. Error Handling
```go
// Don't expose sensitive information in error messages
// Bad:
return errors.New("user 'admin@example.com' not found in database 'production'")

// Good:
return errors.New("invalid credentials")
```

### For Deployment

#### 1. Environment Variables
Never commit sensitive environment variables to version control:
```bash
# Use strong, randomly generated secrets
JWT_SECRET=$(openssl rand -base64 32)
DATABASE_PASSWORD=$(openssl rand -base64 24)

# Rotate secrets regularly (recommended: every 90 days)
```

#### 2. Database Security
- Use strong database passwords
- Enable MongoDB authentication
- Restrict database access by IP
- Enable encryption at rest
- Regular backups with encrypted storage

#### 3. Redis Security
- Enable Redis password authentication
- Bind Redis to localhost or private network only
- Use Redis ACLs for fine-grained access control
- Enable Redis TLS for production

#### 4. Network Security
- Use private networks for service-to-service communication
- Implement network policies to restrict traffic
- Use firewall rules to limit exposed ports
- Enable DDoS protection

#### 5. Monitoring & Logging
```bash
# Monitor for suspicious activities
- Failed login attempts (> 5 per minute)
- Multiple password reset requests
- Token validation failures
- Unusual API access patterns
- Geographic anomalies
```

#### 6. Docker Security
- Use official, minimal base images (alpine)
- Don't run containers as root
- Scan images for vulnerabilities regularly
- Keep base images updated
- Use multi-stage builds to reduce attack surface

## Security Features

### Implemented Security Measures

1. **Password Security**
   - Bcrypt hashing with cost factor 12
   - Password strength validation
   - Password history to prevent reuse
   - Configurable password policies

2. **Token Security**
   - JWT with configurable expiration
   - Refresh token rotation
   - Token blacklist for revocation
   - Secure token storage

3. **Rate Limiting**
   - Login attempts: 5 per minute per IP
   - Registration: 3 per hour per IP
   - Password reset: 3 per hour per IP
   - API endpoints: 100 per minute per user

4. **Brute Force Protection**
   - Account lockout after failed attempts
   - Progressive delays between attempts
   - CAPTCHA integration support
   - IP-based blocking

5. **CSRF Protection**
   - CSRF tokens for state-changing operations
   - SameSite cookie attributes
   - Origin validation

6. **Input Validation**
   - Email format validation
   - Password complexity requirements
   - SQL/NoSQL injection prevention
   - XSS prevention

7. **Multi-Factor Authentication**
   - TOTP-based 2FA
   - Backup codes generation
   - Recovery options

8. **Audit Logging**
   - Authentication events
   - Authorization failures
   - Token operations
   - Security-relevant actions

## Compliance

This service is designed with the following compliance standards in mind:

- **GDPR**: User data privacy and right to be forgotten
- **OWASP Top 10**: Protection against common web vulnerabilities
- **SOC 2**: Security controls and monitoring
- **PCI DSS**: Secure authentication mechanisms

## Security Checklist for Deployment

- [ ] Change all default passwords and secrets
- [ ] Enable TLS/HTTPS on all endpoints
- [ ] Configure CORS with specific allowed origins
- [ ] Set up rate limiting on all public endpoints
- [ ] Enable audit logging
- [ ] Configure MongoDB authentication
- [ ] Enable Redis password authentication
- [ ] Set up monitoring and alerting
- [ ] Implement backup and disaster recovery
- [ ] Review and test security configurations
- [ ] Perform security scanning (Snyk, Trivy)
- [ ] Set up intrusion detection
- [ ] Configure firewall rules
- [ ] Enable DDoS protection
- [ ] Regular security audits

## Known Security Issues

Check our [Security Advisories](https://github.com/vhvplatform/go-auth-service/security/advisories) for current security issues and patches.

## Security Updates

We recommend:
- Subscribe to security advisories
- Update to the latest version regularly
- Review CHANGELOG.md for security fixes
- Test updates in a staging environment first

## Third-Party Dependencies

We regularly scan our dependencies for vulnerabilities using:
- Dependabot
- Snyk
- Trivy

See [go.mod](go.mod) for a complete list of dependencies.

## Contact

For security concerns, please contact:
- Email: security@vhvplatform.com
- Security Advisory: [GitHub Security](https://github.com/vhvplatform/go-auth-service/security)

## Acknowledgments

We appreciate security researchers who help us improve the security of this project. Responsible disclosure is greatly appreciated.
