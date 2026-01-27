# Security Hardening Guide

This guide provides comprehensive security hardening recommendations for the Auth Service in production environments.

## Table of Contents

- [Network Security](#network-security)
- [Authentication Security](#authentication-security)
- [Data Protection](#data-protection)
- [Infrastructure Security](#infrastructure-security)
- [Application Security](#application-security)
- [Monitoring and Auditing](#monitoring-and-auditing)
- [Compliance](#compliance)
- [Security Checklist](#security-checklist)

## Network Security

### TLS/SSL Configuration

**Minimum TLS Version**: TLS 1.3 (TLS 1.2 acceptable with strong cipher suites)

#### Recommended Cipher Suites (TLS 1.3)
```
TLS_AES_128_GCM_SHA256
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
```

#### Nginx Configuration Example
```nginx
server {
    listen 443 ssl http2;
    server_name auth.yourdomain.com;
    
    # TLS Configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.3 TLSv1.2;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    # Security Headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # CSP
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';" always;
    
    location / {
        proxy_pass http://localhost:8081;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Firewall Rules

#### Inbound Rules
```bash
# Allow only necessary ports
iptables -A INPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # SSH (limited IPs)
iptables -A INPUT -j DROP                        # Drop all others

# Allow from specific IPs only
iptables -A INPUT -p tcp --dport 22 -s 203.0.113.0/24 -j ACCEPT
```

#### AWS Security Group Example
```yaml
SecurityGroup:
  Type: AWS::EC2::SecurityGroup
  Properties:
    GroupDescription: Auth Service Security Group
    VpcId: !Ref VPC
    SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 443
        ToPort: 443
        CidrIp: 0.0.0.0/0
      - IpProtocol: tcp
        FromPort: 50051
        ToPort: 50051
        SourceSecurityGroupId: !Ref InternalServicesSecurityGroup
    SecurityGroupEgress:
      - IpProtocol: tcp
        FromPort: 27017
        ToPort: 27017
        DestinationSecurityGroupId: !Ref MongoDBSecurityGroup
      - IpProtocol: tcp
        FromPort: 6379
        ToPort: 6379
        DestinationSecurityGroupId: !Ref RedisSecurityGroup
```

### DDoS Protection

```bash
# Rate limiting with iptables
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --set
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -m recent --update --seconds 60 --hitcount 20 -j DROP

# Connection limits
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 50 -j REJECT
```

## Authentication Security

### JWT Configuration

```bash
# Environment variables for production
JWT_SECRET=$(openssl rand -base64 64)  # Generate strong secret (512 bits)
JWT_ACCESS_TOKEN_EXPIRY=15m            # Short-lived access tokens
JWT_REFRESH_TOKEN_EXPIRY=7d            # Refresh tokens
JWT_ALGORITHM=HS256                     # Or RS256 for distributed systems
JWT_ISSUER=auth.yourdomain.com
JWT_AUDIENCE=yourdomain.com
```

**Best Practices**:
1. **Rotate JWT secrets** every 90 days
2. Use **RS256 for multi-service architecture** (asymmetric keys)
3. Include **jti (JWT ID)** for token revocation tracking
4. Store **refresh tokens hashed** in database
5. Implement **token binding** to prevent token theft

### Password Policy

```go
// Password requirements configuration
const (
    MinPasswordLength = 12
    MaxPasswordLength = 128
    RequireUppercase  = true
    RequireLowercase  = true
    RequireDigit      = true
    RequireSpecial    = true
    MaxPasswordAge    = 90 * 24 * time.Hour  // Force password change
    PasswordHistory   = 5                     // Prevent reuse
)

// Banned passwords list
var CommonPasswords = []string{
    "password123", "admin123", "qwerty123",
    // ... load from file: docs/common-passwords.txt
}
```

**Password Validation Example**:
```go
func ValidatePassword(password string) error {
    if len(password) < MinPasswordLength {
        return errors.New("password too short")
    }
    if len(password) > MaxPasswordLength {
        return errors.New("password too long")
    }
    if RequireUppercase && !hasUppercase(password) {
        return errors.New("password must contain uppercase letter")
    }
    // ... additional checks
    
    // Check against common passwords
    if contains(CommonPasswords, strings.ToLower(password)) {
        return errors.New("password too common")
    }
    
    return nil
}
```

### Account Lockout Policy

```go
const (
    MaxLoginAttempts     = 5
    LockoutDuration      = 15 * time.Minute
    LockoutThreshold     = 3                  // Lockouts before extended ban
    ExtendedLockout      = 24 * time.Hour
)

// Implementation in Redis
func TrackFailedLogin(ctx context.Context, userID string) error {
    key := fmt.Sprintf("failed_login:%s", userID)
    count, _ := redis.Incr(ctx, key).Result()
    
    if count == 1 {
        redis.Expire(ctx, key, LockoutDuration)
    }
    
    if count >= MaxLoginAttempts {
        // Lock account
        lockKey := fmt.Sprintf("account_locked:%s", userID)
        redis.Set(ctx, lockKey, "true", LockoutDuration)
        
        // Check for repeat lockouts
        lockCount, _ := redis.Incr(ctx, fmt.Sprintf("lockout_count:%s", userID)).Result()
        if lockCount >= LockoutThreshold {
            redis.Set(ctx, lockKey, "true", ExtendedLockout)
        }
        
        return errors.New("account locked due to multiple failed attempts")
    }
    
    return nil
}
```

### Multi-Factor Authentication (2FA)

**Enforce 2FA for**:
- Admin accounts (mandatory)
- API key management
- Password changes
- Account settings modifications
- High-privilege operations

```bash
# Environment configuration
REQUIRE_2FA_FOR_ADMINS=true
REQUIRE_2FA_FOR_API_KEYS=true
ALLOW_2FA_BACKUP_CODES=true
BACKUP_CODE_COUNT=10
TOTP_ISSUER=YourCompany
TOTP_PERIOD=30  # seconds
TOTP_DIGITS=6
```

## Data Protection

### Encryption at Rest

#### Database Encryption (MongoDB)

```yaml
# MongoDB configuration with encryption
security:
  enableEncryption: true
  encryptionKeyFile: /path/to/keyfile
  
# Field-level encryption for sensitive data
encryptionFields:
  - field: oauth_accounts.access_token
    algorithm: AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic
  - field: oauth_accounts.refresh_token
    algorithm: AEAD_AES_256_CBC_HMAC_SHA_512-Random
  - field: users.phone_number
    algorithm: AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic
```

#### Application-Level Encryption

```go
package encryption

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/base64"
    "io"
)

// EncryptionService handles AES-256-GCM encryption
type EncryptionService struct {
    key []byte  // 32 bytes for AES-256
}

func NewEncryptionService(key string) (*EncryptionService, error) {
    keyBytes, err := base64.StdEncoding.DecodeString(key)
    if err != nil || len(keyBytes) != 32 {
        return nil, errors.New("invalid encryption key")
    }
    return &EncryptionService{key: keyBytes}, nil
}

func (e *EncryptionService) Encrypt(plaintext string) (string, error) {
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return "", err
    }
    
    ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
    return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (e *EncryptionService) Decrypt(ciphertext string) (string, error) {
    data, err := base64.StdEncoding.DecodeString(ciphertext)
    if err != nil {
        return "", err
    }
    
    block, err := aes.NewCipher(e.key)
    if err != nil {
        return "", err
    }
    
    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return "", err
    }
    
    nonceSize := gcm.NonceSize()
    if len(data) < nonceSize {
        return "", errors.New("ciphertext too short")
    }
    
    nonce, ciphertext := data[:nonceSize], data[nonceSize:]
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return "", err
    }
    
    return string(plaintext), nil
}
```

### PII Data Handling

**Data Classification**:
- **Highly Sensitive**: Passwords, 2FA secrets, OAuth tokens
- **Sensitive**: Email, phone, full name
- **Public**: User ID, tenant ID, roles

**Protection Measures**:
```go
// Mask email for logging
func MaskEmail(email string) string {
    parts := strings.Split(email, "@")
    if len(parts) != 2 {
        return "***"
    }
    username := parts[0]
    if len(username) <= 2 {
        return "***@" + parts[1]
    }
    return username[:2] + "***@" + parts[1]
}

// Never log sensitive data
log.Info("User login",
    zap.String("user_id", user.ID),
    zap.String("email", MaskEmail(user.Email)),  // Masked
    // Never log: password, tokens, secrets
)
```

## Infrastructure Security

### Docker Security

```dockerfile
# Use specific versions, not :latest
FROM golang:1.25.5-alpine AS builder

# Run as non-root user
RUN addgroup -g 1000 appuser && \
    adduser -D -u 1000 -G appuser appuser

# Minimal final image
FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/bin/auth-service /auth-service

# Switch to non-root
USER appuser

# Read-only filesystem
WORKDIR /app
COPY --chown=appuser:appuser . .

CMD ["/auth-service"]
```

**Docker Compose Security**:
```yaml
version: '3.8'
services:
  auth-service:
    image: auth-service:latest
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    tmpfs:
      - /tmp
    networks:
      - internal
    secrets:
      - jwt_secret
      - db_password
```

### Kubernetes Security

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3
  template:
    spec:
      serviceAccountName: auth-service
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: auth-service
        image: auth-service:1.0.0
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          limits:
            cpu: "2"
            memory: "2Gi"
          requests:
            cpu: "500m"
            memory: "512Mi"
        livenessProbe:
          httpGet:
            path: /health
            port: 8081
          initialDelaySeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8081
          initialDelaySeconds: 5
```

### Secrets Management

**Use Secret Managers** (never hardcode secrets):

```go
// AWS Secrets Manager
import "github.com/aws/aws-sdk-go/service/secretsmanager"

func GetSecret(secretName string) (string, error) {
    svc := secretsmanager.New(session.Must(session.NewSession()))
    input := &secretsmanager.GetSecretValueInput{
        SecretId: aws.String(secretName),
    }
    
    result, err := svc.GetSecretValue(input)
    if err != nil {
        return "", err
    }
    
    return *result.SecretString, nil
}

// HashiCorp Vault
import "github.com/hashicorp/vault/api"

func GetSecretFromVault(path string) (string, error) {
    client, err := api.NewClient(api.DefaultConfig())
    if err != nil {
        return "", err
    }
    
    secret, err := client.Logical().Read(path)
    if err != nil {
        return "", err
    }
    
    return secret.Data["value"].(string), nil
}
```

## Application Security

### Input Validation

```go
package validation

import (
    "regexp"
    "github.com/go-playground/validator/v10"
)

var validate = validator.New()

// Register custom validators
func init() {
    validate.RegisterValidation("no_sql_injection", validateNoSQLInjection)
    validate.RegisterValidation("no_xss", validateNoXSS)
}

type RegisterRequest struct {
    Email    string `json:"email" validate:"required,email,max=255"`
    Password string `json:"password" validate:"required,min=12,max=128,password_strength"`
    TenantID string `json:"tenant_id" validate:"required,alphanum,max=50"`
}

func validateNoSQLInjection(fl validator.FieldLevel) bool {
    value := fl.Field().String()
    // Block common NoSQL injection patterns
    patterns := []string{`\$`, `\.`, `\{`, `\}`, `\[`, `\]`}
    for _, pattern := range patterns {
        if matched, _ := regexp.MatchString(pattern, value); matched {
            return false
        }
    }
    return true
}

func validateNoXSS(fl validator.FieldLevel) bool {
    value := fl.Field().String()
    // Block common XSS patterns
    patterns := []string{`<script`, `javascript:`, `onerror=`, `onclick=`}
    for _, pattern := range patterns {
        if matched, _ := regexp.MatchString(`(?i)`+pattern, value); matched {
            return false
        }
    }
    return true
}
```

### CSRF Protection

```go
// CSRF middleware
func CSRFMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Skip CSRF for safe methods
        if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }
        
        // Get CSRF token from header
        token := c.GetHeader("X-CSRF-Token")
        if token == "" {
            c.AbortWithStatusJSON(403, gin.H{"error": "CSRF token missing"})
            return
        }
        
        // Validate token
        if !validateCSRFToken(token, c) {
            c.AbortWithStatusJSON(403, gin.H{"error": "Invalid CSRF token"})
            return
        }
        
        c.Next()
    }
}
```

### Rate Limiting

```go
// Advanced rate limiting with Redis
type RateLimiter struct {
    redis *redis.Client
}

func (rl *RateLimiter) CheckLimit(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
    now := time.Now().Unix()
    windowStart := now - int64(window.Seconds())
    
    pipe := rl.redis.Pipeline()
    
    // Remove old entries
    pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart))
    
    // Count current requests
    pipe.ZCard(ctx, key)
    
    // Add current request
    pipe.ZAdd(ctx, key, &redis.Z{Score: float64(now), Member: fmt.Sprintf("%d", now)})
    
    // Set expiration
    pipe.Expire(ctx, key, window)
    
    cmds, err := pipe.Exec(ctx)
    if err != nil {
        return false, err
    }
    
    count := cmds[1].(*redis.IntCmd).Val()
    
    return count < int64(limit), nil
}

// Usage in middleware
func RateLimitMiddleware(limiter *RateLimiter) gin.HandlerFunc {
    return func(c *gin.Context) {
        ip := c.ClientIP()
        endpoint := c.Request.URL.Path
        key := fmt.Sprintf("rate_limit:%s:%s", ip, endpoint)
        
        allowed, err := limiter.CheckLimit(c.Request.Context(), key, 100, time.Minute)
        if err != nil {
            c.AbortWithStatusJSON(500, gin.H{"error": "Rate limit check failed"})
            return
        }
        
        if !allowed {
            c.AbortWithStatusJSON(429, gin.H{"error": "Rate limit exceeded"})
            return
        }
        
        c.Next()
    }
}
```

## Monitoring and Auditing

### Security Event Logging

```go
type SecurityEvent struct {
    Timestamp  time.Time              `json:"timestamp"`
    EventType  string                 `json:"event_type"`
    UserID     string                 `json:"user_id,omitempty"`
    IP         string                 `json:"ip_address"`
    UserAgent  string                 `json:"user_agent"`
    Success    bool                   `json:"success"`
    Metadata   map[string]interface{} `json:"metadata,omitempty"`
    Severity   string                 `json:"severity"` // INFO, WARNING, CRITICAL
}

// Log security events
func (s *AuthService) LogSecurityEvent(ctx context.Context, event *SecurityEvent) {
    event.Timestamp = time.Now()
    
    // Log to application logger
    s.logger.Info("Security event",
        zap.String("type", event.EventType),
        zap.String("user_id", event.UserID),
        zap.Bool("success", event.Success),
    )
    
    // Store in database for audit trail
    s.auditRepo.Create(ctx, event)
    
    // Send to SIEM if critical
    if event.Severity == "CRITICAL" {
        s.sendToSIEM(event)
    }
}

// Events to log:
// - login_attempt (success/failure)
// - password_change
// - 2fa_enabled/disabled
// - token_generated
// - token_revoked
// - permission_denied
// - account_locked
// - oauth_linked
// - suspicious_activity
```

### Metrics and Alerts

```go
// Prometheus metrics
var (
    loginAttempts = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_login_attempts_total",
            Help: "Total number of login attempts",
        },
        []string{"status", "method"},
    )
    
    failedLogins = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "auth_failed_logins_total",
            Help: "Total number of failed login attempts",
        },
        []string{"reason"},
    )
    
    activeSessions = promauto.NewGauge(
        prometheus.GaugeOpts{
            Name: "auth_active_sessions",
            Help: "Number of active user sessions",
        },
    )
)

// Alert rules (Prometheus AlertManager)
groups:
  - name: auth_security
    rules:
      - alert: HighFailedLoginRate
        expr: rate(auth_failed_logins_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High rate of failed logins detected"
          
      - alert: SuspiciousLoginPattern
        expr: sum(rate(auth_login_attempts_total{status="success"}[1h])) by (ip) > 50
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Suspicious login pattern from single IP"
```

## Compliance

### GDPR Compliance

```go
// Data export (Right to Data Portability)
func (s *AuthService) ExportUserData(ctx context.Context, userID string) (*UserDataExport, error) {
    user, _ := s.userRepo.FindByID(ctx, userID)
    oauthAccounts, _ := s.oauthRepo.FindByUserID(ctx, userID)
    auditLogs, _ := s.auditRepo.FindByUserID(ctx, userID)
    
    return &UserDataExport{
        User:          user,
        OAuthAccounts: oauthAccounts,
        AuditLogs:     auditLogs,
        ExportedAt:    time.Now(),
    }, nil
}

// Data deletion (Right to be Forgotten)
func (s *AuthService) DeleteUserData(ctx context.Context, userID string) error {
    // Delete user account
    s.userRepo.Delete(ctx, userID)
    
    // Delete OAuth accounts
    s.oauthRepo.DeleteByUserID(ctx, userID)
    
    // Revoke all tokens
    s.tokenRepo.RevokeAllByUserID(ctx, userID)
    
    // Anonymize audit logs (keep for compliance)
    s.auditRepo.AnonymizeByUserID(ctx, userID)
    
    // Delete sessions
    s.redis.Delete(ctx, fmt.Sprintf("session:%s*", userID))
    
    return nil
}
```

### PCI DSS Compliance

If handling payment information:
- Never store full credit card numbers
- Use tokenization for payment data
- Implement strong access control
- Regular security audits
- Penetration testing

### SOC 2 Compliance

- Document security policies
- Implement change management
- Regular vulnerability scanning
- Incident response plan
- Employee security training

## Security Checklist

### Pre-Production

- [ ] All secrets stored in secret manager
- [ ] TLS 1.3 enabled
- [ ] Rate limiting configured
- [ ] CSRF protection enabled
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention
- [ ] XSS protection
- [ ] Security headers configured
- [ ] Strong password policy enforced
- [ ] 2FA available for all users
- [ ] Account lockout policy configured
- [ ] JWT secrets rotated
- [ ] Database encryption enabled
- [ ] Backup encryption enabled
- [ ] Security event logging enabled
- [ ] Monitoring and alerts configured

### Regular Maintenance

- [ ] Review audit logs weekly
- [ ] Update dependencies monthly
- [ ] Rotate secrets quarterly
- [ ] Security audit annually
- [ ] Penetration testing annually
- [ ] Review access controls monthly
- [ ] Update security documentation
- [ ] Employee security training quarterly

### Incident Response

- [ ] Incident response plan documented
- [ ] On-call rotation established
- [ ] Escalation procedures defined
- [ ] Communication templates prepared
- [ ] Post-incident review process
- [ ] Regular incident response drills

## Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Go Security Best Practices](https://github.com/OWASP/Go-SCP)
- [JWT Best Practices](https://tools.ietf.org/html/rfc8725)
