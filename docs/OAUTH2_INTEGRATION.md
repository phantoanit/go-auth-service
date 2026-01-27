# OAuth2 Integration Guide

This guide explains how to integrate OAuth2 authentication with the Auth Service.

## Table of Contents

- [Overview](#overview)
- [Supported Providers](#supported-providers)
- [Configuration](#configuration)
- [Implementation Steps](#implementation-steps)
- [Code Examples](#code-examples)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

The Auth Service supports OAuth2 authentication through popular identity providers. Users can:
- Sign in with existing accounts (Google, GitHub, etc.)
- Link multiple OAuth accounts to one user profile
- Access the application without creating separate credentials

**OAuth2 Flow**: Authorization Code Flow with PKCE (recommended for enhanced security)

## Supported Providers

### Currently Supported
- ✅ **Google** - Gmail and Google Workspace accounts
- ✅ **GitHub** - GitHub personal and organization accounts

### Coming Soon
- 🔜 Microsoft (Azure AD, Office 365)
- 🔜 Facebook
- 🔜 Twitter/X
- 🔜 LinkedIn
- 🔜 Custom OIDC providers

## Configuration

### Environment Variables

Add the following to your `.env` file:

```bash
# Google OAuth2
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URL=https://your-domain.com/api/v1/auth/oauth/google/callback

# GitHub OAuth2
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URL=https://your-domain.com/api/v1/auth/oauth/github/callback

# OAuth2 Settings
OAUTH_STATE_TTL=600  # State token TTL in seconds (10 minutes)
OAUTH_ENABLE_ACCOUNT_LINKING=true  # Allow linking OAuth accounts to existing users
```

### Provider Setup

#### Google OAuth2 Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client ID"
5. Configure OAuth consent screen
6. Add authorized redirect URIs:
   - `http://localhost:8081/api/v1/auth/oauth/google/callback` (development)
   - `https://your-domain.com/api/v1/auth/oauth/google/callback` (production)
7. Copy Client ID and Client Secret

**Scopes requested:**
- `openid` - OpenID Connect
- `profile` - User profile information
- `email` - Email address

#### GitHub OAuth2 Setup

1. Go to [GitHub Settings → Developer settings → OAuth Apps](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in application details:
   - **Application name**: Your App Name
   - **Homepage URL**: https://your-domain.com
   - **Authorization callback URL**: https://your-domain.com/api/v1/auth/oauth/github/callback
4. Click "Register application"
5. Copy Client ID and generate Client Secret

**Scopes requested:**
- `user:email` - User email address (required)
- `read:user` - User profile information

## Implementation Steps

### 1. Frontend Integration

#### Initiate OAuth Flow

```javascript
// React/Next.js example
const handleGoogleLogin = () => {
  // Generate and store state token for CSRF protection
  const state = generateRandomString(32);
  sessionStorage.setItem('oauth_state', state);
  
  // Redirect to auth service OAuth endpoint
  const params = new URLSearchParams({
    provider: 'google',
    state: state,
    redirect_uri: window.location.origin + '/auth/callback'
  });
  
  window.location.href = `${API_URL}/api/v1/auth/oauth/google?${params}`;
};

const handleGitHubLogin = () => {
  const state = generateRandomString(32);
  sessionStorage.setItem('oauth_state', state);
  
  const params = new URLSearchParams({
    provider: 'github',
    state: state,
    redirect_uri: window.location.origin + '/auth/callback'
  });
  
  window.location.href = `${API_URL}/api/v1/auth/oauth/github?${params}`;
};
```

#### Handle OAuth Callback

```javascript
// Handle callback on /auth/callback page
import { useEffect } from 'react';
import { useRouter } from 'next/router';

function AuthCallback() {
  const router = useRouter();
  
  useEffect(() => {
    const handleCallback = async () => {
      const { code, state, error } = router.query;
      
      // Check for OAuth errors
      if (error) {
        console.error('OAuth error:', error);
        router.push('/login?error=oauth_failed');
        return;
      }
      
      // Verify state token (CSRF protection)
      const savedState = sessionStorage.getItem('oauth_state');
      if (state !== savedState) {
        console.error('State mismatch - possible CSRF attack');
        router.push('/login?error=csrf');
        return;
      }
      
      // Exchange code for tokens
      try {
        const response = await fetch(`${API_URL}/api/v1/auth/oauth/callback`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code, state, provider: 'google' })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          // Store tokens
          localStorage.setItem('access_token', data.access_token);
          localStorage.setItem('refresh_token', data.refresh_token);
          
          // Clear state
          sessionStorage.removeItem('oauth_state');
          
          // Redirect to dashboard
          router.push('/dashboard');
        } else {
          throw new Error(data.error || 'Authentication failed');
        }
      } catch (error) {
        console.error('Callback error:', error);
        router.push('/login?error=auth_failed');
      }
    };
    
    if (router.isReady) {
      handleCallback();
    }
  }, [router]);
  
  return <div>Authenticating...</div>;
}
```

### 2. Backend Integration

#### API Endpoints

**Start OAuth Flow**
```bash
GET /api/v1/auth/oauth/{provider}?state={state}&redirect_uri={redirect_uri}
```

**Handle OAuth Callback**
```bash
POST /api/v1/auth/oauth/callback
Content-Type: application/json

{
  "code": "authorization_code_from_provider",
  "state": "csrf_protection_state",
  "provider": "google"
}
```

**Link OAuth Account (Authenticated User)**
```bash
POST /api/v1/auth/oauth/link
Authorization: Bearer {access_token}
Content-Type: application/json

{
  "code": "authorization_code_from_provider",
  "provider": "github"
}
```

**Unlink OAuth Account**
```bash
DELETE /api/v1/auth/oauth/unlink/{provider}
Authorization: Bearer {access_token}
```

## Code Examples

### Go Client Library

```go
package main

import (
    "context"
    "fmt"
    "github.com/vhvplatform/go-auth-service/client"
)

func main() {
    // Initialize auth client
    authClient := client.NewAuthClient("http://localhost:8081")
    
    // Start OAuth flow
    authURL, state, err := authClient.GetOAuthURL("google", "http://localhost:3000/callback")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Visit: %s\n", authURL)
    // Redirect user to authURL
    
    // After callback, exchange code for tokens
    var code string // received from callback
    tokens, err := authClient.ExchangeOAuthCode(context.Background(), code, state, "google")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Access Token: %s\n", tokens.AccessToken)
}
```

### Python Client Library

```python
from auth_client import AuthClient

# Initialize client
auth_client = AuthClient(base_url="http://localhost:8081")

# Start OAuth flow
auth_url, state = auth_client.get_oauth_url(
    provider="google",
    redirect_uri="http://localhost:3000/callback"
)

print(f"Visit: {auth_url}")
# Redirect user to auth_url

# After callback, exchange code
code = "code_from_callback"  # received from callback
tokens = auth_client.exchange_oauth_code(
    code=code,
    state=state,
    provider="google"
)

print(f"Access Token: {tokens['access_token']}")
```

### cURL Examples

```bash
# 1. Start OAuth flow (GET in browser)
curl "http://localhost:8081/api/v1/auth/oauth/google?state=random_state_123&redirect_uri=http://localhost:3000/callback"

# 2. Exchange code for tokens (after callback)
curl -X POST http://localhost:8081/api/v1/auth/oauth/callback \
  -H "Content-Type: application/json" \
  -d '{
    "code": "authorization_code_from_google",
    "state": "random_state_123",
    "provider": "google"
  }'

# 3. Link OAuth account to existing user
curl -X POST http://localhost:8081/api/v1/auth/oauth/link \
  -H "Authorization: Bearer your_access_token" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "authorization_code_from_github",
    "provider": "github"
  }'
```

## Testing

### Unit Testing

```go
func TestOAuthGoogleCallback(t *testing.T) {
    // Mock OAuth provider
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "access_token": "mock_access_token",
            "id_token": "mock_id_token",
        })
    }))
    defer mockServer.Close()
    
    // Test OAuth callback
    req := &OAuthCallbackRequest{
        Code: "test_code",
        State: "test_state",
        Provider: "google",
    }
    
    tokens, err := authService.HandleOAuthCallback(context.Background(), req)
    assert.NoError(t, err)
    assert.NotEmpty(t, tokens.AccessToken)
}
```

### Integration Testing

```bash
# 1. Set test credentials
export GOOGLE_CLIENT_ID=test_client_id
export GOOGLE_CLIENT_SECRET=test_secret

# 2. Run integration tests
go test -v ./internal/oauth/... -tags=integration

# 3. Test with real OAuth provider (sandbox)
export TEST_OAUTH_PROVIDER=google_sandbox
go test -v ./test/oauth_integration_test.go
```

## Troubleshooting

### Common Issues

#### 1. "Invalid redirect URI" error

**Problem**: OAuth provider rejects redirect URI

**Solution**:
- Ensure redirect URI in code matches exactly what's configured in provider console
- Include protocol (http/https), port if non-standard
- No trailing slashes unless configured with one

#### 2. "State mismatch" error

**Problem**: CSRF state token doesn't match

**Solution**:
- Check that state is properly stored and retrieved
- Verify session/cookie configuration
- Ensure state generation is cryptographically random

#### 3. User email already exists

**Problem**: OAuth email matches existing user

**Solution**:
- Enable account linking: `OAUTH_ENABLE_ACCOUNT_LINKING=true`
- Prompt user to login and link accounts
- Or require unique emails per provider

#### 4. "Insufficient permissions" error

**Problem**: OAuth token lacks required scopes

**Solution**:
- Review requested scopes in OAuth configuration
- User must grant all required permissions
- Re-authenticate if scopes were changed

### Debug Mode

Enable debug logging:

```bash
export LOG_LEVEL=debug
export OAUTH_DEBUG=true
```

Check logs for detailed OAuth flow information:

```bash
tail -f logs/auth-service.log | grep oauth
```

### Testing OAuth Locally

Use ngrok to expose local server for OAuth callbacks:

```bash
# Install ngrok
brew install ngrok

# Start tunnel
ngrok http 8081

# Use ngrok URL as redirect URI
# Example: https://abc123.ngrok.io/api/v1/auth/oauth/google/callback
```

## Security Best Practices

1. **Always use HTTPS in production**
2. **Validate state tokens** to prevent CSRF attacks
3. **Use PKCE** for additional security (Authorization Code Flow with PKCE)
4. **Store OAuth tokens encrypted** in database
5. **Implement token refresh** before expiration
6. **Log OAuth events** for audit trails
7. **Rate limit OAuth endpoints** to prevent abuse
8. **Validate email from OAuth provider** before auto-account creation
9. **Allow users to unlink** OAuth accounts
10. **Notify users** when OAuth accounts are linked/unlinked

## References

- [OAuth 2.0 RFC 6749](https://tools.ietf.org/html/rfc6749)
- [Google OAuth2 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [GitHub OAuth Documentation](https://docs.github.com/en/developers/apps/building-oauth-apps)
- [OWASP OAuth Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
