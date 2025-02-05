# BlackPoint CLI Authentication Documentation

## Overview

The BlackPoint CLI implements enterprise-grade authentication and security controls to ensure secure access to the BlackPoint Security Integration Framework. This documentation covers authentication methods, configuration, security best practices, and troubleshooting.

### Security Prerequisites

- TLS 1.3 required for all API communication
- API keys must be at least 32 characters with mixed case, numbers, and special characters
- Multi-factor authentication (MFA) support
- Maximum token lifetime of 24 hours
- Secure credential storage using system keychain

### Compliance Requirements

- SOC 2 Type II compliant
- GDPR compliant
- ISO 27001 certified
- PCI DSS compliant

## Authentication Methods

### OAuth 2.0 + JWT Authentication

```bash
# Authenticate with OAuth 2.0
blackpoint-cli auth login [--mfa] [--token-lifetime=8h]

# Parameters:
--mfa               Enable multi-factor authentication
--token-lifetime    Token validity duration (15m-24h)
```

#### Security Controls
- Enforces TLS 1.3 for all communication
- Supports OIDC for identity verification
- Implements PKCE flow for enhanced security
- Automatic token refresh before expiration
- Session termination on security policy violations

### API Key Authentication

```bash
# Configure API key authentication
blackpoint-cli auth configure --api-key <key>

# Requirements:
- Minimum length: 32 characters
- Must contain: uppercase, lowercase, numbers, special characters
- Rotation required every 90 days
- Secure storage in system keychain
```

### Token Management

```bash
# View active tokens
blackpoint-cli auth token list

# Revoke specific token
blackpoint-cli auth token revoke <token-id>

# Revoke all tokens
blackpoint-cli auth token revoke --all
```

## Configuration

### Authentication Configuration Structure

```yaml
auth:
  # Required: API key for authentication
  apiKey: "${BP_API_KEY}"  # Use environment variable
  
  # Optional: Token storage location
  tokenPath: "/secure/path/tokens"
  
  # Optional: Maximum token lifetime (15m-24h)
  maxLifetime: "8h"
  
  # Optional: MFA configuration
  mfa:
    enabled: true
    method: "totp"
```

### Environment Variables

```bash
# Required environment variables
BP_API_KEY          # API key for authentication
BP_MFA_SECRET       # MFA secret (if enabled)

# Optional environment variables
BP_TOKEN_PATH       # Custom token storage path
BP_AUTH_TIMEOUT     # Authentication timeout
```

### Security Validation Rules

1. API Key Validation
   - Minimum length: 32 characters
   - Must contain: uppercase, lowercase, numbers, special characters
   - Cannot contain: sequential patterns, common words
   - Must be rotated every 90 days

2. Token Validation
   - Maximum lifetime: 24 hours
   - Automatic expiration on security policy violation
   - Revocation on suspicious activity
   - Rate limiting: 100 auth requests per hour

3. Storage Security
   - Secure storage using system keychain
   - File permissions: 0600 (owner read/write only)
   - Encryption at rest for sensitive data
   - Secure memory handling

## Commands

### Login Command

```bash
# Standard login
blackpoint-cli auth login

# Login with MFA
blackpoint-cli auth login --mfa

# Login with custom token lifetime
blackpoint-cli auth login --token-lifetime=8h

# Login with specific API key
blackpoint-cli auth login --api-key=${BP_API_KEY}
```

### Logout Command

```bash
# Logout current session
blackpoint-cli auth logout

# Force logout all sessions
blackpoint-cli auth logout --all

# Revoke and logout
blackpoint-cli auth logout --revoke
```

### Token Management Commands

```bash
# List active tokens
blackpoint-cli auth token list

# Get token details
blackpoint-cli auth token info <token-id>

# Revoke specific token
blackpoint-cli auth token revoke <token-id>

# Revoke all tokens
blackpoint-cli auth token revoke --all
```

## Error Handling

### Authentication Errors

| Error Code | Description | Resolution |
|------------|-------------|------------|
| E1001 | Invalid configuration | Verify auth configuration format and values |
| E1002 | Authentication failed | Check credentials and MFA settings |
| E1003 | Connection failed | Verify network and TLS configuration |
| E1004 | Validation failed | Review input against security requirements |
| E1005 | Operation timeout | Adjust timeout settings or retry |

### Security Incidents

1. Multiple Failed Attempts
   ```bash
   Error: [E1002] Authentication failed: too many attempts
   Resolution: Wait 15 minutes before retrying
   ```

2. Invalid Token
   ```bash
   Error: [E1002] Invalid or expired token
   Resolution: Re-authenticate with valid credentials
   ```

3. MFA Failure
   ```bash
   Error: [E1002] MFA verification failed
   Resolution: Verify MFA code and try again
   ```

## Examples

### Secure Initial Setup

```bash
# 1. Set secure API key
export BP_API_KEY="your-secure-api-key"

# 2. Configure authentication
blackpoint-cli auth configure \
  --api-key=${BP_API_KEY} \
  --token-path=/secure/path/tokens \
  --mfa=true

# 3. Perform initial login
blackpoint-cli auth login --mfa
```

### Token Refresh Workflow

```bash
# 1. Check token status
blackpoint-cli auth token status

# 2. Refresh if needed
blackpoint-cli auth token refresh

# 3. Verify new token
blackpoint-cli auth token info
```

### Security Compliance Example

```bash
# 1. Enable audit logging
blackpoint-cli configure set \
  --key=logging.audit \
  --value=true

# 2. Configure secure defaults
blackpoint-cli auth configure \
  --max-lifetime=8h \
  --mfa=required \
  --secure-storage=true

# 3. Verify security settings
blackpoint-cli auth security-check
```

### Error Resolution Examples

```bash
# 1. Handle expired token
blackpoint-cli auth login --renew

# 2. Reset after security incident
blackpoint-cli auth reset \
  --revoke-all \
  --mfa-reset

# 3. Verify security status
blackpoint-cli auth security-status
```