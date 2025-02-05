# BlackPoint CLI Configuration Guide

## Overview

The BlackPoint CLI configuration system provides a secure and flexible way to manage CLI behavior, authentication, logging, and output formatting. This guide covers configuration structure, security considerations, validation rules, and best practices.

## Security Considerations

### Critical Security Requirements

- API keys must be at least 32 characters with mixed case, numbers, and special characters
- All API communication requires HTTPS with TLS 1.2 or higher
- Configuration files are stored with 0600 permissions (owner read/write only)
- Authentication tokens have a maximum lifetime of 24 hours
- Sensitive data is masked in logs and output

### Best Practices

- Rotate API keys every 90 days
- Use environment variables for sensitive values
- Enable audit logging in production environments
- Store configuration files in secure locations
- Validate SSL/TLS certificates

## Configuration Structure

### API Configuration
```yaml
api:
  # Required: HTTPS endpoint for BlackPoint Security API
  endpoint: "https://api.blackpoint.security"
  # Optional: Request timeout (1s-300s, default: 30s)
  timeout: 30s
  # Optional: Number of retry attempts (0-5, default: 3)
  retryAttempts: 3
  # Optional: Delay between retries (100ms-5s, default: 5s)
  retryDelay: 5s
  # Required: API version (format: v1, v2, etc.)
  version: "v1"
```

### Authentication Configuration
```yaml
auth:
  # Required: API key for authentication (min 32 chars)
  apiKey: "YOUR-SECURE-API-KEY"
  # Optional: Path to token storage (absolute path)
  tokenPath: "/secure/path/tokens"
  # Optional: Maximum token lifetime (15m-24h, default: 24h)
  maxLifetime: "24h"
```

### Logging Configuration
```yaml
logging:
  # Optional: Log level (debug, info, warn, error)
  level: "info"
  # Optional: Log format (json, text)
  format: "json"
  # Optional: Log output path (absolute path)
  outputPath: "/var/log/blackpoint/cli.log"
```

### Output Configuration
```yaml
output:
  # Optional: Output format (json, yaml, table, text)
  format: "json"
  # Optional: Enable colored output (default: true)
  colorEnabled: true
  # Optional: Quiet mode - suppress non-essential output
  quiet: false
```

## Default Values

The CLI uses secure defaults defined in `pkg/config/defaults.go`:

| Setting | Default Value | Security Context |
|---------|--------------|------------------|
| API Endpoint | https://api.blackpoint.security | Enforces HTTPS |
| API Timeout | 30 seconds | Prevents hanging connections |
| Retry Attempts | 3 | Balances availability and security |
| Log Level | info | Conservative logging |
| Log Format | json | Structured logging |
| Output Format | json | Consistent parsing |
| Token Lifetime | 24 hours | Limited session duration |

## Validation Rules

### API Configuration Validation
- Endpoint must use HTTPS protocol
- Timeout must be between 1s and 300s
- Retry attempts limited to 0-5
- Retry delay between 100ms and 5s
- API version must match pattern `v\d+`

### Authentication Validation
- API key minimum length: 32 characters
- API key must contain: uppercase, lowercase, numbers, special characters
- Token path must be absolute and directory must exist
- Token lifetime between 15 minutes and 24 hours

### Logging Validation
- Valid log levels: debug, info, warn, error
- Valid formats: json, text
- Output directory must exist and be writable
- File permissions checked for security

### Output Validation
- Valid formats: json, yaml, table, text
- Color output validated against terminal capabilities
- Quiet mode affects non-essential output only

## Examples

### Basic Secure Configuration
```yaml
api:
  endpoint: "https://api.blackpoint.security"
  version: "v1"
auth:
  apiKey: "${BP_API_KEY}"  # Use environment variable
logging:
  level: "info"
  format: "json"
output:
  format: "json"
  colorEnabled: true
```

### Advanced Security Configuration
```yaml
api:
  endpoint: "https://api.blackpoint.security"
  timeout: 10s
  retryAttempts: 3
  retryDelay: 2s
  version: "v1"
auth:
  apiKey: "${BP_API_KEY}"
  tokenPath: "/secure/path/tokens"
  maxLifetime: "8h"
logging:
  level: "info"
  format: "json"
  outputPath: "/var/log/blackpoint/cli.log"
output:
  format: "json"
  colorEnabled: true
  quiet: false
```

## Troubleshooting

### Common Configuration Errors

| Error Code | Description | Resolution |
|------------|-------------|------------|
| E1001 | Invalid configuration | Check configuration format and values |
| E1002 | Authentication failed | Verify API key and permissions |
| E1003 | Connection failed | Check network and endpoint configuration |
| E1004 | Validation failed | Review configuration against requirements |
| E1005 | Operation timeout | Adjust timeout settings or retry |

### Security Warnings

- Never commit API keys to version control
- Avoid storing sensitive data in plain text
- Monitor log files for sensitive information
- Regularly audit configuration permissions
- Keep CLI and dependencies updated