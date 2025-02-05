# BlackPoint CLI Command Reference

## Overview

The BlackPoint Security Integration Framework CLI provides a comprehensive set of commands for managing security platform integrations, data collection, monitoring, and system configuration with enterprise-grade security controls.

### Installation Prerequisites

- Operating System: Linux, macOS, Windows
- Required Permissions: Administrative access for installation
- Security Requirements: TLS 1.3, valid SSL certificates
- Authentication: OAuth2.0 credentials or API key

### Global Security Controls

- All commands require authentication
- TLS 1.3 encryption for all API communication
- Rate limiting: 1000 requests/minute per client
- Audit logging of all operations
- Token-based session management

## Command Structure

```bash
blackpoint-cli <command> [subcommand] [options]

Global Options:
  --config string        Config file (default "~/.blackpoint/config.yaml")
  --log-level string    Set logging level (default "info")
  --output string       Output format (json|yaml|table) (default "json")
  --security-mode       Enable enhanced security controls
  --version            Display version information
```

## Command Groups

### Authentication Commands

```bash
# Authenticate with the platform
blackpoint-cli auth login [--mfa] [--token-lifetime]

# Terminate active session
blackpoint-cli auth logout

# View authentication status
blackpoint-cli auth status

# Manage authentication tokens
blackpoint-cli auth token [list|revoke]

# View authentication audit log
blackpoint-cli auth audit [--timerange] [--export]
```

### Integration Management

```bash
# Create new integration
blackpoint-cli integrate new \
  --platform string     # Platform type
  --config string      # Configuration file
  --validate          # Validate configuration
  --security-scan     # Perform security scan

# List integrations
blackpoint-cli integrate list [--status] [--format]

# Update integration
blackpoint-cli integrate update \
  --id string         # Integration ID
  --config string    # Updated configuration

# Delete integration
blackpoint-cli integrate delete --id string [--force]
```

### Data Collection

```bash
# Start data collection
blackpoint-cli collect start \
  --integration string  # Integration ID
  --batch-size int    # Batch size (default 1000)
  --encryption        # Enable field encryption

# Stop data collection
blackpoint-cli collect stop --integration string

# View collection status
blackpoint-cli collect status \
  --integration string
  --metrics          # Show performance metrics
```

### System Configuration

```bash
# Configure system settings
blackpoint-cli configure set \
  --key string       # Configuration key
  --value string    # Configuration value
  --encrypt        # Encrypt sensitive values

# View configuration
blackpoint-cli configure view [--decrypt]

# Validate configuration
blackpoint-cli configure validate
```

### System Monitoring

```bash
# Check system status
blackpoint-cli monitor status \
  --component string  # Filter by component
  --format string    # Output format
  --threshold float  # Alert threshold

# View system alerts
blackpoint-cli monitor alerts \
  --severity string  # Alert severity
  --timerange string # Time range
```

## Security Considerations

### Authentication Security

- Supports Multi-Factor Authentication (MFA)
- Maximum token lifetime: 24 hours
- Automatic session termination on inactivity
- Secure credential storage using system keychain

### Data Security

- TLS 1.3 encryption for all communication
- Field-level encryption for sensitive data
- Secure configuration storage (0600 permissions)
- Encrypted audit logging

### Access Control

- Role-Based Access Control (RBAC)
- Least privilege principle enforcement
- Resource-level permissions
- Action audit logging

## Output Formats

### Success Output

```json
{
  "status": "success",
  "timestamp": "2024-01-20T10:00:00Z",
  "data": {
    "id": "integration-123",
    "status": "active",
    "metrics": {
      "events_processed": 1000,
      "processing_time": "2.5s"
    }
  }
}
```

### Error Output

```json
{
  "status": "error",
  "timestamp": "2024-01-20T10:00:00Z",
  "error": {
    "code": "E1001",
    "message": "Invalid configuration provided",
    "details": "Missing required field: api_key"
  }
}
```

## Rate Limiting

| Command Group | Rate Limit | Burst Limit |
|--------------|------------|-------------|
| Authentication | 100/hour | 10 |
| Integration | 1000/minute | 100 |
| Collection | 5000/minute | 500 |
| Configuration | 100/minute | 10 |
| Monitoring | 1000/minute | 100 |

## Troubleshooting

### Common Error Codes

| Code | Description | Resolution |
|------|-------------|------------|
| E1001 | Invalid configuration | Verify configuration format and required fields |
| E1002 | Authentication failed | Check credentials and MFA settings |
| E1003 | Connection failed | Verify network connectivity and TLS certificates |
| E1004 | Validation failed | Review input parameters against requirements |
| E1005 | Operation timeout | Check system resources and retry operation |

### Security Validation

1. Verify TLS certificate validity
2. Confirm authentication token status
3. Check RBAC permissions
4. Validate encryption settings
5. Review audit logs for issues

## Compliance

- SOC 2 Type II compliant
- ISO 27001 certified
- GDPR compliant
- PCI DSS compliant

## Version Information

- CLI Version: 1.0.0
- API Version: v1
- Documentation Last Updated: 2024-01-20