# BlackPoint Security Integration Framework - Backend Services

## Overview

The BlackPoint Security Integration Framework is a scalable data ingestion and processing system designed to accelerate the integration of third-party security platforms into BlackPoint's security monitoring ecosystem. The system implements a three-tier data architecture (Bronze, Silver, Gold) deployed on Kubernetes with Confluent streaming and ChaosSearch storage.

### Key Features

- High-performance event collection and processing
- Three-tier data architecture for security event processing
- Enterprise-grade security controls and compliance features
- Kubernetes-native deployment with high availability
- Real-time streaming with Confluent Kafka
- Scalable storage with ChaosSearch

### Performance Characteristics

- Processing Latency: Bronze <1s, Silver <5s, Gold <30s
- Throughput: >1000 events/second per client
- Client Scalability: 100+ concurrent clients
- Integration Development: 2 weeks per integration
- Accuracy: ≥80% compared to manual integration

## Prerequisites

- Go 1.21+
- Docker 24.0.0+
- Kubernetes 1.25+
- Confluent Platform 7.0+
- AWS Account with required services:
  - EKS
  - ECR
  - KMS
  - S3
  - ChaosSearch

## Architecture

### Three-Tier Processing

1. **Bronze Tier (Raw Data)**
   - Event collection and validation
   - Raw data preservation
   - Initial security checks

2. **Silver Tier (Normalized Data)**
   - Event normalization
   - Field transformation
   - Security context enrichment

3. **Gold Tier (Intelligence)**
   - Threat detection
   - Event correlation
   - Alert generation

### Security Features

- OAuth2/OIDC Authentication
- Role-Based Access Control (RBAC)
- Field-level encryption
- Audit logging
- Compliance monitoring
- TLS 1.3 enforcement

## Development Setup

1. **Clone Repository**
   ```bash
   git clone https://github.com/blackpoint/backend
   cd backend
   ```

2. **Install Dependencies**
   ```bash
   go mod download
   ```

3. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Build Services**
   ```bash
   make build
   ```

5. **Run Tests**
   ```bash
   make test
   ```

## Deployment

### Local Development

```bash
# Start local development environment
make dev

# Run specific component
make run-collector
make run-normalizer
make run-analyzer
```

### Production Deployment

```bash
# Build production images
make build

# Run security scans
make scan

# Deploy to Kubernetes
make deploy
```

### Kubernetes Configuration

- Namespace: blackpoint-system
- Components:
  - Collector (Bronze Tier)
  - Normalizer (Silver Tier)
  - Analyzer (Gold Tier)
- High Availability:
  - Multi-AZ deployment
  - Pod anti-affinity rules
  - Resource limits and requests

## Integration Development

1. **Create Integration Configuration**
   ```yaml
   # config/integrations/example.yaml
   platform_type: "example"
   collection:
     mode: "realtime"
     batch_size: 1000
   validation:
     schema_validation: true
     strict_mode: true
   ```

2. **Implement Collection Logic**
   ```go
   // internal/collector/platforms/example.go
   package platforms

   type ExampleCollector struct {
       // Implementation
   }
   ```

3. **Configure Normalization**
   ```yaml
   # config/normalizer/mappings/example.yaml
   field_mappings:
     source_field: "target_field"
   ```

4. **Deploy Integration**
   ```bash
   make deploy-integration INTEGRATION=example
   ```

## Monitoring

### Metrics

- Prometheus endpoints: /metrics
- Default port: 9090
- Key metrics:
  - Event processing latency
  - Throughput rates
  - Error rates
  - Resource utilization

### Health Checks

- Liveness: /health
- Readiness: /ready
- Startup: /startup

## Security Configuration

### TLS Configuration

```yaml
tls:
  enabled: true
  min_version: "1.3"
  cert_path: "/etc/blackpoint/certs/tls.crt"
  key_path: "/etc/blackpoint/certs/tls.key"
```

### Authentication

```yaml
auth:
  type: "oauth2"
  issuer: "https://auth.blackpoint.io"
  audience: "blackpoint-api"
```

### Encryption

```yaml
encryption:
  provider: "aws-kms"
  key_id: "alias/blackpoint-encryption"
  algorithm: "AES-256-GCM"
```

## Documentation

- API Documentation: /docs/api
- Integration Guide: /docs/integration
- Security Guide: /docs/security
- Operations Guide: /docs/operations

## Support

For support and issues:
- GitHub Issues: [github.com/blackpoint/backend/issues](https://github.com/blackpoint/backend/issues)
- Security Issues: security@blackpoint.io

## License

Copyright (c) 2024 BlackPoint Security. All rights reserved.