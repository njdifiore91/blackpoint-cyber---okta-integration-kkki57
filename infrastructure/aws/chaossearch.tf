# Configure Terraform version and required providers
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws" # v5.0
      version = "~> 5.0"
    }
  }
}

# ChaosSearch instance configuration with enhanced security and performance settings
resource "aws_chaossearch_instance" "blackpoint" {
  name         = "${var.project_name}-${var.environment}"
  storage_size = var.chaossearch_storage_size

  # Configure source S3 buckets for data tiers
  source_buckets = [
    aws_s3_bucket.bronze_tier.id,
    aws_s3_bucket.silver_tier.id,
    aws_s3_bucket.gold_tier.id
  ]

  # Enhanced encryption configuration
  encryption_config {
    kms_key_id           = var.kms_key_id
    encryption_at_rest   = true
    encryption_in_transit = true
  }

  # Tier-specific data retention policies
  retention_config {
    bronze_tier = "30d"  # 30 days retention for raw data
    silver_tier = "90d"  # 90 days retention for normalized data
    gold_tier   = "365d" # 365 days retention for intelligence data
  }

  # Performance optimization settings
  performance_config {
    query_concurrency = 50  # Maximum concurrent queries
    index_concurrency = 25  # Maximum concurrent indexing operations
    max_query_size    = "10GB"
  }

  # Monitoring and logging configuration
  monitoring_config {
    metrics_export = true
    logging_level  = "INFO"
    audit_logging  = true
  }

  tags = {
    Environment      = var.environment
    Project         = var.project_name
    ManagedBy       = "terraform"
    SecurityTier    = "critical"
    ComplianceScope = "sox-pci-gdpr"
  }
}

# Bronze tier index configuration for raw security events
resource "aws_chaossearch_index" "bronze_index" {
  name          = "bronze-events"
  source_bucket = aws_s3_bucket.bronze_tier.id
  pattern       = "*.json"
  retention_days = 30

  index_settings {
    shards            = 3
    replicas         = 2
    refresh_interval = "5s"
    max_result_window = 10000

    analysis {
      analyzer        = "security_event_analyzer"
      search_analyzer = "standard"
    }
  }

  field_mappings {
    timestamp = {
      type = "date"
    }
    event_type = {
      type = "keyword"
    }
    source_ip = {
      type = "ip"
    }
    payload = {
      type = "object"
    }
  }
}

# Silver tier index configuration for normalized events
resource "aws_chaossearch_index" "silver_index" {
  name          = "silver-events"
  source_bucket = aws_s3_bucket.silver_tier.id
  pattern       = "*.json"
  retention_days = 90

  index_settings {
    shards            = 3
    replicas         = 2
    refresh_interval = "10s"
    max_result_window = 15000

    analysis {
      analyzer        = "security_correlation_analyzer"
      search_analyzer = "standard"
    }
  }
}

# Gold tier index configuration for security intelligence
resource "aws_chaossearch_index" "gold_index" {
  name          = "gold-events"
  source_bucket = aws_s3_bucket.gold_tier.id
  pattern       = "*.json"
  retention_days = 365

  index_settings {
    shards            = 3
    replicas         = 2
    refresh_interval = "30s"
    max_result_window = 20000

    analysis {
      analyzer        = "intelligence_analyzer"
      search_analyzer = "standard"
    }
  }
}

# Export ChaosSearch endpoint and API key for application configuration
output "chaossearch_endpoint" {
  description = "ChaosSearch service endpoint"
  value       = aws_chaossearch_instance.blackpoint.endpoint
  sensitive   = true
}

output "chaossearch_api_key" {
  description = "ChaosSearch API key for authentication"
  value       = aws_chaossearch_instance.blackpoint.api_key
  sensitive   = true
}

# Export index names for application configuration
output "chaossearch_indices" {
  description = "ChaosSearch index names for each tier"
  value = {
    bronze_index = aws_chaossearch_index.bronze_index.name
    silver_index = aws_chaossearch_index.silver_index.name
    gold_index   = aws_chaossearch_index.gold_index.name
  }
}