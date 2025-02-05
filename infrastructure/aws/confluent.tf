# Terraform configuration for Confluent Cloud deployment
# Version: 1.0.0

terraform {
  required_providers {
    confluent = {
      source  = "confluentinc/confluent-cloud"
      version = "~> 1.0"  # v1.0 for stable enterprise features
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # v5.0 for latest security features
    }
  }
}

# Data sources for VPC and subnet information
data "aws_vpc" "main" {
  id = var.vpc_id
}

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }
  filter {
    name   = "tag:NetworkType"
    values = ["Private"]
  }
}

# Confluent Cloud Environment
resource "confluent_environment" "main" {
  name           = "blackpoint-security-${var.environment}"
  display_name   = "BlackPoint Security ${var.environment}"

  tags = {
    Environment         = var.environment
    ManagedBy          = "terraform"
    SecurityCompliance = "soc2"
    DataClassification = "sensitive"
    BusinessUnit       = "security"
  }
}

# Dedicated Kafka Cluster with enhanced security
resource "confluent_kafka_cluster" "main" {
  display_name = "blackpoint-security-kafka-${var.environment}"
  availability = "MULTI_ZONE"
  cloud        = "AWS"
  region       = var.aws_region
  
  dedicated {
    cku = 2  # 2 Confluent Kafka Units for production workload
  }

  environment {
    id = confluent_environment.main.id
  }

  network {
    vpc_id           = data.aws_vpc.main.id
    private_subnets  = data.aws_subnets.private.ids
    security_group_rules = [
      {
        type        = "ingress"
        from_port   = 9092
        to_port     = 9092
        protocol    = "tcp"
        cidr_blocks = [data.aws_vpc.main.cidr_block]
      }
    ]
  }

  config {
    auto.create.topics.enable    = "false"  # Disable auto topic creation for security
    default.replication.factor   = "3"      # Triple replication for HA
    min.insync.replicas         = "2"      # Ensure data durability
    num.io.threads              = "8"      # Optimized for performance
    num.network.threads         = "8"      # Optimized for throughput
    num.partitions              = "12"     # Default partitions for scalability
  }
}

# Kafka topics with optimized configurations per tier
resource "confluent_kafka_topic" "topics" {
  for_each = {
    bronze_events = {
      partitions      = 12
      retention_ms    = 2592000000  # 30 days
      cleanup_policy  = "delete"
      replication_factor = 3
    }
    silver_events = {
      partitions      = 12
      retention_ms    = 7776000000  # 90 days
      cleanup_policy  = "compact,delete"
      replication_factor = 3
    }
    gold_events = {
      partitions      = 6
      retention_ms    = 31536000000  # 365 days
      cleanup_policy  = "compact"
      replication_factor = 3
    }
  }

  topic_name     = "blackpoint-${each.key}"
  partitions_count = each.value.partitions
  rest_endpoint  = confluent_kafka_cluster.main.rest_endpoint

  config = {
    "cleanup.policy"                = each.value.cleanup_policy
    "retention.ms"                  = each.value.retention_ms
    "min.insync.replicas"          = "2"
    "replication.factor"           = each.value.replication_factor
    "unclean.leader.election.enable" = "false"  # Ensure data consistency
    "compression.type"             = "lz4"      # Optimize network bandwidth
  }
}

# Service accounts with granular permissions
resource "confluent_service_account" "accounts" {
  for_each = {
    collector = {
      description = "Event Collector service account"
      roles      = ["DeveloperWrite"]
    }
    processor = {
      description = "Event Processor service account"
      roles      = ["DeveloperRead", "DeveloperWrite"]
    }
    analyzer = {
      description = "Security Analyzer service account"
      roles      = ["DeveloperRead"]
    }
  }

  display_name = "blackpoint-${each.key}-${var.environment}"
  description  = each.value.description
}

# Outputs for application configuration
output "kafka_cluster_id" {
  description = "Kafka cluster ID for application configuration"
  value       = confluent_kafka_cluster.main.id
  sensitive   = true
}

output "kafka_bootstrap_endpoint" {
  description = "Kafka bootstrap server endpoint"
  value       = confluent_kafka_cluster.main.bootstrap_endpoint
  sensitive   = true
}

output "service_account_credentials" {
  description = "Service account credentials"
  value = {
    for k, v in confluent_service_account.accounts : k => {
      id          = v.id
      api_key     = v.api_key
      api_secret  = v.api_secret
    }
  }
  sensitive = true
}