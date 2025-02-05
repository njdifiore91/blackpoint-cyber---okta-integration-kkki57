# AWS Provider configuration for Redis deployment
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Redis subnet group for multi-AZ deployment
resource "aws_elasticache_subnet_group" "redis" {
  name       = "blackpoint-redis-${var.environment}"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name        = "blackpoint-redis-subnet-group"
    Environment = var.environment
    ManagedBy   = "terraform"
    Purpose     = "Redis cluster networking"
  }
}

# Redis parameter group with optimized settings
resource "aws_elasticache_parameter_group" "redis" {
  family      = "redis7.0"
  name        = "blackpoint-redis-params-${var.environment}"
  description = "Redis parameter group for BlackPoint Security"

  # Memory management
  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  # Persistence configuration
  parameter {
    name  = "appendonly"
    value = "yes"
  }

  # Performance optimization
  parameter {
    name  = "activedefrag"
    value = "yes"
  }

  parameter {
    name  = "maxmemory-samples"
    value = "10"
  }

  tags = {
    Name        = "blackpoint-redis-params"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Redis replication group for high availability
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id          = "blackpoint-redis-${var.environment}"
  description                   = "Redis cluster for BlackPoint Security caching"
  node_type                    = "cache.r6g.xlarge"
  num_cache_clusters           = 3
  port                        = 6379
  parameter_group_name         = aws_elasticache_parameter_group.redis.name
  subnet_group_name           = aws_elasticache_subnet_group.redis.name
  security_group_ids          = [aws_security_group.redis.id]
  automatic_failover_enabled  = true
  multi_az_enabled           = true
  engine                     = "redis"
  engine_version             = "7.0"
  at_rest_encryption_enabled = true
  transit_encryption_enabled = true
  auth_token                = random_password.redis_auth_token.result
  
  # Maintenance window during off-peak hours
  maintenance_window = "sun:05:00-sun:09:00"
  snapshot_window   = "03:00-05:00"
  
  # Backup configuration
  snapshot_retention_limit = 7
  
  tags = {
    Name        = "blackpoint-redis-cluster"
    Environment = var.environment
    ManagedBy   = "terraform"
    Purpose     = "Application caching"
  }
}

# Generate secure auth token for Redis
resource "random_password" "redis_auth_token" {
  length  = 32
  special = false
}

# Security group for Redis access
resource "aws_security_group" "redis" {
  name        = "blackpoint-redis-sg-${var.environment}"
  description = "Security group for Redis cluster access"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    cidr_blocks     = [var.vpc_cidr]
    description     = "Redis port access from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "blackpoint-redis-security-group"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Outputs for application configuration
output "redis_endpoint" {
  description = "Primary Redis endpoint for application connection"
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  sensitive   = true
}

output "redis_port" {
  description = "Redis port number for application connection"
  value       = aws_elasticache_replication_group.redis.port
}

output "redis_auth_token" {
  description = "Authentication token for Redis connection"
  value       = random_password.redis_auth_token.result
  sensitive   = true
}