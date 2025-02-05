# AWS Provider configuration with version constraint
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Bronze tier KMS key for sensitive data encryption
resource "aws_kms_key" "bronze_tier" {
  deletion_window_in_days    = 30
  description               = "KMS key for Bronze tier data encryption with automatic rotation"
  enable_key_rotation       = true
  is_enabled               = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name               = "blackpoint-bronze-key"
    Environment        = var.environment
    Project           = var.project_name
    Tier              = "bronze"
    ComplianceScope   = "SOC2,GDPR,ISO27001,PCIDSS"
    AutoRotation      = "enabled"
    DataClassification = "sensitive"
    ManagedBy         = "terraform"
  }
}

# Silver tier KMS key for sensitive data encryption
resource "aws_kms_key" "silver_tier" {
  deletion_window_in_days    = 30
  description               = "KMS key for Silver tier data encryption with automatic rotation"
  enable_key_rotation       = true
  is_enabled               = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name               = "blackpoint-silver-key"
    Environment        = var.environment
    Project           = var.project_name
    Tier              = "silver"
    ComplianceScope   = "SOC2,GDPR,ISO27001,PCIDSS"
    AutoRotation      = "enabled"
    DataClassification = "sensitive"
    ManagedBy         = "terraform"
  }
}

# Gold tier KMS key for critical data encryption
resource "aws_kms_key" "gold_tier" {
  deletion_window_in_days    = 30
  description               = "KMS key for Gold tier data encryption with automatic rotation"
  enable_key_rotation       = true
  is_enabled               = true
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  multi_region             = false

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      }
    ]
  })

  tags = {
    Name               = "blackpoint-gold-key"
    Environment        = var.environment
    Project           = var.project_name
    Tier              = "gold"
    ComplianceScope   = "SOC2,GDPR,ISO27001,PCIDSS"
    AutoRotation      = "enabled"
    DataClassification = "critical"
    ManagedBy         = "terraform"
  }
}

# KMS key aliases for easier reference
resource "aws_kms_alias" "bronze_tier" {
  name          = "alias/${var.project_name}-bronze-${var.environment}"
  target_key_id = aws_kms_key.bronze_tier.key_id
}

resource "aws_kms_alias" "silver_tier" {
  name          = "alias/${var.project_name}-silver-${var.environment}"
  target_key_id = aws_kms_key.silver_tier.key_id
}

resource "aws_kms_alias" "gold_tier" {
  name          = "alias/${var.project_name}-gold-${var.environment}"
  target_key_id = aws_kms_key.gold_tier.key_id
}

# Data source for current AWS account ID
data "aws_caller_identity" "current" {}

# Outputs for key IDs to be used by other modules
output "bronze_key_id" {
  description = "KMS key ID for Bronze tier encryption"
  value       = aws_kms_key.bronze_tier.key_id
}

output "silver_key_id" {
  description = "KMS key ID for Silver tier encryption"
  value       = aws_kms_key.silver_tier.key_id
}

output "gold_key_id" {
  description = "KMS key ID for Gold tier encryption"
  value       = aws_kms_key.gold_tier.key_id
}