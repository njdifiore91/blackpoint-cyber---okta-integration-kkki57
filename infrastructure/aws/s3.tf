# AWS Provider configuration with version constraint
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Bronze tier S3 bucket for raw security event data
resource "aws_s3_bucket" "bronze" {
  bucket = "${var.project_name}-${var.environment}-bronze-tier"
  
  # Prevent accidental deletion of sensitive data
  force_destroy = false

  tags = {
    Name             = "${var.project_name}-${var.environment}-bronze-tier"
    Environment      = var.environment
    Project          = var.project_name
    Tier             = "bronze"
    SecurityLevel    = "high"
    DataRetention    = "90days"
    ComplianceScope  = "SOC2,GDPR,ISO27001"
    DataClassification = "sensitive"
    ManagedBy        = "terraform"
  }
}

# Silver tier S3 bucket for normalized security event data
resource "aws_s3_bucket" "silver" {
  bucket = "${var.project_name}-${var.environment}-silver-tier"
  force_destroy = false

  tags = {
    Name             = "${var.project_name}-${var.environment}-silver-tier"
    Environment      = var.environment
    Project          = var.project_name
    Tier             = "silver"
    SecurityLevel    = "high"
    DataRetention    = "180days"
    ComplianceScope  = "SOC2,GDPR,ISO27001"
    DataClassification = "sensitive"
    ManagedBy        = "terraform"
  }
}

# Gold tier S3 bucket for security intelligence data
resource "aws_s3_bucket" "gold" {
  bucket = "${var.project_name}-${var.environment}-gold-tier"
  force_destroy = false

  tags = {
    Name             = "${var.project_name}-${var.environment}-gold-tier"
    Environment      = var.environment
    Project          = var.project_name
    Tier             = "gold"
    SecurityLevel    = "critical"
    DataRetention    = "365days"
    ComplianceScope  = "SOC2,GDPR,ISO27001"
    DataClassification = "critical"
    ManagedBy        = "terraform"
  }
}

# Enable versioning for all tiers
resource "aws_s3_bucket_versioning" "bronze" {
  bucket = aws_s3_bucket.bronze.id
  versioning_configuration {
    status = "Enabled"
    mfa_delete = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "silver" {
  bucket = aws_s3_bucket.silver.id
  versioning_configuration {
    status = "Enabled"
    mfa_delete = "Enabled"
  }
}

resource "aws_s3_bucket_versioning" "gold" {
  bucket = aws_s3_bucket.gold.id
  versioning_configuration {
    status = "Enabled"
    mfa_delete = "Enabled"
  }
}

# Configure encryption using KMS keys
resource "aws_s3_bucket_server_side_encryption_configuration" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.bronze_tier.key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "silver" {
  bucket = aws_s3_bucket.silver.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.silver_tier.key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "gold" {
  bucket = aws_s3_bucket.gold.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.gold_tier.key_id
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Configure lifecycle rules for cost optimization
resource "aws_s3_bucket_lifecycle_rule" "bronze" {
  bucket = aws_s3_bucket.bronze.id
  id     = "bronze_tier_lifecycle"
  enabled = true
  prefix = ""

  transition {
    days          = 30
    storage_class = "STANDARD_IA"
  }

  transition {
    days          = 60
    storage_class = "INTELLIGENT_TIERING"
  }

  expiration {
    days = 90
  }

  noncurrent_version_expiration {
    days = 30
  }
}

resource "aws_s3_bucket_lifecycle_rule" "silver" {
  bucket = aws_s3_bucket.silver.id
  id     = "silver_tier_lifecycle"
  enabled = true
  prefix = ""

  transition {
    days          = 60
    storage_class = "STANDARD_IA"
  }

  transition {
    days          = 120
    storage_class = "INTELLIGENT_TIERING"
  }

  expiration {
    days = 180
  }

  noncurrent_version_expiration {
    days = 60
  }
}

resource "aws_s3_bucket_lifecycle_rule" "gold" {
  bucket = aws_s3_bucket.gold.id
  id     = "gold_tier_lifecycle"
  enabled = true
  prefix = ""

  transition {
    days          = 90
    storage_class = "STANDARD_IA"
  }

  transition {
    days          = 180
    storage_class = "INTELLIGENT_TIERING"
  }

  expiration {
    days = 365
  }

  noncurrent_version_expiration {
    days = 90
  }
}

# Block public access for all buckets
resource "aws_s3_bucket_public_access_block" "bronze" {
  bucket = aws_s3_bucket.bronze.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "silver" {
  bucket = aws_s3_bucket.silver.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "gold" {
  bucket = aws_s3_bucket.gold.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Outputs for bucket IDs and ARNs
output "bronze_bucket_id" {
  description = "ID of the Bronze tier S3 bucket"
  value       = aws_s3_bucket.bronze.id
}

output "bronze_bucket_arn" {
  description = "ARN of the Bronze tier S3 bucket"
  value       = aws_s3_bucket.bronze.arn
}

output "silver_bucket_id" {
  description = "ID of the Silver tier S3 bucket"
  value       = aws_s3_bucket.silver.id
}

output "silver_bucket_arn" {
  description = "ARN of the Silver tier S3 bucket"
  value       = aws_s3_bucket.silver.arn
}

output "gold_bucket_id" {
  description = "ID of the Gold tier S3 bucket"
  value       = aws_s3_bucket.gold.id
}

output "gold_bucket_arn" {
  description = "ARN of the Gold tier S3 bucket"
  value       = aws_s3_bucket.gold.arn
}