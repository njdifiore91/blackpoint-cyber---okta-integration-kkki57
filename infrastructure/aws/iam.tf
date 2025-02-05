# AWS Provider configuration with enhanced security features
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws" # v5.0
      version = "~> 5.0"
    }
  }
}

# Get current AWS account ID for security policies
data "aws_caller_identity" "current" {}

# EKS Cluster IAM Role with enhanced security controls
resource "aws_iam_role" "eks_cluster_role" {
  name                 = "${var.project_name}-${var.environment}-eks-cluster-role"
  max_session_duration = 3600 # 1 hour maximum session duration for security

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Environment         = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    SecurityCompliance = "SOC2-ISO27001"
    DataClassification = "Sensitive"
  }
}

# Attach required AWS managed policies to EKS cluster role
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster_role.name
}

# EKS Node Group IAM Role
resource "aws_iam_role" "eks_node_role" {
  name                 = "${var.project_name}-${var.environment}-eks-node-role"
  max_session_duration = 3600

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Environment         = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    SecurityCompliance = "SOC2-ISO27001"
    DataClassification = "Sensitive"
  }
}

# Attach required AWS managed policies to EKS node role
resource "aws_iam_role_policy_attachment" "eks_node_policy" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  ])

  policy_arn = each.value
  role       = aws_iam_role.eks_node_role.name
}

# Custom S3 access policy with encryption requirements
resource "aws_iam_policy" "s3_access_policy" {
  name        = "${var.project_name}-${var.environment}-s3-access-policy"
  description = "Policy for S3 bucket access with encryption requirements"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:DeleteObject"
        ]
        Resource = [
          "${aws_s3_bucket.bronze_tier.arn}/*",
          "${aws_s3_bucket.silver_tier.arn}/*",
          "${aws_s3_bucket.gold_tier.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })

  tags = {
    Environment         = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    SecurityCompliance = "SOC2-ISO27001"
  }
}

# KMS key access policy for encryption operations
resource "aws_iam_policy" "kms_access_policy" {
  name        = "${var.project_name}-${var.environment}-kms-access-policy"
  description = "Policy for KMS key operations with strict controls"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.s3_encryption_key.arn
        ]
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })

  tags = {
    Environment         = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    SecurityCompliance = "SOC2-ISO27001"
  }
}

# CloudWatch logging policy for audit requirements
resource "aws_iam_policy" "cloudwatch_logging_policy" {
  name        = "${var.project_name}-${var.environment}-cloudwatch-logging-policy"
  description = "Policy for CloudWatch logging with audit requirements"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = [
          "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/eks/${var.project_name}-${var.environment}*"
        ]
      }
    ]
  })

  tags = {
    Environment         = var.environment
    Project            = var.project_name
    ManagedBy          = "terraform"
    SecurityCompliance = "SOC2-ISO27001"
  }
}

# Attach logging policy to EKS roles
resource "aws_iam_role_policy_attachment" "eks_cloudwatch_policy" {
  for_each = {
    cluster = aws_iam_role.eks_cluster_role.name
    node    = aws_iam_role.eks_node_role.name
  }

  policy_arn = aws_iam_policy.cloudwatch_logging_policy.arn
  role       = each.value
}

# Export role ARNs for use in other modules
output "eks_cluster_role_arn" {
  description = "ARN of EKS cluster IAM role"
  value       = aws_iam_role.eks_cluster_role.arn
}

output "eks_node_role_arn" {
  description = "ARN of EKS node IAM role"
  value       = aws_iam_role.eks_node_role.arn
}