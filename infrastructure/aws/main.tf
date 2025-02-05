# Enhanced Terraform configuration with security and compliance features
terraform {
  required_version = ">=1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws" # v5.0
      version = "~> 5.0"
      configuration = {
        max_retries = 3
        assume_role = {
          role_arn     = var.terraform_role_arn
          session_name = "terraform-session"
        }
      }
    }
    kubernetes = {
      source  = "hashicorp/kubernetes" # v2.0
      version = "~> 2.0"
    }
  }

  backend "s3" {
    bucket         = var.state_bucket
    key            = "terraform.tfstate"
    region         = var.aws_region
    dynamodb_table = var.state_lock_table
    encrypt        = true
    kms_key_id     = var.state_encryption_key
    versioning     = true
  }
}

# Primary AWS provider configuration
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

# DR region AWS provider configuration
provider "aws" {
  alias  = "dr"
  region = var.dr_region

  default_tags {
    tags = local.common_tags
  }
}

# Local variables for enhanced resource tagging
locals {
  common_tags = {
    Environment        = var.environment
    Project           = "blackpoint-security"
    ManagedBy         = "terraform"
    SecurityCompliance = "soc2"
    DataClassification = "sensitive"
    BackupPolicy      = "daily"
    DisasterRecovery  = "enabled"
  }
}

# VPC module with enhanced security features
module "vpc" {
  source = "./vpc"

  aws_region          = var.aws_region
  environment         = var.environment
  vpc_cidr           = var.vpc_cidr
  availability_zones  = var.availability_zones
  enable_flow_logs    = true
  enable_vpc_endpoints = true
  enable_nat_gateway  = true
  single_nat_gateway  = false

  tags = local.common_tags
}

# EKS module with security controls
module "eks" {
  source = "./eks"

  cluster_name              = var.cluster_name
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnet_ids
  node_instance_type       = var.node_instance_type
  eks_version              = var.eks_version
  enable_encryption        = true
  enable_pod_security_policy = true
  enable_network_policy    = true
  enable_cluster_autoscaler = true

  tags = local.common_tags
}

# DR region VPC module
module "vpc_dr" {
  source = "./vpc"
  providers = {
    aws = aws.dr
  }

  aws_region          = var.dr_region
  environment         = "${var.environment}-dr"
  vpc_cidr           = var.vpc_cidr_dr
  availability_zones  = var.dr_availability_zones
  enable_flow_logs    = true
  enable_vpc_endpoints = true
  enable_nat_gateway  = true
  single_nat_gateway  = false

  tags = merge(local.common_tags, {
    DisasterRecoveryRole = "secondary"
  })
}

# DR region EKS module
module "eks_dr" {
  source = "./eks"
  providers = {
    aws = aws.dr
  }

  cluster_name              = "${var.cluster_name}-dr"
  vpc_id                   = module.vpc_dr.vpc_id
  subnet_ids               = module.vpc_dr.private_subnet_ids
  node_instance_type       = var.node_instance_type
  eks_version              = var.eks_version
  enable_encryption        = true
  enable_pod_security_policy = true
  enable_network_policy    = true
  enable_cluster_autoscaler = true

  tags = merge(local.common_tags, {
    DisasterRecoveryRole = "secondary"
  })
}

# Outputs for infrastructure access
output "vpc_id" {
  description = "ID of the primary VPC"
  value       = module.vpc.vpc_id
}

output "eks_cluster_endpoint" {
  description = "Endpoint for primary EKS cluster"
  value       = module.eks.cluster_endpoint
  sensitive   = true
}

output "eks_cluster_name" {
  description = "Name of the primary EKS cluster"
  value       = module.eks.cluster_name
}

output "vpc_dr_id" {
  description = "ID of the DR region VPC"
  value       = module.vpc_dr.vpc_id
}

output "eks_dr_cluster_endpoint" {
  description = "Endpoint for DR EKS cluster"
  value       = module.eks_dr.cluster_endpoint
  sensitive   = true
}

output "eks_dr_cluster_name" {
  description = "Name of the DR EKS cluster"
  value       = module.eks_dr.cluster_name
}