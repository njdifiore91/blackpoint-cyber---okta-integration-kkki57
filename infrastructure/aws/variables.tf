# AWS Region Configuration
variable "aws_region" {
  description = "AWS region for infrastructure deployment. Must be in approved regions for compliance."
  type        = string
  default     = "us-west-2"

  validation {
    condition     = can(regex("^us-(east|west)-[1-2]$", var.aws_region))
    error_message = "AWS region must be us-east-1, us-east-2, us-west-1, or us-west-2 for compliance requirements"
  }
}

# Environment Configuration
variable "environment" {
  description = "Deployment environment with specific security and scaling configurations per environment"
  type        = string

  validation {
    condition     = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be production, staging, or development"
  }
}

# Project Configuration
variable "project_name" {
  description = "Project name for resource tagging and identification in compliance reports"
  type        = string
  default     = "blackpoint-security"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens"
  }
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC with enhanced validation for proper network segmentation"
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0)) && can(regex("^10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}/16$", var.vpc_cidr))
    error_message = "VPC CIDR must be a valid /16 IPv4 CIDR block in the 10.0.0.0/8 range"
  }
}

variable "availability_zones" {
  description = "List of availability zones for multi-AZ deployment ensuring high availability"
  type        = list(string)
  default     = ["us-west-2a", "us-west-2b", "us-west-2c"]

  validation {
    condition     = length(var.availability_zones) >= 3
    error_message = "At least 3 availability zones required for high availability"
  }
}

# EKS Configuration
variable "cluster_name" {
  description = "Name of the EKS cluster following naming conventions"
  type        = string
  default     = "blackpoint-eks-cluster"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.cluster_name)) && length(var.cluster_name) <= 40
    error_message = "Cluster name must be lowercase alphanumeric with hyphens and max 40 characters"
  }
}

variable "eks_version" {
  description = "Kubernetes version for EKS cluster with strict version control"
  type        = string
  default     = "1.25"

  validation {
    condition     = can(regex("^1\\.(2[4-5])$", var.eks_version))
    error_message = "EKS version must be 1.24 or 1.25 for security compliance"
  }
}

variable "node_instance_type" {
  description = "EC2 instance type for EKS worker nodes optimized for performance"
  type        = string
  default     = "c5.2xlarge"

  validation {
    condition     = can(regex("^c5\\.(2xlarge|4xlarge|9xlarge)$", var.node_instance_type))
    error_message = "Instance type must be c5.2xlarge, c5.4xlarge, or c5.9xlarge for optimal performance"
  }
}

variable "node_group_desired_size" {
  description = "Desired number of worker nodes for optimal performance"
  type        = number
  default     = 3

  validation {
    condition     = var.node_group_desired_size >= 3
    error_message = "Minimum 3 nodes required for high availability"
  }
}

variable "node_group_min_size" {
  description = "Minimum number of worker nodes ensuring high availability"
  type        = number
  default     = 3

  validation {
    condition     = var.node_group_min_size >= 3
    error_message = "Minimum 3 nodes required for high availability"
  }
}

variable "node_group_max_size" {
  description = "Maximum number of worker nodes for scaling"
  type        = number
  default     = 15

  validation {
    condition     = var.node_group_max_size >= var.node_group_min_size * 2
    error_message = "Maximum size must be at least double the minimum size for proper scaling"
  }
}

# State Management Configuration
variable "state_bucket" {
  description = "S3 bucket name for Terraform state storage with versioning"
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+$", var.state_bucket))
    error_message = "S3 bucket name must be lowercase alphanumeric with dots and hyphens"
  }
}

variable "state_lock_table" {
  description = "DynamoDB table name for Terraform state locking"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9_.-]+$", var.state_lock_table))
    error_message = "DynamoDB table name must be alphanumeric with underscores, dots, and hyphens"
  }
}

# Resource Tagging
variable "tags" {
  description = "Additional tags for all resources including compliance and security tags"
  type        = map(string)
  default = {
    ManagedBy           = "Terraform"
    SecurityCompliance  = "SOC2"
    Environment        = "production"
  }
}