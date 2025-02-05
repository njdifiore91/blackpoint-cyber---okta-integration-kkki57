# Configure Terraform version and required providers
terraform {
  required_version = ">=1.0.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
  }
}

# AWS Provider Configuration
provider "aws" {
  region = var.aws_region
  
  # Enhanced security and compliance tagging for all resources
  default_tags {
    tags = {
      Environment         = var.environment
      Project            = var.project_name
      ManagedBy          = "terraform"
      SecurityCompliance = "required"
      DataClassification = "sensitive"
    }
  }

  # Assume role configuration for enhanced security
  assume_role {
    role_arn     = var.aws_role_arn
    session_name = "terraform-blackpoint"
  }
}

# Kubernetes Provider Configuration for EKS
provider "kubernetes" {
  host                   = module.eks.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
  
  # AWS IAM Authenticator configuration
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      module.eks.cluster_name,
      "--region",
      var.aws_region
    ]
  }
}

# Helm Provider Configuration
provider "helm" {
  kubernetes {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    
    # AWS IAM Authenticator configuration
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        module.eks.cluster_name,
        "--region",
        var.aws_region
      ]
    }
  }

  # Helm specific configurations
  repository_config_path = "${path.module}/helm/repositories.yaml"
  repository_cache      = "${path.module}/helm/cache"
}