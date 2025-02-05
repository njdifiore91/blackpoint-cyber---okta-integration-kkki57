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

# KMS key for EKS cluster encryption
resource "aws_kms_key" "eks" {
  description             = "KMS key for EKS cluster encryption"
  deletion_window_in_days = 7
  enable_key_rotation    = true

  tags = {
    Name               = "${var.cluster_name}-encryption-key"
    Environment        = var.environment
    SecurityCompliance = "SOC2"
    ManagedBy         = "terraform"
  }
}

# Security group for EKS cluster
resource "aws_security_group" "eks_cluster" {
  name        = "${var.cluster_name}-cluster-sg"
  description = "Security group for EKS cluster control plane"
  vpc_id      = data.aws_vpc.main.id

  ingress {
    description = "Allow HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.main.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name               = "${var.cluster_name}-cluster-sg"
    Environment        = var.environment
    SecurityCompliance = "SOC2"
  }
}

# EKS Cluster with enhanced security and compliance features
resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = data.aws_iam_role.eks_cluster_role.arn
  version  = var.eks_version

  vpc_config {
    subnet_ids              = data.aws_subnet.private[*].id
    endpoint_private_access = true
    endpoint_public_access  = true
    security_group_ids      = [aws_security_group.eks_cluster.id]
    public_access_cidrs     = ["10.0.0.0/8"]  # Restrict to internal network
  }

  encryption_config {
    provider {
      key_arn = aws_kms_key.eks.arn
    }
    resources = ["secrets"]
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  kubernetes_network_config {
    service_ipv4_cidr = "172.20.0.0/16"
    ip_family         = "ipv4"
  }

  tags = {
    Name               = var.cluster_name
    Environment        = var.environment
    ManagedBy         = "terraform"
    SecurityCompliance = "SOC2"
    CostCenter        = "security-platform"
  }

  depends_on = [
    aws_security_group.eks_cluster,
    aws_kms_key.eks
  ]
}

# EKS Node Groups with workload isolation
resource "aws_eks_node_group" "main" {
  for_each = {
    application = {
      instance_type  = "c5.2xlarge"
      desired_size   = 3
      min_size      = 3
      max_size      = 10
      disk_size     = 100
      capacity_type = "ON_DEMAND"
      taints       = []
    }
    monitoring = {
      instance_type  = "c5.2xlarge"
      desired_size   = 2
      min_size      = 2
      max_size      = 5
      disk_size     = 100
      capacity_type = "ON_DEMAND"
      taints       = []
    }
  }

  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "${var.cluster_name}-${each.key}"
  node_role_arn   = data.aws_iam_role.eks_node_role.arn
  subnet_ids      = data.aws_subnet.private[*].id

  instance_types = [each.value.instance_type]
  capacity_type  = each.value.capacity_type
  disk_size      = each.value.disk_size

  scaling_config {
    desired_size = each.value.desired_size
    max_size     = each.value.max_size
    min_size     = each.value.min_size
  }

  update_config {
    max_unavailable_percentage = 25
  }

  labels = {
    role        = each.key
    environment = var.environment
    nodegroup   = each.key
  }

  tags = {
    Name               = "${var.cluster_name}-${each.key}"
    Environment        = var.environment
    ManagedBy         = "terraform"
    SecurityCompliance = "SOC2"
    NodeGroupType     = each.key
    CostCenter        = "security-platform"
  }

  depends_on = [aws_eks_cluster.main]
}

# CloudWatch Log Group for EKS cluster logs
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.cluster_name}/cluster"
  retention_in_days = 90

  tags = {
    Name        = "${var.cluster_name}-logs"
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

# Outputs for cluster access and configuration
output "cluster_endpoint" {
  description = "EKS cluster endpoint URL for kubectl configuration"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_security_group_id" {
  description = "Security group ID for EKS cluster access configuration"
  value       = aws_security_group.eks_cluster.id
}

output "cluster_certificate_authority_data" {
  description = "Cluster CA certificate for secure communication"
  value       = aws_eks_cluster.main.certificate_authority[0].data
}