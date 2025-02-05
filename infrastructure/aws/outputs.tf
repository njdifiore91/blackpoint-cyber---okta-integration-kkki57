# Output configuration for BlackPoint Security Integration Framework infrastructure
# Exports critical infrastructure values for cross-module integration and external tool configuration

# VPC Outputs
output "vpc_id" {
  description = "ID of the VPC hosting the BlackPoint Security infrastructure"
  value       = module.vpc.vpc_id
  sensitive   = false
}

output "vpc_private_subnet_ids" {
  description = "IDs of private subnets for workload deployment"
  value       = module.vpc.private_subnet_ids
  sensitive   = false
}

output "vpc_public_subnet_ids" {
  description = "IDs of public subnets for load balancer deployment"
  value       = module.vpc.public_subnet_ids
  sensitive   = false
}

# EKS Cluster Outputs
output "eks_cluster_endpoint" {
  description = "Endpoint URL for the EKS cluster API server"
  value       = module.eks.cluster_endpoint
  sensitive   = false
}

output "eks_cluster_name" {
  description = "Name of the EKS cluster"
  value       = module.eks.cluster_name
  sensitive   = false
}

output "eks_cluster_security_group_id" {
  description = "ID of the security group attached to the EKS cluster"
  value       = module.eks.cluster_security_group_id
  sensitive   = false
}