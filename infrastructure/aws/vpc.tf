# AWS Provider configuration v5.0
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Main VPC resource with enhanced security features
resource "aws_vpc" "main" {
  cidr_block                           = var.vpc_cidr
  enable_dns_hostnames                 = true
  enable_dns_support                   = true
  enable_network_address_usage_metrics = true

  tags = {
    Name          = "blackpoint-${var.environment}-vpc"
    Environment   = var.environment
    Purpose       = "Security platform infrastructure"
    SecurityLevel = "High"
    Compliance    = "SOC2"
    ManagedBy     = "Terraform"
  }
}

# VPC Flow Logs for security monitoring and compliance
resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/blackpoint-${var.environment}-flow-logs"
  retention_in_days = 90

  tags = {
    Name    = "blackpoint-${var.environment}-flow-logs"
    Purpose = "Security monitoring"
  }
}

resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type            = "ALL"
  log_destination_type    = "cloud-watch-logs"
  log_destination         = aws_cloudwatch_log_group.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name    = "blackpoint-${var.environment}-flow-logs"
    Purpose = "Security monitoring"
  }
}

# Private subnets for EKS cluster with optimized CIDR allocation
resource "aws_subnet" "private" {
  count             = 3
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name                              = "blackpoint-${var.environment}-private-${count.index + 1}"
    "kubernetes.io/role/internal-elb" = "1"
    NetworkType                       = "Private"
    SecurityZone                      = "Restricted"
    Environment                       = var.environment
  }
}

# Network ACLs for enhanced subnet security
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    Name    = "blackpoint-${var.environment}-nacl"
    Purpose = "Network security"
  }
}

# NAT Gateways for private subnet internet access
resource "aws_eip" "nat" {
  count  = 3
  domain = "vpc"

  tags = {
    Name = "blackpoint-${var.environment}-nat-eip-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count         = 3
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.private[count.index].id

  tags = {
    Name = "blackpoint-${var.environment}-nat-${count.index + 1}"
  }
}

# Route tables for private subnets with cross-AZ redundancy
resource "aws_route_table" "private" {
  count  = 3
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = {
    Name    = "blackpoint-${var.environment}-private-rt-${count.index + 1}"
    Purpose = "Private subnet routing"
  }
}

resource "aws_route_table_association" "private" {
  count          = 3
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Outputs for use in other Terraform configurations
output "vpc_id" {
  description = "ID of the created VPC"
  value       = aws_vpc.main.id
}

output "vpc_flow_log_group" {
  description = "Name of the VPC flow logs CloudWatch log group"
  value       = aws_cloudwatch_log_group.flow_logs.name
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "nat_gateway_ids" {
  description = "IDs of the NAT gateways"
  value       = aws_nat_gateway.main[*].id
}