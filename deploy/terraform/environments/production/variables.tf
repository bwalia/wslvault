###############################################################################
# WSLVault — Production Environment Variables
###############################################################################

variable "region" {
  type        = string
  description = "AWS region to deploy resources into."
  default     = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "ID of the VPC in which to deploy the EKS cluster and RDS instance."

  validation {
    condition     = can(regex("^vpc-[0-9a-f]{8,17}$", var.vpc_id))
    error_message = "vpc_id must be a valid AWS VPC ID (e.g. vpc-0123456789abcdef0)."
  }
}

variable "subnet_ids" {
  type        = list(string)
  description = <<-EOT
    List of private subnet IDs used for both EKS node groups and the RDS DB
    subnet group.  At least two subnets in different Availability Zones are
    required so that Multi-AZ RDS and EKS node distribution work correctly.
  EOT

  validation {
    condition     = length(var.subnet_ids) >= 2
    error_message = "At least two subnet IDs must be provided for multi-AZ coverage."
  }

  validation {
    condition     = alltrue([for s in var.subnet_ids : can(regex("^subnet-[0-9a-f]{8,17}$", s))])
    error_message = "Each subnet_id must be a valid AWS subnet ID (e.g. subnet-0123456789abcdef0)."
  }
}

variable "cluster_version" {
  type        = string
  description = "Kubernetes version to run on the EKS control plane."
  default     = "1.31"
}

variable "helm_chart_version" {
  type        = string
  description = <<-EOT
    Version of the wslvault Helm chart to deploy.  Pinning this value
    prevents unintended automatic upgrades when the chart is updated.
    All production deployments must be preceded by a successful dev
    deployment of the same chart version.
  EOT
  default     = "0.1.0"
}
