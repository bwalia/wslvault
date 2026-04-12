###############################################################################
# WSLVault — Production Environment Provider & Terraform Version Constraints
###############################################################################

terraform {
  required_version = ">= 1.5.0"

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
    random = {
      # Required by the rds-postgres module for random_password
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

###############################################################################
# AWS provider
#
# The region is read from the variable defined in variables.tf so that a
# single workspace can be targeted at any region without editing HCL files.
###############################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "wslvault"
      Environment = "production"
      ManagedBy   = "terraform"
    }
  }
}
