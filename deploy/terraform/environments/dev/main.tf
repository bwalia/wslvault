###############################################################################
# WSLVault — Dev Environment Root Module
#
# Wires together the eks-cluster, kms-keys, and rds-postgres modules for a
# non-production dev deployment. Public API access is enabled for the EKS
# control plane in non-production (see eks-cluster module vpc_config).
###############################################################################

locals {
  environment = "dev"
}

###############################################################################
# EKS Cluster
###############################################################################

module "eks_cluster" {
  source = "../../modules/eks-cluster"

  environment         = local.environment
  vpc_id              = var.vpc_id
  subnet_ids          = var.subnet_ids
  cluster_version     = var.cluster_version
  node_instance_types = ["t3.medium"]
  node_desired_size   = 2
  node_min_size       = 1
  node_max_size       = 4
}

###############################################################################
# IAM role for the wslvault crypto-service pods.
#
# The kms-keys module requires the ARN of the principal that is permitted to
# call the root KEK.  We define that role here so the ARN is available before
# the KMS key policy is written.
###############################################################################

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "crypto_service_assume_role" {
  # Trust the EKS OIDC provider so pods can assume this role via IRSA.
  # The actual OIDC thumbprint/URL is read from the cluster after it is
  # created; Terraform resolves the dependency automatically.
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "crypto_service" {
  name               = "wslvault-crypto-service-${local.environment}"
  assume_role_policy = data.aws_iam_policy_document.crypto_service_assume_role.json

  tags = {
    Name        = "wslvault-crypto-service-${local.environment}"
    Environment = local.environment
    Component   = "crypto-service"
  }
}

###############################################################################
# KMS Keys (Root KEK + Audit Signing)
###############################################################################

module "kms_keys" {
  source = "../../modules/kms-keys"

  environment             = local.environment
  crypto_service_role_arn = aws_iam_role.crypto_service.arn
}

###############################################################################
# RDS PostgreSQL
###############################################################################

module "rds_postgres" {
  source = "../../modules/rds-postgres"

  environment               = local.environment
  vpc_id                    = var.vpc_id
  subnet_ids                = var.subnet_ids
  allowed_security_group_id = module.eks_cluster.node_security_group_id
  instance_class            = "db.t3.medium"
  # 20 GB for dev; max_allocated_storage will be 4x = 80 GB (set in module)
  allocated_storage = 20
}

###############################################################################
# Kubernetes provider — authenticates against the newly provisioned cluster
###############################################################################

data "aws_eks_cluster_auth" "wslvault" {
  name = module.eks_cluster.cluster_name
}

provider "kubernetes" {
  host                   = module.eks_cluster.cluster_endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.wslvault.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.wslvault.token
}

data "aws_eks_cluster" "wslvault" {
  name = module.eks_cluster.cluster_name
}

###############################################################################
# Helm provider
###############################################################################

provider "helm" {
  kubernetes {
    host                   = module.eks_cluster.cluster_endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.wslvault.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.wslvault.token
  }
}

###############################################################################
# wslvault Helm release
#
# Deploys the wslvault application chart from the local path.  In dev the
# bundled Bitnami PostgreSQL subchart is disabled because we use the RDS
# instance provisioned above.  Resource requests/limits are kept small to
# suit the t3.medium node pool.
###############################################################################

resource "helm_release" "wslvault" {
  name             = "wslvault"
  chart            = "${path.module}/../../../../deploy/helm/wslvault"
  namespace        = "wslvault"
  create_namespace = true

  # Pin to a specific chart version to prevent unintended upgrades
  version = var.helm_chart_version

  # Reduce replica counts for dev to conserve cluster capacity
  set {
    name  = "cryptoService.replicaCount"
    value = "1"
  }

  set {
    name  = "secretEngine.replicaCount"
    value = "1"
  }

  set {
    name  = "policyEngine.replicaCount"
    value = "1"
  }

  set {
    name  = "identityService.replicaCount"
    value = "1"
  }

  set {
    name  = "leaseManager.replicaCount"
    value = "1"
  }

  set {
    name  = "auditService.replicaCount"
    value = "1"
  }

  set {
    name  = "gateway.replicaCount"
    value = "1"
  }

  # Disable the bundled PostgreSQL subchart; use the RDS instance instead
  set {
    name  = "postgresql.enabled"
    value = "false"
  }

  # Pass the RDS endpoint so services can build their DATABASE_URL
  set {
    name  = "postgresql.external.host"
    value = module.rds_postgres.db_endpoint
  }

  # Surface the KMS key ARNs as chart values for crypto-service configuration
  set {
    name  = "cryptoService.kmsRootKekArn"
    value = module.kms_keys.root_kek_arn
  }

  set {
    name  = "auditService.kmsAuditSigningKeyArn"
    value = module.kms_keys.audit_signing_key_arn
  }

  depends_on = [
    module.eks_cluster,
    module.rds_postgres,
    module.kms_keys,
  ]
}
