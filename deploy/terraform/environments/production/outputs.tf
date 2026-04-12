###############################################################################
# WSLVault — Production Environment Outputs
###############################################################################

output "cluster_endpoint" {
  description = "HTTPS endpoint of the EKS API server."
  value       = module.eks_cluster.cluster_endpoint
}

output "cluster_name" {
  description = "Name of the EKS cluster (used by kubectl and CI tooling)."
  value       = module.eks_cluster.cluster_name
}

output "database_endpoint" {
  description = <<-EOT
    Connection endpoint for the RDS PostgreSQL Multi-AZ instance in the
    format <host>:<port>.  The full credentials are stored in Secrets Manager
    (see db_secret_arn).
  EOT
  value       = module.rds_postgres.db_endpoint
}

output "db_secret_arn" {
  description = "ARN of the Secrets Manager secret that holds the RDS credentials JSON."
  value       = module.rds_postgres.db_secret_arn
}

output "root_kek_arn" {
  description = "ARN of the KMS root Key-Encryption-Key used in the envelope encryption hierarchy."
  value       = module.kms_keys.root_kek_arn
}

output "audit_hmac_key_arn" {
  description = "ARN of the HMAC_256 KMS key used to sign audit log events."
  value       = module.kms_keys.audit_signing_key_arn
}

output "crypto_service_role_arn" {
  description = "ARN of the IAM role assumed by crypto-service pods (used in KMS key policy)."
  value       = aws_iam_role.crypto_service.arn
}
