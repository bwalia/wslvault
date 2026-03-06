###############################################################################
# WSLVault — KMS Keys Module
# Manages the root KEK for the envelope encryption hierarchy.
###############################################################################

variable "environment" {
  type        = string
  description = "Environment name"
}

variable "crypto_service_role_arn" {
  type        = string
  description = "IAM role ARN for the crypto-service (allowed to use the root KEK)"
}

# Root KEK — the top of the envelope encryption hierarchy
resource "aws_kms_key" "root_kek" {
  description             = "WSLVault Root KEK (${var.environment})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  key_usage               = "ENCRYPT_DECRYPT"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowRootAccountFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowCryptoServiceUse"
        Effect = "Allow"
        Principal = {
          AWS = var.crypto_service_role_arn
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:GenerateDataKeyWithoutPlaintext",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "wslvault-root-kek-${var.environment}"
    Environment = var.environment
    Purpose     = "root-kek"
  }
}

resource "aws_kms_alias" "root_kek" {
  name          = "alias/wslvault-root-kek-${var.environment}"
  target_key_id = aws_kms_key.root_kek.key_id
}

# Audit signing key — used to HMAC audit events
resource "aws_kms_key" "audit_signing" {
  description             = "WSLVault Audit Signing Key (${var.environment})"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  key_usage               = "GENERATE_VERIFY_MAC"
  customer_master_key_spec = "HMAC_256"

  tags = {
    Name        = "wslvault-audit-signing-${var.environment}"
    Environment = var.environment
    Purpose     = "audit-signing"
  }
}

resource "aws_kms_alias" "audit_signing" {
  name          = "alias/wslvault-audit-signing-${var.environment}"
  target_key_id = aws_kms_key.audit_signing.key_id
}

data "aws_caller_identity" "current" {}

output "root_kek_arn" {
  value = aws_kms_key.root_kek.arn
}

output "root_kek_alias" {
  value = aws_kms_alias.root_kek.name
}

output "audit_signing_key_arn" {
  value = aws_kms_key.audit_signing.arn
}
