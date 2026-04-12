###############################################################################
# WSLVault — Production Environment Remote State Backend
#
# Uses an S3 bucket for state storage with server-side encryption and a
# DynamoDB table for state-locking to prevent concurrent runs from corrupting
# state.
#
# The production state is stored under a separate key from dev so the two
# environments have fully independent state files.
#
# Prerequisites (create once, outside Terraform):
#   aws s3api create-bucket \
#     --bucket wslvault-terraform-state \
#     --region us-east-1 \
#     --create-bucket-configuration LocationConstraint=us-east-1
#
#   aws s3api put-bucket-versioning \
#     --bucket wslvault-terraform-state \
#     --versioning-configuration Status=Enabled
#
#   aws s3api put-bucket-encryption \
#     --bucket wslvault-terraform-state \
#     --server-side-encryption-configuration \
#       '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}'
#
#   aws dynamodb create-table \
#     --table-name wslvault-terraform-locks \
#     --attribute-definitions AttributeName=LockID,AttributeType=S \
#     --key-schema AttributeName=LockID,KeyType=HASH \
#     --billing-mode PAY_PER_REQUEST \
#     --region us-east-1
###############################################################################

terraform {
  backend "s3" {
    bucket         = "wslvault-terraform-state"
    key            = "environments/production/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "wslvault-terraform-locks"
  }
}
