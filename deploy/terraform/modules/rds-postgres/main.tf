###############################################################################
# WSLVault — RDS PostgreSQL Module
###############################################################################

variable "environment" {
  type        = string
  description = "Environment name (dev, staging, production)"
}

variable "vpc_id" {
  type        = string
  description = "VPC ID for the database"
}

variable "subnet_ids" {
  type        = list(string)
  description = "Private subnet IDs for the DB subnet group"
}

variable "allowed_security_group_id" {
  type        = string
  description = "Security group ID allowed to access the database (EKS nodes)"
}

variable "instance_class" {
  type    = string
  default = "db.r6g.large"
}

variable "allocated_storage" {
  type    = number
  default = 100
}

resource "aws_db_subnet_group" "wslvault" {
  name       = "wslvault-${var.environment}"
  subnet_ids = var.subnet_ids

  tags = {
    Name        = "wslvault-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_security_group" "rds" {
  name_prefix = "wslvault-rds-${var.environment}-"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.allowed_security_group_id]
    description     = "PostgreSQL from EKS nodes"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "wslvault-rds-${var.environment}"
    Environment = var.environment
  }
}

resource "aws_db_instance" "wslvault" {
  identifier     = "wslvault-${var.environment}"
  engine         = "postgres"
  engine_version = "16.4"
  instance_class = var.instance_class

  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.allocated_storage * 4
  storage_type          = "gp3"
  storage_encrypted     = true

  db_name  = "wslvault"
  username = "wslvault_admin"
  password = random_password.db_password.result

  db_subnet_group_name   = aws_db_subnet_group.wslvault.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  multi_az                = var.environment == "production" ? true : false
  backup_retention_period = var.environment == "production" ? 14 : 3
  deletion_protection     = var.environment == "production" ? true : false

  performance_insights_enabled = true
  monitoring_interval          = 60

  tags = {
    Name        = "wslvault-${var.environment}"
    Environment = var.environment
  }
}

resource "random_password" "db_password" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name = "wslvault/${var.environment}/db-credentials"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.wslvault.username
    password = random_password.db_password.result
    host     = aws_db_instance.wslvault.address
    port     = aws_db_instance.wslvault.port
    dbname   = aws_db_instance.wslvault.db_name
    url      = "postgres://${aws_db_instance.wslvault.username}:${random_password.db_password.result}@${aws_db_instance.wslvault.address}:${aws_db_instance.wslvault.port}/${aws_db_instance.wslvault.db_name}"
  })
}

output "db_endpoint" {
  value = aws_db_instance.wslvault.endpoint
}

output "db_secret_arn" {
  value = aws_secretsmanager_secret.db_credentials.arn
}
