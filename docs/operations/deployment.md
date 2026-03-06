# WSLVault Deployment Guide

## Local Development

```bash
# Start all services with Docker Compose
docker compose up -d

# Verify services are healthy
curl http://localhost:8081/health   # secret-engine
curl http://localhost:8080/health   # crypto-service
curl http://localhost:8087/health   # mcp-server
```

## Kubernetes (Kustomize)

### Development
```bash
kubectl apply -k deploy/kubernetes/overlays/dev
```

### Production
```bash
kubectl apply -k deploy/kubernetes/overlays/production
```

## Terraform (AWS)

### Prerequisites
- AWS CLI configured with appropriate credentials
- Terraform >= 1.5

### Deploy
```bash
cd deploy/terraform/environments/production
terraform init
terraform plan
terraform apply
```

## Configuration

All services are configured via environment variables with the `VAULT_` prefix:

| Variable | Service | Description |
|----------|---------|-------------|
| `VAULT_ROOT_KEY` | crypto-service | Base64-encoded 32-byte root KEK |
| `VAULT_JWT_SECRET` | identity-service | JWT HMAC-SHA256 signing secret |
| `VAULT_AUDIT_SIGNING_KEY` | audit-service | Audit log HMAC signing key |
| `VAULT__DATABASE__URL` | all | PostgreSQL connection URL |
| `VAULT_LISTEN_ADDR` | all | Service listen address |
| `RUST_LOG` | all | Log level filter (e.g. `info,secret_engine=debug`) |

## Monitoring

- Prometheus metrics exposed on port 9090 of each service
- Structured JSON logs to stdout (compatible with CloudWatch, Datadog, etc.)
- OpenTelemetry trace export via OTLP
