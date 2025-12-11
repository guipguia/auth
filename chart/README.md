# Auth Service Helm Chart

This Helm chart deploys the Chassis Auth Service, a gRPC-based authentication service that handles user authentication, registration, MFA, sessions, and OAuth integration.

## Prerequisites

- Kubernetes 1.19+
- Helm 3.2.0+
- PostgreSQL database
- Redis cache

## Installing the Chart

To install the chart with the release name `auth-service`:

```bash
helm install auth-service ./chart
```

To install with custom values:

```bash
helm install auth-service ./chart -f custom-values.yaml
```

## Uninstalling the Chart

To uninstall the `auth-service` deployment:

```bash
helm uninstall auth-service
```

## Configuration

The following table lists the configurable parameters of the Auth Service chart and their default values.

### Basic Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Image repository | `chassis/auth-service` |
| `image.tag` | Image tag | `latest` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |

### Resource Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `resources.limits.cpu` | CPU limit | `500m` |
| `resources.limits.memory` | Memory limit | `512Mi` |
| `resources.requests.cpu` | CPU request | `100m` |
| `resources.requests.memory` | Memory request | `128Mi` |

### Autoscaling

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU utilization | `80` |
| `autoscaling.targetMemoryUtilizationPercentage` | Target memory utilization | `80` |

### Database Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `database.host` | PostgreSQL host | `postgres` |
| `database.port` | PostgreSQL port | `5432` |
| `database.name` | Database name | `auth_db` |
| `database.user` | Database user | `auth_user` |
| `database.password` | Database password | `changeme` |
| `database.sslmode` | SSL mode | `disable` |
| `database.maxOpenConns` | Max open connections | `25` |
| `database.maxIdleConns` | Max idle connections | `5` |
| `database.connMaxLifetime` | Connection max lifetime | `5m` |

### Redis Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.address` | Redis address | `redis:6379` |
| `redis.password` | Redis password | `""` |
| `redis.db` | Redis database | `0` |
| `redis.dialTimeout` | Dial timeout | `5s` |
| `redis.readTimeout` | Read timeout | `3s` |
| `redis.writeTimeout` | Write timeout | `3s` |
| `redis.poolSize` | Connection pool size | `10` |

### JWT Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `jwt.accessSecret` | Access token secret | `changeme-access-secret` |
| `jwt.refreshSecret` | Refresh token secret | `changeme-refresh-secret` |
| `jwt.accessExpiry` | Access token expiry | `15m` |
| `jwt.refreshExpiry` | Refresh token expiry | `168h` |
| `jwt.issuer` | JWT issuer | `auth-service` |

### Encryption Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `encryption.key` | Encryption key for field-level encryption | `changeme-encryption-key-32bytes` |

### Email/SMTP Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `email.enabled` | Enable email functionality | `true` |
| `email.from` | From email address | `noreply@chassis.dev` |
| `email.smtp.host` | SMTP host | `smtp.gmail.com` |
| `email.smtp.port` | SMTP port | `587` |
| `email.smtp.username` | SMTP username | `""` |
| `email.smtp.password` | SMTP password | `""` |
| `email.smtp.useTLS` | Use TLS | `true` |

### OAuth Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `oauth.google.enabled` | Enable Google OAuth | `false` |
| `oauth.google.clientId` | Google OAuth client ID | `""` |
| `oauth.google.clientSecret` | Google OAuth client secret | `""` |
| `oauth.google.redirectUrl` | Google OAuth redirect URL | `https://chassis.dev/auth/callback/google` |
| `oauth.github.enabled` | Enable GitHub OAuth | `false` |
| `oauth.github.clientId` | GitHub OAuth client ID | `""` |
| `oauth.github.clientSecret` | GitHub OAuth client secret | `""` |
| `oauth.github.redirectUrl` | GitHub OAuth redirect URL | `https://chassis.dev/auth/callback/github` |
| `oauth.microsoft.enabled` | Enable Microsoft OAuth | `false` |
| `oauth.microsoft.clientId` | Microsoft OAuth client ID | `""` |
| `oauth.microsoft.clientSecret` | Microsoft OAuth client secret | `""` |
| `oauth.microsoft.redirectUrl` | Microsoft OAuth redirect URL | `https://chassis.dev/auth/callback/microsoft` |

### Tenant Service Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `tenant.serviceUrl` | Tenant service gRPC URL | `tenant-service:8080` |
| `tenant.timeout` | Request timeout | `5s` |

### Logging Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `logging.level` | Log level | `info` |
| `logging.format` | Log format | `json` |

## Example: Production Configuration

Create a `production-values.yaml` file:

```yaml
replicaCount: 3

image:
  repository: your-registry.io/chassis/auth-service
  tag: v1.0.0
  pullPolicy: Always

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 250m
    memory: 256Mi

database:
  host: postgres.production.svc.cluster.local
  port: 5432
  name: auth_production
  user: auth_prod_user
  password: <use-secret-or-sealed-secret>
  sslmode: require
  maxOpenConns: 50
  maxIdleConns: 10

redis:
  address: redis.production.svc.cluster.local:6379
  password: <use-secret-or-sealed-secret>

jwt:
  accessSecret: <generate-secure-random-string>
  refreshSecret: <generate-secure-random-string>
  accessExpiry: 15m
  refreshExpiry: 168h
  issuer: auth-service-production

encryption:
  key: <generate-32-byte-key>

email:
  enabled: true
  from: noreply@yourcompany.com
  smtp:
    host: smtp.sendgrid.net
    port: 587
    username: apikey
    password: <your-sendgrid-api-key>

oauth:
  google:
    enabled: true
    clientId: <your-google-client-id>
    clientSecret: <your-google-client-secret>
    redirectUrl: https://yourapp.com/auth/callback/google
  github:
    enabled: true
    clientId: <your-github-client-id>
    clientSecret: <your-github-client-secret>
    redirectUrl: https://yourapp.com/auth/callback/github

logging:
  level: info
  format: json
```

Install with production values:

```bash
helm install auth-service ./chart -f production-values.yaml
```

## Security Considerations

1. **Change Default Secrets**: Always change the default values for:
   - `database.password`
   - `jwt.accessSecret`
   - `jwt.refreshSecret`
   - `encryption.key`
   - SMTP credentials
   - OAuth credentials

2. **Use External Secrets**: For production, consider using:
   - [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets)
   - [External Secrets Operator](https://external-secrets.io/)
   - [HashiCorp Vault](https://www.vaultproject.io/)

3. **Enable TLS**: Configure TLS for database and Redis connections in production

4. **Network Policies**: Implement Kubernetes Network Policies to restrict traffic

## Monitoring and Health Checks

The deployment includes:
- **Liveness Probe**: TCP check on gRPC port (default: 8080)
- **Readiness Probe**: TCP check on gRPC port (default: 8080)

For production, consider implementing gRPC health checks using the [gRPC Health Checking Protocol](https://github.com/grpc/grpc/blob/master/doc/health-checking.md).

## Troubleshooting

### Check Pod Status
```bash
kubectl get pods -l app.kubernetes.io/name=auth-service
```

### View Logs
```bash
kubectl logs -l app.kubernetes.io/name=auth-service --tail=100 -f
```

### Describe Pod
```bash
kubectl describe pod -l app.kubernetes.io/name=auth-service
```

### Test gRPC Connection
```bash
kubectl run -it --rm grpcurl --image=fullstorydev/grpcurl --restart=Never -- \
  auth-service:8080 list
```

## Upgrading

To upgrade the release:

```bash
helm upgrade auth-service ./chart -f values.yaml
```

To rollback:

```bash
helm rollback auth-service
```

## License

Copyright (c) 2024 Chassis Team
