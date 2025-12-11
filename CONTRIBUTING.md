# Contributing to Auth Chassis

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Go 1.21 or higher
- PostgreSQL 12 or higher
- Protocol Buffers compiler (protoc)
- Docker (optional, for running the full stack)

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/guipguia/auth.git
   cd auth
   ```

2. **Install dependencies**
   ```bash
   go mod download
   make install-tools
   ```

3. **Set up PostgreSQL**
   ```bash
   # Using Docker
   docker run -d --name auth-postgres \
     -e POSTGRES_USER=postgres \
     -e POSTGRES_PASSWORD=postgres \
     -e POSTGRES_DB=auth_db \
     -p 5432:5432 \
     postgres:16

   # Or use docker-compose
   docker-compose up -d postgres
   ```

4. **Configure environment**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Run the service**
   ```bash
   make run
   ```

## Development Workflow

### Making Changes

1. Create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the code style guidelines below.

3. Run tests to ensure nothing is broken:
   ```bash
   make test-all
   ```

4. Commit your changes with a clear commit message.

5. Push your branch and open a Pull Request.

### Code Style

- Follow standard Go conventions and [Effective Go](https://go.dev/doc/effective_go)
- Use `gofmt` or `goimports` to format code
- Run `golangci-lint` before committing:
  ```bash
  golangci-lint run
  ```

### Testing

- Write tests for new functionality
- Repository tests require a PostgreSQL database
- Service tests should mock dependencies via interfaces
- Run the full test suite before submitting PRs:
  ```bash
  make test-all
  ```

### Protobuf Changes

If you modify `api/proto/auth/v1/auth.proto`:

1. Install protobuf tools if not already installed:
   ```bash
   make install-tools
   ```

2. Regenerate Go code:
   ```bash
   make proto
   ```

3. Include the generated `*.pb.go` files in your commit.

## Pull Request Guidelines

### Before Submitting

- [ ] Tests pass locally (`make test-all`)
- [ ] Code is formatted (`gofmt`)
- [ ] Linter passes (`golangci-lint run`)
- [ ] New functionality includes tests
- [ ] Proto changes include regenerated files

### PR Description

- Clearly describe what the PR does
- Reference any related issues
- Include any breaking changes
- Add migration notes if applicable

### Review Process

1. All PRs require at least one approval
2. CI checks must pass
3. Address review feedback promptly
4. Keep PRs focused and reasonably sized

## Architecture Guidelines

### Layered Architecture

Follow the existing layered architecture:

```
gRPC Handler (proto-generated)
    ↓
Service Layer (business logic)
    ↓
Repository Layer (data access)
    ↓
Database/Cache
```

### Adding New Features

1. **Domain models** go in `internal/domain/`
2. **Repository interfaces and implementations** go in `internal/repository/`
3. **Business logic** goes in `internal/service/`
4. **gRPC definitions** go in `api/proto/auth/v1/auth.proto`

### Multi-Tenant Considerations

All data operations must be scoped to a tenant. Extract `TenantID` from context using `TenantFromContext(ctx)`.

## Reporting Issues

### Bug Reports

Include:
- Go version and OS
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

### Feature Requests

Include:
- Use case description
- Proposed solution (if any)
- Alternatives considered

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
