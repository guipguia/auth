FROM golang:1.25.5-alpine AS builder

# Install dependencies
RUN apk add --no-cache git make protobuf protobuf-dev wget

# Install grpc-health-probe for health checks
RUN GRPC_HEALTH_PROBE_VERSION=v0.4.25 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Install proto plugins
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Generate proto files
RUN make proto

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o auth-server cmd/server/main.go

# Final stage
FROM gcr.io/distroless/static-debian12

WORKDIR /app

# Copy binary and templates from builder
COPY --from=builder /app/auth-server .
COPY --from=builder /app/templates ./templates
COPY --from=builder /bin/grpc_health_probe /bin/grpc_health_probe

EXPOSE 8080

# Run the application
CMD ["./auth-server"]
