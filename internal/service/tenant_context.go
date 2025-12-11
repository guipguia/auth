package service

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
)

// TenantContextKey is the key used to store tenant ID in context
type TenantContextKey struct{}

// MetadataTenantKey is the gRPC metadata key for tenant ID
const MetadataTenantKey = "x-tenant-id"

// TenantFromContext extracts the tenant ID from context
func TenantFromContext(ctx context.Context) (uuid.UUID, error) {
	// First try to get from context value (set by interceptor)
	if tenantID, ok := ctx.Value(TenantContextKey{}).(uuid.UUID); ok {
		return tenantID, nil
	}

	// Fall back to gRPC metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return uuid.Nil, fmt.Errorf("no metadata in context")
	}

	tenantIDs := md.Get(MetadataTenantKey)
	if len(tenantIDs) == 0 {
		return uuid.Nil, fmt.Errorf("tenant ID not found in metadata")
	}

	tenantID, err := uuid.Parse(tenantIDs[0])
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid tenant ID format: %w", err)
	}

	return tenantID, nil
}

// ContextWithTenant adds the tenant ID to the context
func ContextWithTenant(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, TenantContextKey{}, tenantID)
}

// MustTenantFromContext extracts the tenant ID from context.
// Returns uuid.Nil if tenant ID is not found instead of panicking.
//
// Deprecated: Use TenantFromContext instead which returns an error for proper error handling.
// This function is kept for backward compatibility but should be avoided in new code.
func MustTenantFromContext(ctx context.Context) uuid.UUID {
	tenantID, err := TenantFromContext(ctx)
	if err != nil {
		// Return uuid.Nil instead of panicking - caller should check for nil UUID
		return uuid.Nil
	}
	return tenantID
}

// IPAddressKey is the key used to store IP address in context
type IPAddressKey struct{}

// UserAgentKey is the key used to store user agent in context
type UserAgentKey struct{}

// IPAddressFromContext extracts the IP address from context
func IPAddressFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value(IPAddressKey{}).(string); ok {
		return ip
	}

	// Try gRPC metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	// Common headers for IP address
	headers := []string{"x-forwarded-for", "x-real-ip", "x-client-ip"}
	for _, header := range headers {
		if values := md.Get(header); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// UserAgentFromContext extracts the user agent from context
func UserAgentFromContext(ctx context.Context) string {
	if ua, ok := ctx.Value(UserAgentKey{}).(string); ok {
		return ua
	}

	// Try gRPC metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if values := md.Get("user-agent"); len(values) > 0 {
		return values[0]
	}

	return ""
}

// ContextWithIPAddress adds the IP address to the context
func ContextWithIPAddress(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, IPAddressKey{}, ip)
}

// ContextWithUserAgent adds the user agent to the context
func ContextWithUserAgent(ctx context.Context, ua string) context.Context {
	return context.WithValue(ctx, UserAgentKey{}, ua)
}
