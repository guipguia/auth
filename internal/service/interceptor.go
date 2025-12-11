package service

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Public methods that don't require authentication
var publicMethods = map[string]bool{
	"/auth.v1.AuthService/Register":                true,
	"/auth.v1.AuthService/Login":                   true,
	"/auth.v1.AuthService/RefreshToken":            true,
	"/auth.v1.AuthService/ForgotPassword":          true,
	"/auth.v1.AuthService/ResetPassword":           true,
	"/auth.v1.AuthService/SendPasswordlessEmail":   true,
	"/auth.v1.AuthService/VerifyPasswordlessToken": true,
	"/auth.v1.AuthService/GetOAuthURL":             true,
	"/auth.v1.AuthService/OAuthCallback":           true,
	"/auth.v1.AuthService/VerifyEmail":             true,
	"/auth.v1.AuthService/ResendVerificationEmail": true,
	"/auth.v1.AuthService/GetInvitationByToken":    true,
	// Team management - authenticated via API gateway, tenant/user IDs passed in metadata
	"/auth.v1.AuthService/ListTeamMembers":        true,
	"/auth.v1.AuthService/GetTeamMember":          true,
	"/auth.v1.AuthService/InviteTeamMember":       true,
	"/auth.v1.AuthService/AcceptInvitation":       true,
	"/auth.v1.AuthService/UpdateTeamMemberRole":   true,
	"/auth.v1.AuthService/RemoveTeamMember":       true,
	"/auth.v1.AuthService/ListPendingInvitations": true,
	"/auth.v1.AuthService/CancelInvitation":       true,
	// Health check and reflection endpoints
	"/grpc.health.v1.Health/Check":                                   true,
	"/grpc.health.v1.Health/Watch":                                   true,
	"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo": true,
	"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo":      true,
}

// UnaryAuthInterceptor returns a gRPC unary interceptor for authentication
func UnaryAuthInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip authentication for public methods
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return nil, status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		// Get authorization header
		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return nil, status.Errorf(codes.Unauthenticated, "missing authorization header")
		}

		// Extract token from "Bearer <token>" format
		authHeader := authHeaders[0]
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return nil, status.Errorf(codes.Unauthenticated, "invalid authorization header format")
		}

		token := parts[1]

		// Note: In a real implementation, you would validate the token here
		// For now, we'll assume it's valid if present
		// You could inject the JWT service into the interceptor and validate it

		// Add user info to context if needed
		ctx = context.WithValue(ctx, "token", token)

		return handler(ctx, req)
	}
}

// StreamAuthInterceptor returns a gRPC stream interceptor for authentication
func StreamAuthInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip authentication for public methods
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Extract metadata from context
		md, ok := metadata.FromIncomingContext(ss.Context())
		if !ok {
			return status.Errorf(codes.Unauthenticated, "missing metadata")
		}

		// Get authorization header
		authHeaders := md.Get("authorization")
		if len(authHeaders) == 0 {
			return status.Errorf(codes.Unauthenticated, "missing authorization header")
		}

		// Extract token from "Bearer <token>" format
		authHeader := authHeaders[0]
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return status.Errorf(codes.Unauthenticated, "invalid authorization header format")
		}

		return handler(srv, ss)
	}
}
