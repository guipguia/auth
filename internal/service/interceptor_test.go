package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Mock handler for unary interceptor tests
func mockUnaryHandler(ctx context.Context, req interface{}) (interface{}, error) {
	return "success", nil
}

// Mock stream for stream interceptor tests
type mockServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (m *mockServerStream) Context() context.Context {
	return m.ctx
}

// Mock stream handler
func mockStreamHandler(srv interface{}, stream grpc.ServerStream) error {
	return nil
}

// Test: UnaryAuthInterceptor with public method (Register)
func TestUnaryAuthInterceptor_PublicMethod_Register(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/Register",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

// Test: UnaryAuthInterceptor with public method (Login)
func TestUnaryAuthInterceptor_PublicMethod_Login(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/Login",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

// Test: UnaryAuthInterceptor with public method (ForgotPassword)
func TestUnaryAuthInterceptor_PublicMethod_ForgotPassword(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/ForgotPassword",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

// Test: UnaryAuthInterceptor with protected method and valid token
func TestUnaryAuthInterceptor_ProtectedMethod_ValidToken(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	md := metadata.Pairs("authorization", "Bearer valid-token-123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/GetUserProfile",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.NoError(t, err)
	assert.Equal(t, "success", resp)
}

// Test: UnaryAuthInterceptor with protected method and missing metadata
func TestUnaryAuthInterceptor_ProtectedMethod_MissingMetadata(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	ctx := context.Background()
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/GetUserProfile",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing metadata")
}

// Test: UnaryAuthInterceptor with protected method and missing authorization header
func TestUnaryAuthInterceptor_ProtectedMethod_MissingAuthHeader(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	md := metadata.Pairs("other-header", "value")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/GetUserProfile",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing authorization header")
}

// Test: UnaryAuthInterceptor with invalid authorization header format (no Bearer)
func TestUnaryAuthInterceptor_ProtectedMethod_InvalidHeaderFormat_NoBearer(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	md := metadata.Pairs("authorization", "invalid-token-123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/GetUserProfile",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "invalid authorization header format")
}

// Test: UnaryAuthInterceptor with invalid authorization header format (wrong scheme)
func TestUnaryAuthInterceptor_ProtectedMethod_InvalidHeaderFormat_WrongScheme(t *testing.T) {
	interceptor := UnaryAuthInterceptor()
	md := metadata.Pairs("authorization", "Basic token-123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	info := &grpc.UnaryServerInfo{
		FullMethod: "/auth.v1.AuthService/GetUserProfile",
	}

	resp, err := interceptor(ctx, nil, info, mockUnaryHandler)

	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "invalid authorization header format")
}

// Test: StreamAuthInterceptor with public method
func TestStreamAuthInterceptor_PublicMethod(t *testing.T) {
	interceptor := StreamAuthInterceptor()
	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.v1.AuthService/Login",
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)
}

// Test: StreamAuthInterceptor with protected method and valid token
func TestStreamAuthInterceptor_ProtectedMethod_ValidToken(t *testing.T) {
	interceptor := StreamAuthInterceptor()
	md := metadata.Pairs("authorization", "Bearer valid-token-123")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.v1.AuthService/StreamData",
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.NoError(t, err)
}

// Test: StreamAuthInterceptor with protected method and missing metadata
func TestStreamAuthInterceptor_ProtectedMethod_MissingMetadata(t *testing.T) {
	interceptor := StreamAuthInterceptor()
	ctx := context.Background()
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.v1.AuthService/StreamData",
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing metadata")
}

// Test: StreamAuthInterceptor with protected method and missing authorization header
func TestStreamAuthInterceptor_ProtectedMethod_MissingAuthHeader(t *testing.T) {
	interceptor := StreamAuthInterceptor()
	md := metadata.Pairs("other-header", "value")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.v1.AuthService/StreamData",
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "missing authorization header")
}

// Test: StreamAuthInterceptor with invalid authorization header format
func TestStreamAuthInterceptor_ProtectedMethod_InvalidHeaderFormat(t *testing.T) {
	interceptor := StreamAuthInterceptor()
	md := metadata.Pairs("authorization", "invalid-token")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	stream := &mockServerStream{ctx: ctx}
	info := &grpc.StreamServerInfo{
		FullMethod: "/auth.v1.AuthService/StreamData",
	}

	err := interceptor(nil, stream, info, mockStreamHandler)

	assert.Error(t, err)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
	assert.Contains(t, st.Message(), "invalid authorization header format")
}
