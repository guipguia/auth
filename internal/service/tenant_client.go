package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TenantClient provides access to the tenant service
type TenantClient interface {
	// ValidateTenant checks if a tenant exists and is active
	ValidateTenant(ctx context.Context, tenantID uuid.UUID) (bool, error)
	// GetTenant retrieves tenant information
	GetTenant(ctx context.Context, tenantID uuid.UUID) (*TenantInfo, error)
	// GetTenantBySlug retrieves tenant by slug
	GetTenantBySlug(ctx context.Context, slug string) (*TenantInfo, error)
	// GetTenantByDomain retrieves tenant by domain
	GetTenantByDomain(ctx context.Context, domain string) (*TenantInfo, error)
	// Close closes the client connection
	Close() error
}

// TenantInfo holds basic tenant information
type TenantInfo struct {
	ID       uuid.UUID
	Name     string
	Slug     string
	Domain   string
	Status   string
	Settings map[string]interface{}
}

// TenantClientConfig holds configuration for the tenant client
type TenantClientConfig struct {
	Address string
	Timeout time.Duration
}

// grpcTenantClient implements TenantClient using gRPC
type grpcTenantClient struct {
	conn    *grpc.ClientConn
	timeout time.Duration
	// client tenantv1.TenantServiceClient // Will be used when tenant proto is generated
}

// NewTenantClient creates a new tenant client
func NewTenantClient(cfg *TenantClientConfig) (TenantClient, error) {
	if cfg.Address == "" {
		// Return a no-op client if tenant service is not configured
		return &noopTenantClient{}, nil
	}

	conn, err := grpc.NewClient(
		cfg.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to tenant service: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &grpcTenantClient{
		conn:    conn,
		timeout: timeout,
		// client: tenantv1.NewTenantServiceClient(conn),
	}, nil
}

func (c *grpcTenantClient) ValidateTenant(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp := &validateTenantResponse{}
	err := c.conn.Invoke(ctx, "/tenant.v1.TenantService/ValidateTenant",
		&validateTenantRequest{Id: tenantID.String()},
		resp)
	if err != nil {
		return false, fmt.Errorf("failed to validate tenant: %w", err)
	}

	return resp.Valid && resp.Active, nil
}

func (c *grpcTenantClient) GetTenant(ctx context.Context, tenantID uuid.UUID) (*TenantInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp := &getTenantResponse{}
	err := c.conn.Invoke(ctx, "/tenant.v1.TenantService/GetTenant",
		&getTenantRequest{Id: tenantID.String()},
		resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	if resp.Tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	id, _ := uuid.Parse(resp.Tenant.Id)
	return &TenantInfo{
		ID:       id,
		Name:     resp.Tenant.Name,
		Slug:     resp.Tenant.Slug,
		Domain:   resp.Tenant.Domain,
		Status:   resp.Tenant.Status,
		Settings: nil, // Settings would need to be parsed from Struct
	}, nil
}

func (c *grpcTenantClient) GetTenantBySlug(ctx context.Context, slug string) (*TenantInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp := &getTenantBySlugResponse{}
	err := c.conn.Invoke(ctx, "/tenant.v1.TenantService/GetTenantBySlug",
		&getTenantBySlugRequest{Slug: slug},
		resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by slug: %w", err)
	}

	if resp.Tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	id, _ := uuid.Parse(resp.Tenant.Id)
	return &TenantInfo{
		ID:       id,
		Name:     resp.Tenant.Name,
		Slug:     resp.Tenant.Slug,
		Domain:   resp.Tenant.Domain,
		Status:   resp.Tenant.Status,
		Settings: nil,
	}, nil
}

func (c *grpcTenantClient) GetTenantByDomain(ctx context.Context, domain string) (*TenantInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	resp := &getTenantByDomainResponse{}
	err := c.conn.Invoke(ctx, "/tenant.v1.TenantService/GetTenantByDomain",
		&getTenantByDomainRequest{Domain: domain},
		resp)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant by domain: %w", err)
	}

	if resp.Tenant == nil {
		return nil, fmt.Errorf("tenant not found")
	}

	id, _ := uuid.Parse(resp.Tenant.Id)
	return &TenantInfo{
		ID:       id,
		Name:     resp.Tenant.Name,
		Slug:     resp.Tenant.Slug,
		Domain:   resp.Tenant.Domain,
		Status:   resp.Tenant.Status,
		Settings: nil,
	}, nil
}

func (c *grpcTenantClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// noopTenantClient is a no-op implementation when tenant service is not configured
type noopTenantClient struct{}

func (c *noopTenantClient) ValidateTenant(ctx context.Context, tenantID uuid.UUID) (bool, error) {
	// Always return true when tenant service is not configured
	return true, nil
}

func (c *noopTenantClient) GetTenant(ctx context.Context, tenantID uuid.UUID) (*TenantInfo, error) {
	return nil, fmt.Errorf("tenant service not configured")
}

func (c *noopTenantClient) GetTenantBySlug(ctx context.Context, slug string) (*TenantInfo, error) {
	return nil, fmt.Errorf("tenant service not configured")
}

func (c *noopTenantClient) GetTenantByDomain(ctx context.Context, domain string) (*TenantInfo, error) {
	return nil, fmt.Errorf("tenant service not configured")
}

func (c *noopTenantClient) Close() error {
	return nil
}

// Message types for gRPC calls (matching tenant.proto)

type validateTenantRequest struct {
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (m *validateTenantRequest) Reset()         { *m = validateTenantRequest{} }
func (m *validateTenantRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *validateTenantRequest) ProtoMessage()  {}

type validateTenantResponse struct {
	Valid  bool `protobuf:"varint,1,opt,name=valid,proto3" json:"valid,omitempty"`
	Active bool `protobuf:"varint,2,opt,name=active,proto3" json:"active,omitempty"`
}

func (m *validateTenantResponse) Reset()         { *m = validateTenantResponse{} }
func (m *validateTenantResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *validateTenantResponse) ProtoMessage()  {}

type getTenantRequest struct {
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (m *getTenantRequest) Reset()         { *m = getTenantRequest{} }
func (m *getTenantRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantRequest) ProtoMessage()  {}

type getTenantResponse struct {
	Tenant *tenantProto `protobuf:"bytes,1,opt,name=tenant,proto3" json:"tenant,omitempty"`
}

func (m *getTenantResponse) Reset()         { *m = getTenantResponse{} }
func (m *getTenantResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantResponse) ProtoMessage()  {}

type getTenantBySlugRequest struct {
	Slug string `protobuf:"bytes,1,opt,name=slug,proto3" json:"slug,omitempty"`
}

func (m *getTenantBySlugRequest) Reset()         { *m = getTenantBySlugRequest{} }
func (m *getTenantBySlugRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantBySlugRequest) ProtoMessage()  {}

type getTenantBySlugResponse struct {
	Tenant *tenantProto `protobuf:"bytes,1,opt,name=tenant,proto3" json:"tenant,omitempty"`
}

func (m *getTenantBySlugResponse) Reset()         { *m = getTenantBySlugResponse{} }
func (m *getTenantBySlugResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantBySlugResponse) ProtoMessage()  {}

type getTenantByDomainRequest struct {
	Domain string `protobuf:"bytes,1,opt,name=domain,proto3" json:"domain,omitempty"`
}

func (m *getTenantByDomainRequest) Reset()         { *m = getTenantByDomainRequest{} }
func (m *getTenantByDomainRequest) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantByDomainRequest) ProtoMessage()  {}

type getTenantByDomainResponse struct {
	Tenant *tenantProto `protobuf:"bytes,1,opt,name=tenant,proto3" json:"tenant,omitempty"`
}

func (m *getTenantByDomainResponse) Reset()         { *m = getTenantByDomainResponse{} }
func (m *getTenantByDomainResponse) String() string { return fmt.Sprintf("%+v", *m) }
func (m *getTenantByDomainResponse) ProtoMessage()  {}

type tenantProto struct {
	Id     string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name   string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Slug   string `protobuf:"bytes,3,opt,name=slug,proto3" json:"slug,omitempty"`
	Domain string `protobuf:"bytes,4,opt,name=domain,proto3" json:"domain,omitempty"`
	Status string `protobuf:"bytes,5,opt,name=status,proto3" json:"status,omitempty"`
}

func (m *tenantProto) Reset()         { *m = tenantProto{} }
func (m *tenantProto) String() string { return fmt.Sprintf("%+v", *m) }
func (m *tenantProto) ProtoMessage()  {}
