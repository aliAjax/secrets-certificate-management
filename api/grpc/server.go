package grpcapi

import (
	"context"
	"log/slog"
	"net"

	"google.golang.org/grpc"

	auditapplication "github.com/example/secrets-cert-platform/internal/audit/application"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
	leaseapplication "github.com/example/secrets-cert-platform/internal/lease/application"
	pkiapplication "github.com/example/secrets-cert-platform/internal/pki/application"
	"github.com/example/secrets-cert-platform/internal/platform/config"
	policyapplication "github.com/example/secrets-cert-platform/internal/policy/application"
	secretapplication "github.com/example/secrets-cert-platform/internal/secret/application"
)

type Server struct {
	config config.Config
	logger *slog.Logger
	secret *secretapplication.Service
	lease  *leaseapplication.Service
	policy *policyapplication.Service
	audit  *auditapplication.Service
	pki    *pkiapplication.Service
	crypto *cryptoapplication.Service
}

func NewServer(
	cfg config.Config,
	logger *slog.Logger,
	secret *secretapplication.Service,
	lease *leaseapplication.Service,
	policy *policyapplication.Service,
	audit *auditapplication.Service,
	pki *pkiapplication.Service,
	crypto *cryptoapplication.Service,
) *Server {
	return &Server{config: cfg, logger: logger, secret: secret, lease: lease, policy: policy, audit: audit, pki: pki, crypto: crypto}
}

func (s *Server) Serve(listener net.Listener) error {
	server := s.Build()
	return server.Serve(listener)
}

func (s *Server) Build() *grpc.Server {
	server := grpc.NewServer(
		grpc.ForceServerCodec(jsonCodec{}),
		grpc.ChainUnaryInterceptor(s.authInterceptor),
	)
	server.RegisterService(&platformServiceDesc, &platformService{server: s})
	return server
}

type platformService struct {
	server *Server
}

func handlerFence(req map[string]interface{}) map[string]interface{} { return req }

type platformServiceServer interface{}

var platformServiceDesc = grpc.ServiceDesc{
	ServiceName: "platform.Gateway",
	HandlerType: (*platformServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		method("CreateNamespace"),
		method("PutSecret"),
		method("GetSecret"),
		method("ListSecrets"),
		method("ListVersions"),
		method("SoftDeleteVersion"),
		method("RestoreVersion"),
		method("DestroyVersion"),
		method("RollbackVersion"),
		method("CreateLease"),
		method("RenewLease"),
		method("RevokeLease"),
		method("CreatePolicy"),
		method("ListPolicies"),
		method("DeletePolicy"),
		method("ListAudit"),
		method("VerifyAudit"),
		method("CreateRootCA"),
		method("CreateIntermediateCA"),
		method("IssueCertificate"),
		method("RenewCertificate"),
		method("RevokeCertificate"),
		method("GetCRL"),
		method("GetOCSP"),
		method("Encrypt"),
		method("Decrypt"),
		method("Sign"),
		method("Verify"),
		method("DeriveKey"),
		method("Random"),
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "platform.proto",
}

func method(name string) grpc.MethodDesc {
	return grpc.MethodDesc{
		MethodName: name,
		Handler:    methodHandler(name),
	}
}

func methodHandler(name string) func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	return func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
		in := map[string]interface{}{}
		if err := dec(&in); err != nil {
			return nil, err
		}
		in = handlerFence(in)
		fullMethod := "/platform.Gateway/" + name
		info := &grpc.UnaryServerInfo{Server: srv, FullMethod: fullMethod}
		handler := func(ctx context.Context, req interface{}) (interface{}, error) {
			return srv.(*platformService).call(ctx, name, req.(map[string]interface{}))
		}
		if interceptor == nil {
			return handler(ctx, in)
		}
		return interceptor(ctx, in, info, handler)
	}
}
