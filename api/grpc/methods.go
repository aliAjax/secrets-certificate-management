package grpcapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	auditdomain "github.com/example/secrets-cert-platform/internal/audit/domain"
	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
	leasedomain "github.com/example/secrets-cert-platform/internal/lease/domain"
	pkidomain "github.com/example/secrets-cert-platform/internal/pki/domain"
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
	secretdomain "github.com/example/secrets-cert-platform/internal/secret/domain"
)

func (s *platformService) call(ctx context.Context, method string, req map[string]interface{}) (interface{}, error) {
	switch method {
	case "CreateNamespace":
		return s.createNamespace(ctx, req)
	case "PutSecret":
		return s.putSecret(ctx, req)
	case "GetSecret":
		return s.getSecret(ctx, req)
	case "ListSecrets":
		return s.listSecrets(ctx, req)
	case "ListVersions":
		return s.listVersions(ctx, req)
	case "SoftDeleteVersion":
		return s.softDeleteVersion(ctx, req)
	case "RestoreVersion":
		return s.restoreVersion(ctx, req)
	case "DestroyVersion":
		return s.destroyVersion(ctx, req)
	case "RollbackVersion":
		return s.rollbackVersion(ctx, req)
	case "CreateLease":
		return s.createLease(ctx, req)
	case "RenewLease":
		return s.renewLease(ctx, req)
	case "RevokeLease":
		return s.revokeLease(ctx, req)
	case "CreatePolicy":
		return s.createPolicy(ctx, req)
	case "ListPolicies":
		return s.listPolicies(ctx, req)
	case "DeletePolicy":
		return s.deletePolicy(ctx, req)
	case "ListAudit":
		return s.listAudit(ctx, req)
	case "VerifyAudit":
		return s.verifyAudit(ctx, req)
	case "CreateRootCA":
		return s.createRootCA(ctx, req)
	case "CreateIntermediateCA":
		return s.createIntermediateCA(ctx, req)
	case "IssueCertificate":
		return s.issueCertificate(ctx, req)
	case "RenewCertificate":
		return s.renewCertificate(ctx, req)
	case "RevokeCertificate":
		return s.revokeCertificate(ctx, req)
	case "GetCRL":
		return s.getCRL(ctx, req)
	case "GetOCSP":
		return s.getOCSP(ctx, req)
	case "Encrypt":
		return s.encrypt(ctx, req)
	case "Decrypt":
		return s.decrypt(ctx, req)
	case "Sign":
		return s.sign(ctx, req)
	case "Verify":
		return s.verify(ctx, req)
	case "DeriveKey":
		return s.deriveKey(ctx, req)
	case "Random":
		return s.random(ctx, req)
	default:
		return nil, status.Errorf(codes.Unimplemented, "unknown method %s", method)
	}
}

func requestSnapshot(req map[string]interface{}) map[string]interface{} {
	return snapshotFence(handlerFence(req))
}

func (s *platformService) authorize(ctx context.Context, namespace, path string, capability policydomain.Capability) error {
	allowed, err := s.server.policy.Authorize(ctx, policydomain.AuthorizationRequest{
		Identity:   actorFromContext(ctx),
		Namespace:  namespace,
		Path:       path,
		Capability: capability,
		Context:    map[string]string{"grpc": "true"},
	})
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}
	if !allowed {
		return status.Error(codes.PermissionDenied, "forbidden")
	}
	return nil
}

func (s *platformService) audit(ctx context.Context, namespace, path, action, result string, metadata map[string]string) {
	if s.server.audit == nil {
		return
	}
	_, _ = s.server.audit.Record(ctx, auditdomain.RecordInput{
		Actor:     actorFromContext(ctx),
		Namespace: namespace,
		Path:      path,
		Action:    action,
		Result:    result,
		Metadata:  metadata,
	})
}

func (s *platformService) createNamespace(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	name := strValue(req, "name")
	desc := strValue(req, "description")
	if err := s.authorize(ctx, name, "/", policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	ns, err := s.server.secret.CreateNamespace(ctx, name, desc)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, ns.Name, "/", "namespace.create", "success", map[string]string{"namespace": ns.Name})
	return ns, nil
}

func (s *platformService) putSecret(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	metadata, err := s.server.secret.PutSecret(ctx, secretdomain.PutSecretInput{
		Namespace: namespace,
		Path:      path,
		Type:      secretdomain.SecretType(strValue(req, "type")),
		Value:     []byte(strValue(req, "value")),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.create", "success", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	return metadata, nil
}

func (s *platformService) getSecret(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityRead); err != nil {
		return nil, err
	}
	value, metadata, err := s.server.secret.GetSecret(ctx, namespace, path, int64Value(req, "version"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.read", "success", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	return map[string]interface{}{"value": string(value), "version": metadata.Version, "state": metadata.State}, nil
}

func (s *platformService) listSecrets(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityList); err != nil {
		return nil, err
	}
	secrets, err := s.server.secret.ListSecrets(ctx, namespace)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.audit(ctx, namespace, "/", "secret.list", "success", map[string]string{"count": strconv.Itoa(len(secrets))})
	return secrets, nil
}

func (s *platformService) listVersions(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityRead); err != nil {
		return nil, err
	}
	versions, err := s.server.secret.ListVersions(ctx, namespace, path)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.versions.list", "success", map[string]string{"count": strconv.Itoa(len(versions))})
	return versions, nil
}

func (s *platformService) softDeleteVersion(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityDelete); err != nil {
		return nil, err
	}
	metadata, err := s.server.secret.SoftDeleteVersion(ctx, namespace, path, int64Value(req, "version"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.version.delete", "success", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	return metadata, nil
}

func (s *platformService) restoreVersion(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityUpdate); err != nil {
		return nil, err
	}
	metadata, err := s.server.secret.RestoreVersion(ctx, namespace, path, int64Value(req, "version"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.version.restore", "success", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	return metadata, nil
}

func (s *platformService) destroyVersion(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityDelete); err != nil {
		return nil, err
	}
	version := int64Value(req, "version")
	if err := s.server.secret.DestroyVersion(ctx, namespace, path, version); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.version.destroy", "success", map[string]string{"version": strconv.FormatInt(version, 10)})
	return map[string]bool{"destroyed": true}, nil
}

func (s *platformService) rollbackVersion(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityUpdate); err != nil {
		return nil, err
	}
	metadata, err := s.server.secret.Rollback(ctx, namespace, path, int64Value(req, "version"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "secret.version.rollback", "success", map[string]string{"version": strconv.FormatInt(metadata.Version, 10)})
	return metadata, nil
}

func (s *platformService) createLease(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	path := normalizePath(strValue(req, "path"))
	if err := s.authorize(ctx, namespace, path, policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	lease, err := s.server.lease.Create(ctx, leasedomain.CreateInput{
		Namespace: namespace,
		Path:      path,
		TTL:       ttl,
		Renewable: boolValue(req, "renewable"),
		Metadata:  stringMap(req["metadata"]),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, path, "lease.create", "success", map[string]string{"lease_id": lease.ID.String()})
	return lease, nil
}

func (s *platformService) renewLease(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	id, err := uuid.Parse(strValue(req, "id"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	lease, err := s.server.lease.Get(ctx, id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, lease.Namespace, lease.Path, policydomain.CapabilityUpdate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	renewed, err := s.server.lease.Renew(ctx, id, ttl)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, renewed.Namespace, renewed.Path, "lease.renew", "success", map[string]string{"lease_id": renewed.ID.String()})
	return renewed, nil
}

func (s *platformService) revokeLease(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	id, err := uuid.Parse(strValue(req, "id"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	lease, err := s.server.lease.Get(ctx, id)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, lease.Namespace, lease.Path, policydomain.CapabilityDelete); err != nil {
		return nil, err
	}
	revoked, err := s.server.lease.Revoke(ctx, id)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, revoked.Namespace, revoked.Path, "lease.revoke", "success", map[string]string{"lease_id": revoked.ID.String()})
	return revoked, nil
}

func (s *platformService) createPolicy(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	caps := make([]policydomain.Capability, 0)
	for _, value := range stringSlice(req["capabilities"]) {
		cap, err := policydomain.ValidateCapability(value)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		caps = append(caps, cap)
	}
	policy, err := s.server.policy.Create(ctx, policydomain.CreateInput{
		Name:         strValue(req, "name"),
		Namespace:    namespace,
		PathPrefix:   normalizePath(strValue(req, "path_prefix")),
		Identity:     strValue(req, "identity"),
		Capabilities: caps,
		Conditions:   stringMap(req["conditions"]),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, "/", "policy.create", "success", map[string]string{"policy": policy.Name})
	return policy, nil
}

func (s *platformService) listPolicies(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityList); err != nil {
		return nil, err
	}
	policies, err := s.server.policy.List(ctx, namespace)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.audit(ctx, namespace, "/", "policy.list", "success", map[string]string{"count": strconv.Itoa(len(policies))})
	return policies, nil
}

func (s *platformService) deletePolicy(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	name := strValue(req, "name")
	policy, err := s.server.policy.Get(ctx, name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, policy.Namespace, "/", policydomain.CapabilityDelete); err != nil {
		return nil, err
	}
	if err := s.server.policy.Delete(ctx, name); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, policy.Namespace, "/", "policy.delete", "success", map[string]string{"policy": policy.Name})
	return map[string]bool{"deleted": true}, nil
}

func (s *platformService) listAudit(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityList); err != nil {
		return nil, err
	}
	events, err := s.server.audit.List(ctx, auditdomain.ListFilter{
		Namespace: namespace,
		Path:      strValue(req, "path"),
		Actor:     strValue(req, "actor"),
		Action:    strValue(req, "action"),
		Limit:     intValue(req, "limit"),
	})
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.audit(ctx, namespace, "/", "audit.list", "success", map[string]string{"count": strconv.Itoa(len(events))})
	return events, nil
}

func (s *platformService) verifyAudit(ctx context.Context, _ map[string]interface{}) (interface{}, error) {
	ok, count, err := s.server.audit.Verify(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	s.audit(ctx, "*", "/", "audit.verify", "success", map[string]string{"events": strconv.Itoa(count)})
	return map[string]interface{}{"valid": ok, "events": count}, nil
}

func (s *platformService) createRootCA(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	ca, err := s.server.pki.CreateRoot(ctx, pkidomain.CreateCAInput{
		Name:       strValue(req, "name"),
		Namespace:  namespace,
		CommonName: strValue(req, "common_name"),
		TTL:        ttl,
		MaxPathLen: intValue(req, "max_path_len"),
		DNSDomains: stringSlice(req["dns_domains"]),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, "/", "pki.ca.root.create", "success", map[string]string{"ca": ca.Name})
	return ca, nil
}

func (s *platformService) createIntermediateCA(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	namespace := strValue(req, "namespace")
	if err := s.authorize(ctx, namespace, "/", policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	ca, err := s.server.pki.CreateIntermediate(ctx, pkidomain.CreateCAInput{
		Name:       strValue(req, "name"),
		Namespace:  namespace,
		ParentName: strValue(req, "parent_name"),
		CommonName: strValue(req, "common_name"),
		TTL:        ttl,
		MaxPathLen: intValue(req, "max_path_len"),
		DNSDomains: stringSlice(req["dns_domains"]),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, namespace, "/", "pki.ca.intermediate.create", "success", map[string]string{"ca": ca.Name})
	return ca, nil
}

func (s *platformService) issueCertificate(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	ca, err := s.server.pki.GetCA(ctx, strValue(req, "ca_name"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, ca.Namespace, "/", policydomain.CapabilityCreate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	cert, err := s.server.pki.Issue(ctx, pkidomain.IssueInput{
		CAName:     ca.Name,
		CommonName: strValue(req, "common_name"),
		DNSNames:   stringSlice(req["dns_names"]),
		TTL:        ttl,
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, cert.Namespace, "/", "pki.certificate.issue", "success", map[string]string{"serial": cert.SerialNumber})
	return cert, nil
}

func (s *platformService) renewCertificate(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	cert, err := s.server.pki.GetCertificate(ctx, strValue(req, "namespace"), strValue(req, "serial_number"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, cert.Namespace, "/", policydomain.CapabilityUpdate); err != nil {
		return nil, err
	}
	ttl, _ := time.ParseDuration(strValue(req, "ttl"))
	renewed, err := s.server.pki.Renew(ctx, pkidomain.RenewInput{SerialNumber: cert.SerialNumber, TTL: ttl})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, renewed.Namespace, "/", "pki.certificate.renew", "success", map[string]string{"serial": renewed.SerialNumber})
	return renewed, nil
}

func (s *platformService) revokeCertificate(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	cert, err := s.server.pki.GetCertificate(ctx, strValue(req, "namespace"), strValue(req, "serial_number"))
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, cert.Namespace, "/", policydomain.CapabilityDelete); err != nil {
		return nil, err
	}
	revocation, err := s.server.pki.Revoke(ctx, pkidomain.RevokeInput{
		SerialNumber: cert.SerialNumber,
		Reason:       strValue(req, "reason"),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, cert.Namespace, "/", "pki.certificate.revoke", "success", map[string]string{"serial": cert.SerialNumber})
	return revocation, nil
}

func (s *platformService) getCRL(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	name := strValue(req, "ca_name")
	ca, err := s.server.pki.GetCA(ctx, name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, ca.Namespace, "/", policydomain.CapabilityRead); err != nil {
		return nil, err
	}
	crl, err := s.server.pki.CRL(ctx, name)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, ca.Namespace, "/", "pki.crl.read", "success", map[string]string{"ca": name})
	return map[string]string{"crl": crl}, nil
}

func (s *platformService) getOCSP(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	name := strValue(req, "ca_name")
	serial := strValue(req, "serial")
	ca, err := s.server.pki.GetCA(ctx, name)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	if err := s.authorize(ctx, ca.Namespace, "/", policydomain.CapabilityRead); err != nil {
		return nil, err
	}
	response, err := s.server.pki.OCSP(ctx, name, serial)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, ca.Namespace, "/", "pki.ocsp.read", "success", map[string]string{"ca": name, "serial": serial})
	return map[string]string{"ocsp_response": response}, nil
}

func (s *platformService) encrypt(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	ciphertext, err := s.server.crypto.Encrypt(ctx, cryptodomain.EncryptRequest{Plaintext: []byte(strValue(req, "plaintext"))})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.encrypt", "success", nil)
	return map[string]string{"ciphertext": base64.StdEncoding.EncodeToString(ciphertext.Data), "key_version": ciphertext.KeyVersion}, nil
}

func (s *platformService) decrypt(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	data, err := base64.StdEncoding.DecodeString(strValue(req, "ciphertext"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	plaintext, err := s.server.crypto.Decrypt(ctx, cryptodomain.DecryptRequest{
		Ciphertext: backenddomain.Ciphertext{Data: data, KeyVersion: strValue(req, "key_version")},
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.decrypt", "success", nil)
	return map[string]string{"plaintext": string(plaintext)}, nil
}

func (s *platformService) sign(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	sig, err := s.server.crypto.Sign(ctx, cryptodomain.SignRequest{Data: []byte(strValue(req, "data"))})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.sign", "success", nil)
	return map[string]string{"signature": base64.StdEncoding.EncodeToString(sig.Signature), "algorithm": sig.Algorithm}, nil
}

func (s *platformService) verify(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	sig, err := base64.StdEncoding.DecodeString(strValue(req, "signature"))
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	ok, err := s.server.crypto.Verify(ctx, cryptodomain.VerifyRequest{
		Data:      []byte(strValue(req, "data")),
		Signature: backenddomain.Signature{Signature: sig, Algorithm: strValue(req, "algorithm")},
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.verify", "success", nil)
	return map[string]bool{"valid": ok}, nil
}

func (s *platformService) deriveKey(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	derived, err := s.server.crypto.DeriveKey(ctx, cryptodomain.DeriveRequest{
		Material: []byte(strValue(req, "material")),
		Salt:     []byte(strValue(req, "salt")),
		Length:   intValue(req, "length"),
	})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.derive", "success", nil)
	return map[string]string{"derived": base64.StdEncoding.EncodeToString(derived)}, nil
}

func (s *platformService) random(ctx context.Context, req map[string]interface{}) (interface{}, error) {
	random, err := s.server.crypto.Random(ctx, cryptodomain.RandomRequest{Length: intValue(req, "length")})
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	s.audit(ctx, "*", "/crypto", "crypto.random", "success", nil)
	return map[string]string{"random": base64.StdEncoding.EncodeToString(random)}, nil
}

func strValue(m map[string]interface{}, key string) string {
	value, _ := m[key].(string)
	return value
}

func intValue(m map[string]interface{}, key string) int {
	switch value := m[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	case json.Number:
		n, _ := value.Int64()
		return int(n)
	default:
		return 0
	}
}

func int64Value(m map[string]interface{}, key string) int64 {
	return int64(intValue(m, key))
}

func boolValue(m map[string]interface{}, key string) bool {
	value, _ := m[key].(bool)
	return value
}

func stringSlice(value interface{}) []string {
	if value == nil {
		return nil
	}
	items, ok := value.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func stringMap(value interface{}) map[string]string {
	if value == nil {
		return nil
	}
	raw, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	out := make(map[string]string, len(raw))
	for key, item := range raw {
		out[key] = fmt.Sprint(item)
	}
	return out
}

func normalizePath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		path = "/" + path
	}
	for len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	return path
}
