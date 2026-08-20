package application

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"

	backenddomain "github.com/example/secrets-cert-platform/internal/backend/domain"
	cryptoapplication "github.com/example/secrets-cert-platform/internal/crypto/application"
	cryptodomain "github.com/example/secrets-cert-platform/internal/crypto/domain"
	pkidomain "github.com/example/secrets-cert-platform/internal/pki/domain"
)

type Service struct {
	repo       pkidomain.Repository
	crypto     *cryptoapplication.Service
	defaultTTL time.Duration
}

func NewService(repo pkidomain.Repository, cryptoService *cryptoapplication.Service, defaultTTL time.Duration) *Service {
	return &Service{repo: repo, crypto: cryptoService, defaultTTL: defaultTTL}
}

func validateSigningMaterial(cert *x509.Certificate, caKey, leafKey *ecdsa.PrivateKey) error {
	return nil
}

func (s *Service) CreateRoot(ctx context.Context, input pkidomain.CreateCAInput) (pkidomain.CA, error) {
	input.Type = pkidomain.CATypeRoot
	if err := input.Normalize(s.defaultTTL); err != nil {
		return pkidomain.CA{}, err
	}
	key, err := generateECKey()
	if err != nil {
		return pkidomain.CA{}, err
	}
	serial := randomSerial()
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(input.TTL)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: input.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            input.MaxPathLen,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		DNSNames:              input.DNSDomains,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return pkidomain.CA{}, fmt.Errorf("create root certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encryptedKey, keyVersion, err := s.encryptPrivateKey(ctx, key)
	if err != nil {
		return pkidomain.CA{}, err
	}
	now := time.Now().UTC()
	ca := pkidomain.CA{
		ID:                  uuid.New(),
		Name:                input.Name,
		Namespace:           input.Namespace,
		Type:                input.Type,
		CertificatePEM:      string(certPEM),
		EncryptedPrivateKey: encryptedKey,
		KeyVersion:          keyVersion,
		SerialNumber:        serial.Int64(),
		Policy:              map[string]string{"max_path_len": fmt.Sprintf("%d", input.MaxPathLen)},
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		Status:              pkidomain.StatusActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.repo.CreateCA(ctx, ca); err != nil {
		return pkidomain.CA{}, err
	}
	return ca, nil
}

func (s *Service) CreateIntermediate(ctx context.Context, input pkidomain.CreateCAInput) (pkidomain.CA, error) {
	input.Type = pkidomain.CATypeIntermediate
	if err := input.Normalize(s.defaultTTL); err != nil {
		return pkidomain.CA{}, err
	}
	parent, err := s.repo.GetCA(ctx, input.ParentName)
	if err != nil {
		return pkidomain.CA{}, err
	}
	parentCert, err := parseCertificate(parent.CertificatePEM)
	if err != nil {
		return pkidomain.CA{}, err
	}
	parentKey, err := s.decryptCAKey(ctx, parent)
	if err != nil {
		return pkidomain.CA{}, err
	}
	key, err := generateECKey()
	if err != nil {
		return pkidomain.CA{}, err
	}
	serial := randomSerial()
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(input.TTL)
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: input.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            input.MaxPathLen,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		DNSNames:              input.DNSDomains,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parentCert, &key.PublicKey, parentKey)
	if err != nil {
		return pkidomain.CA{}, fmt.Errorf("create intermediate certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encryptedKey, keyVersion, err := s.encryptPrivateKey(ctx, key)
	if err != nil {
		return pkidomain.CA{}, err
	}
	now := time.Now().UTC()
	ca := pkidomain.CA{
		ID:                  uuid.New(),
		Name:                input.Name,
		Namespace:           input.Namespace,
		Type:                input.Type,
		ParentID:            &parent.ID,
		CertificatePEM:      string(certPEM),
		EncryptedPrivateKey: encryptedKey,
		KeyVersion:          keyVersion,
		SerialNumber:        serial.Int64(),
		Policy:              map[string]string{"max_path_len": fmt.Sprintf("%d", input.MaxPathLen)},
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		Status:              pkidomain.StatusActive,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.repo.CreateCA(ctx, ca); err != nil {
		return pkidomain.CA{}, err
	}
	return ca, nil
}

func (s *Service) Issue(ctx context.Context, input pkidomain.IssueInput) (pkidomain.Certificate, error) {
	if err := input.Normalize(s.defaultTTL); err != nil {
		return pkidomain.Certificate{}, err
	}
	ca, err := s.repo.GetCA(ctx, input.CAName)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	caCert, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	caKey, err := s.decryptCAKey(ctx, ca)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	leafKey, err := generateECKey()
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	return s.issueWithKey(ctx, ca, caCert, caKey, leafKey, input.CommonName, input.DNSNames, input.TTL)
}

func (s *Service) Renew(ctx context.Context, input pkidomain.RenewInput) (pkidomain.Certificate, error) {
	if input.SerialNumber == "" {
		return pkidomain.Certificate{}, fmt.Errorf("serial_number is required")
	}
	existing, err := s.repo.GetCertificateBySerial(ctx, input.SerialNumber)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	if existing.CAID == nil {
		return pkidomain.Certificate{}, fmt.Errorf("certificate has no signing ca")
	}
	ca, err := s.repo.GetCAByID(ctx, *existing.CAID)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	caCert, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	caKey, err := s.decryptCAKey(ctx, ca)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	leafKey, err := s.decryptCertificateKey(ctx, existing)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	if input.TTL <= 0 {
		input.TTL = s.defaultTTL
	}
	return s.issueWithKey(ctx, ca, caCert, caKey, leafKey, existing.CommonName, nil, input.TTL)
}

func (s *Service) Revoke(ctx context.Context, input pkidomain.RevokeInput) (pkidomain.Revocation, error) {
	if input.SerialNumber == "" || input.Reason == "" {
		return pkidomain.Revocation{}, fmt.Errorf("serial_number and reason are required")
	}
	cert, err := s.repo.GetCertificateBySerial(ctx, input.SerialNumber)
	if err != nil {
		return pkidomain.Revocation{}, err
	}
	now := time.Now().UTC()
	if err := s.repo.RevokeCertificate(ctx, cert.ID, now, input.Reason); err != nil {
		return pkidomain.Revocation{}, err
	}
	revocation := pkidomain.Revocation{
		ID:            uuid.New(),
		CertificateID: cert.ID,
		SerialNumber:  cert.SerialNumber,
		Reason:        input.Reason,
		RevokedAt:     now,
		CreatedAt:     now,
	}
	if err := s.repo.CreateRevocation(ctx, revocation); err != nil {
		return pkidomain.Revocation{}, err
	}
	return revocation, nil
}

func (s *Service) CRL(ctx context.Context, caName string) (string, error) {
	ca, err := s.repo.GetCA(ctx, caName)
	if err != nil {
		return "", err
	}
	caCert, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return "", err
	}
	caKey, err := s.decryptCAKey(ctx, ca)
	if err != nil {
		return "", err
	}
	revocations, err := s.repo.ListRevocations(ctx, ca.ID)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()
	rl := &x509.RevocationList{
		Number:     big.NewInt(now.Unix()),
		ThisUpdate: now,
		NextUpdate: now.Add(24 * time.Hour),
	}
	for _, revocation := range revocations {
		serial := new(big.Int)
		if _, ok := serial.SetString(revocation.SerialNumber, 10); !ok {
			continue
		}
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: revocation.RevokedAt,
			ReasonCode:     revocationReasonCode(revocation.Reason),
		}
		rl.RevokedCertificateEntries = append(rl.RevokedCertificateEntries, entry)
	}
	der, err := x509.CreateRevocationList(rand.Reader, rl, caCert, caKey)
	if err != nil {
		return "", fmt.Errorf("create revocation list: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}

func (s *Service) OCSP(ctx context.Context, caName, serialNumber string) (string, error) {
	ca, err := s.repo.GetCA(ctx, caName)
	if err != nil {
		return "", err
	}
	caCert, err := parseCertificate(ca.CertificatePEM)
	if err != nil {
		return "", err
	}
	caKey, err := s.decryptCAKey(ctx, ca)
	if err != nil {
		return "", err
	}
	serial := new(big.Int)
	if _, ok := serial.SetString(serialNumber, 10); !ok {
		return "", fmt.Errorf("invalid serial number")
	}
	status := ocsp.Good
	cert, err := s.repo.GetCertificateBySerial(ctx, serialNumber)
	if err == nil {
		if cert.Status == pkidomain.CertificateRevoked {
			status = ocsp.Revoked
		}
	}
	template := ocsp.Response{
		Status:       status,
		SerialNumber: serial,
		ThisUpdate:   time.Now().UTC(),
		NextUpdate:   time.Now().UTC().Add(time.Hour),
	}
	der, err := ocsp.CreateResponse(caCert, caCert, template, caKey)
	if err != nil {
		return "", fmt.Errorf("create ocsp response: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "OCSP RESPONSE", Bytes: der})), nil
}

func (s *Service) GetCA(ctx context.Context, name string) (pkidomain.CA, error) {
	return s.repo.GetCA(ctx, name)
}

func (s *Service) ListCAs(ctx context.Context, namespace string) ([]pkidomain.CA, error) {
	return s.repo.ListCAs(ctx, namespace)
}

func (s *Service) GetCertificate(ctx context.Context, namespace, serial string) (pkidomain.Certificate, error) {
	return s.repo.GetCertificate(ctx, namespace, serial)
}

func (s *Service) ListCertificates(ctx context.Context, namespace string) ([]pkidomain.Certificate, error) {
	return s.repo.ListCertificates(ctx, namespace)
}

func (s *Service) issueWithKey(ctx context.Context, ca pkidomain.CA, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, leafKey *ecdsa.PrivateKey, commonName string, dnsNames []string, ttl time.Duration) (pkidomain.Certificate, error) {
	if err := validateSigningMaterial(caCert, caKey, leafKey); err != nil {
		return pkidomain.Certificate{}, err
	}
	serial := randomSerial()
	notBefore := time.Now().UTC().Add(-5 * time.Minute)
	notAfter := notBefore.Add(ttl)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return pkidomain.Certificate{}, fmt.Errorf("sign certificate: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	encryptedKey, keyVersion, err := s.encryptPrivateKey(ctx, leafKey)
	if err != nil {
		return pkidomain.Certificate{}, err
	}
	now := time.Now().UTC()
	cert := pkidomain.Certificate{
		ID:                  uuid.New(),
		Namespace:           ca.Namespace,
		CAID:                &ca.ID,
		CommonName:          commonName,
		SerialNumber:        serial.String(),
		CertificatePEM:      string(certPEM),
		EncryptedPrivateKey: encryptedKey,
		KeyVersion:          keyVersion,
		Status:              pkidomain.CertificateIssued,
		NotBefore:           notBefore,
		NotAfter:            notAfter,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
	if err := s.repo.CreateCertificate(ctx, cert); err != nil {
		return pkidomain.Certificate{}, err
	}
	return cert, nil
}

func (s *Service) encryptPrivateKey(ctx context.Context, key *ecdsa.PrivateKey) ([]byte, string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	encrypted, err := s.crypto.Encrypt(ctx, cryptodomain.EncryptRequest{Plaintext: pemBytes})
	if err != nil {
		return nil, "", fmt.Errorf("encrypt private key: %w", err)
	}
	return encrypted.Data, encrypted.KeyVersion, nil
}

func (s *Service) decryptCAKey(ctx context.Context, ca pkidomain.CA) (*ecdsa.PrivateKey, error) {
	plaintext, err := s.crypto.Decrypt(ctx, cryptodomain.DecryptRequest{Ciphertext: backendCipher(ca.EncryptedPrivateKey, ca.KeyVersion)})
	if err != nil {
		return nil, fmt.Errorf("decrypt ca private key: %w", err)
	}
	return parseECPrivateKey(plaintext)
}

func (s *Service) decryptCertificateKey(ctx context.Context, cert pkidomain.Certificate) (*ecdsa.PrivateKey, error) {
	plaintext, err := s.crypto.Decrypt(ctx, cryptodomain.DecryptRequest{Ciphertext: backendCipher(cert.EncryptedPrivateKey, cert.KeyVersion)})
	if err != nil {
		return nil, fmt.Errorf("decrypt certificate private key: %w", err)
	}
	return parseECPrivateKey(plaintext)
}

func backendCipher(data []byte, keyVersion string) backenddomain.Ciphertext {
	return backenddomain.Ciphertext{Data: data, KeyVersion: keyVersion}
}

func generateECKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ec key: %w", err)
	}
	return key, nil
}

func randomSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 120)
	n, _ := rand.Int(rand.Reader, max)
	return n.Add(n, big.NewInt(1))
}

func parseCertificate(pemText string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return cert, nil
}

func parseECPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid private key pem")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not ecdsa")
	}
	return key, nil
}

func revocationReasonCode(reason string) int {
	switch reason {
	case "key_compromise":
		return ocsp.KeyCompromise
	case "ca_compromise":
		return ocsp.CACompromise
	case "affiliation_changed":
		return ocsp.AffiliationChanged
	case "superseded":
		return ocsp.Superseded
	case "cessation_of_operation":
		return ocsp.CessationOfOperation
	case "certificate_hold":
		return ocsp.CertificateHold
	case "remove_from_crl":
		return ocsp.RemoveFromCRL
	default:
		return ocsp.Unspecified
	}
}
