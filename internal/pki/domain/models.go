package domain

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

type CAType string

const (
	CATypeRoot         CAType = "root"
	CATypeIntermediate CAType = "intermediate"
)

type Status string

const (
	StatusActive  Status = "active"
	StatusRevoked Status = "revoked"
	StatusExpired Status = "expired"
)

type CertificateStatus string

const (
	CertificateIssued  CertificateStatus = "issued"
	CertificateRevoked CertificateStatus = "revoked"
	CertificateExpired CertificateStatus = "expired"
)

type CA struct {
	ID                  uuid.UUID         `json:"id"`
	Name                string            `json:"name"`
	Namespace           string            `json:"namespace"`
	Type                CAType            `json:"type"`
	ParentID            *uuid.UUID        `json:"parent_id,omitempty"`
	CertificatePEM      string            `json:"certificate_pem"`
	EncryptedPrivateKey []byte            `json:"-"`
	KeyVersion          string            `json:"key_version"`
	SerialNumber        int64             `json:"serial_number"`
	Policy              map[string]string `json:"policy"`
	NotBefore           time.Time         `json:"not_before"`
	NotAfter            time.Time         `json:"not_after"`
	Status              Status            `json:"status"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

type Certificate struct {
	ID                  uuid.UUID         `json:"id"`
	Namespace           string            `json:"namespace"`
	CAID                *uuid.UUID        `json:"ca_id,omitempty"`
	CommonName          string            `json:"common_name"`
	SerialNumber        string            `json:"serial_number"`
	CertificatePEM      string            `json:"certificate_pem"`
	EncryptedPrivateKey []byte            `json:"-"`
	KeyVersion          string            `json:"key_version"`
	Status              CertificateStatus `json:"status"`
	NotBefore           time.Time         `json:"not_before"`
	NotAfter            time.Time         `json:"not_after"`
	RevokedAt           *time.Time        `json:"revoked_at,omitempty"`
	RevocationReason    string            `json:"revocation_reason,omitempty"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

type Revocation struct {
	ID            uuid.UUID `json:"id"`
	CertificateID uuid.UUID `json:"certificate_id"`
	SerialNumber  string    `json:"serial_number"`
	Reason        string    `json:"reason"`
	RevokedAt     time.Time `json:"revoked_at"`
	CreatedAt     time.Time `json:"created_at"`
}

type CreateCAInput struct {
	Name       string
	Namespace  string
	Type       CAType
	ParentName string
	CommonName string
	TTL        time.Duration
	MaxPathLen int
	DNSDomains []string
}

type IssueInput struct {
	CAName     string
	CommonName string
	DNSNames   []string
	TTL        time.Duration
}

type RenewInput struct {
	SerialNumber string
	TTL          time.Duration
}

type RevokeInput struct {
	SerialNumber string
	Reason       string
}

func (i *CreateCAInput) Normalize(defaultTTL time.Duration) error {
	if i.Name == "" || i.Namespace == "" || i.CommonName == "" {
		return fmt.Errorf("name, namespace and common_name are required")
	}
	if i.Type != CATypeRoot && i.Type != CATypeIntermediate {
		return fmt.Errorf("ca type must be root or intermediate")
	}
	if i.Type == CATypeIntermediate && i.ParentName == "" {
		return fmt.Errorf("intermediate ca requires parent_name")
	}
	if i.TTL <= 0 {
		i.TTL = defaultTTL
	}
	return nil
}

func (i *IssueInput) Normalize(defaultTTL time.Duration) error {
	if i.CAName == "" || i.CommonName == "" {
		return fmt.Errorf("ca_name and common_name are required")
	}
	if i.TTL <= 0 {
		i.TTL = defaultTTL
	}
	return nil
}
