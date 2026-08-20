package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

var ErrSecretNotFound = errors.New("secret not found")

func IsSecretNotFound(err error) bool { return errors.Is(err, ErrSecretNotFound) }

type SecretType string

const (
	SecretTypeStatic  SecretType = "static"
	SecretTypeDynamic SecretType = "dynamic"
	SecretTypeKV      SecretType = "kv"
)

type VersionState string

const (
	VersionStateActive    VersionState = "active"
	VersionStateDeleted   VersionState = "deleted"
	VersionStateDestroyed VersionState = "destroyed"
)

type Namespace struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Secret struct {
	ID             uuid.UUID  `json:"id"`
	Namespace      string     `json:"namespace"`
	Path           string     `json:"path"`
	Type           SecretType `json:"type"`
	CurrentVersion int64      `json:"current_version"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

type SecretVersion struct {
	ID             uuid.UUID    `json:"id"`
	SecretID       uuid.UUID    `json:"secret_id"`
	Version        int64        `json:"version"`
	EncryptedValue []byte       `json:"-"`
	ValueSHA256    []byte       `json:"-"`
	KeyVersion     string       `json:"key_version"`
	State          VersionState `json:"state"`
	DeleteAfter    *time.Time   `json:"delete_after,omitempty"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
}

type CreateNamespaceInput struct {
	Name        string
	Description string
}

type PutSecretInput struct {
	Namespace string
	Path      string
	Type      SecretType
	Value     []byte
}

type VersionMetadata struct {
	ID          uuid.UUID    `json:"id"`
	Version     int64        `json:"version"`
	State       VersionState `json:"state"`
	KeyVersion  string       `json:"key_version"`
	CreatedAt   time.Time    `json:"created_at"`
	DeleteAfter *time.Time   `json:"delete_after,omitempty"`
}

func NormalizeNamespace(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("namespace is required")
	}
	if strings.ContainsAny(name, "/ \t\r\n") {
		return "", fmt.Errorf("namespace cannot contain path separators or whitespace")
	}
	return name, nil
}

func NormalizePath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("secret path is required")
	}
	if !strings.HasPrefix(path, "/") {
		return "", fmt.Errorf("secret path must start with /")
	}
	if strings.Contains(path, "..") || strings.Contains(path, "\\") {
		return "", fmt.Errorf("secret path contains invalid sequence")
	}
	cleaned := "/" + strings.Trim(path, "/")
	return cleaned, nil
}

func ValidateType(value string) (SecretType, error) {
	switch SecretType(strings.ToLower(value)) {
	case SecretTypeStatic, SecretTypeDynamic, SecretTypeKV:
		return SecretType(strings.ToLower(value)), nil
	default:
		return "", fmt.Errorf("unsupported secret type")
	}
}

func ValidateVersionState(value string) (VersionState, error) {
	switch VersionState(value) {
	case VersionStateActive, VersionStateDeleted, VersionStateDestroyed:
		return VersionState(value), nil
	default:
		return "", fmt.Errorf("unsupported version state")
	}
}
