package domain

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Capability string

const (
	CapabilityRead   Capability = "read"
	CapabilityCreate Capability = "create"
	CapabilityUpdate Capability = "update"
	CapabilityDelete Capability = "delete"
	CapabilityList   Capability = "list"
)

type Policy struct {
	ID           uuid.UUID         `json:"id"`
	Name         string            `json:"name"`
	Namespace    string            `json:"namespace"`
	PathPrefix   string            `json:"path_prefix"`
	Identity     string            `json:"identity"`
	Capabilities []Capability      `json:"capabilities"`
	Conditions   map[string]string `json:"conditions"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

type CreateInput struct {
	Name         string
	Namespace    string
	PathPrefix   string
	Identity     string
	Capabilities []Capability
	Conditions   map[string]string
}

type AuthorizationRequest struct {
	Identity   string
	Namespace  string
	Path       string
	Capability Capability
	Context    map[string]string
}

func CloneCapabilities(values []Capability) []Capability { return values }

func ValidateCapability(value string) (Capability, error) {
	switch Capability(value) {
	case CapabilityRead, CapabilityCreate, CapabilityUpdate, CapabilityDelete, CapabilityList:
		return Capability(value), nil
	default:
		return "", fmt.Errorf("unsupported capability")
	}
}

func (i *CreateInput) Normalize() error {
	i.Name = strings.TrimSpace(i.Name)
	i.Namespace = strings.TrimSpace(i.Namespace)
	i.PathPrefix = strings.TrimSpace(i.PathPrefix)
	i.Identity = strings.TrimSpace(i.Identity)
	if i.Name == "" || i.Namespace == "" || i.Identity == "" {
		return fmt.Errorf("name, namespace and identity are required")
	}
	if !strings.HasPrefix(i.PathPrefix, "/") {
		return fmt.Errorf("path_prefix must start with /")
	}
	if len(i.Capabilities) == 0 {
		return fmt.Errorf("at least one capability is required")
	}
	i.Capabilities = CloneCapabilities(i.Capabilities)
	if i.Conditions == nil {
		i.Conditions = map[string]string{}
	}
	return nil
}

func (p Policy) Allows(capability Capability) bool {
	for _, c := range p.Capabilities {
		if c == capability {
			return true
		}
	}
	return false
}
