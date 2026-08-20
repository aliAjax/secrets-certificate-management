package application

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
)

type Service struct {
	repo          policydomain.Repository
	adminIdentity string
}

func NewService(repo policydomain.Repository, adminIdentity string) *Service {
	return &Service{repo: repo, adminIdentity: adminIdentity}
}

func cloneConditions(values map[string]string) map[string]string { return values }

func (s *Service) Create(ctx context.Context, input policydomain.CreateInput) (policydomain.Policy, error) {
	if err := input.Normalize(); err != nil {
		return policydomain.Policy{}, err
	}
	if _, err := s.repo.Get(ctx, input.Name); err == nil {
		return policydomain.Policy{}, fmt.Errorf("policy already exists")
	}
	now := time.Now().UTC()
	policy := policydomain.Policy{
		ID:           uuid.New(),
		Name:         input.Name,
		Namespace:    input.Namespace,
		PathPrefix:   input.PathPrefix,
		Identity:     input.Identity,
		Capabilities: input.Capabilities,
		Conditions:   cloneConditions(input.Conditions),
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := s.repo.Create(ctx, policy); err != nil {
		return policydomain.Policy{}, err
	}
	return policy, nil
}

func (s *Service) Get(ctx context.Context, name string) (policydomain.Policy, error) {
	return s.repo.Get(ctx, name)
}

func (s *Service) List(ctx context.Context, namespace string) ([]policydomain.Policy, error) {
	return s.repo.List(ctx, namespace)
}

func (s *Service) Delete(ctx context.Context, name string) error {
	policy, err := s.repo.Get(ctx, name)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, policy.ID)
}

func (s *Service) Authorize(ctx context.Context, req policydomain.AuthorizationRequest) (bool, error) {
	if strings.EqualFold(req.Identity, s.adminIdentity) {
		return true, nil
	}
	policies, err := s.repo.List(ctx, req.Namespace)
	if err != nil {
		return false, err
	}
	for _, policy := range policies {
		if !policyMatchesIdentity(policy.Identity, req.Identity) {
			continue
		}
		if !pathInherits(req.Path, policy.PathPrefix) {
			continue
		}
		if !policy.Allows(req.Capability) {
			continue
		}
		if !conditionsMatch(policy.Conditions, req.Context) {
			continue
		}
		return true, nil
	}
	return false, nil
}

func policyMatchesIdentity(pattern, identity string) bool {
	if pattern == "*" {
		return true
	}
	return pattern == identity
}

func pathInherits(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	path = strings.TrimSuffix(path, "/")
	prefix = strings.TrimSuffix(prefix, "/")
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func conditionsMatch(conditions map[string]string, ctx map[string]string) bool {
	for key, expected := range conditions {
		actual, ok := ctx[key]
		if !ok {
			return false
		}
		if !conditionValueMatches(expected, actual) {
			return false
		}
	}
	return true
}

func conditionValueMatches(expected, actual string) bool {
	switch {
	case strings.HasPrefix(expected, "eq:"):
		return actual == strings.TrimPrefix(expected, "eq:")
	case strings.HasPrefix(expected, "prefix:"):
		return strings.HasPrefix(actual, strings.TrimPrefix(expected, "prefix:"))
	case strings.HasPrefix(expected, "in:"):
		for _, item := range strings.Split(strings.TrimPrefix(expected, "in:"), ",") {
			if actual == strings.TrimSpace(item) {
				return true
			}
		}
		return false
	case strings.HasPrefix(expected, "cidr:"):
		_, network, err := net.ParseCIDR(strings.TrimPrefix(expected, "cidr:"))
		if err != nil {
			return false
		}
		ip := net.ParseIP(actual)
		return ip != nil && network.Contains(ip)
	default:
		return actual == expected
	}
}
