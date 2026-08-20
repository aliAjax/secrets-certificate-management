package postgres

import (
	policydomain "github.com/example/secrets-cert-platform/internal/policy/domain"
	"testing"
)

func TestPolicyForStorageOwnsNestedData(t *testing.T) {
	src := policydomain.Policy{Capabilities: []policydomain.Capability{policydomain.CapabilityRead}, Conditions: map[string]string{"method": "GET"}}
	got := policyForStorage(src)
	got.Capabilities[0] = policydomain.CapabilityDelete
	got.Conditions["method"] = "POST"
	if src.Capabilities[0] != policydomain.CapabilityRead || src.Conditions["method"] != "GET" {
		t.Fatal("stored policy aliases caller data")
	}
}
