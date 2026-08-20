package domain

import "testing"

func TestCloneCapabilitiesDoesNotAliasInput(t *testing.T) {
	src := []Capability{CapabilityRead}
	got := CloneCapabilities(src)
	got[0] = CapabilityDelete
	if src[0] != CapabilityRead {
		t.Fatal("capability clone mutated input")
	}
}
