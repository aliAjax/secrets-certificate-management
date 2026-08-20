package domain

import (
	"fmt"
	"testing"
)

func TestProviderUnavailableIsStable(t *testing.T) {
	if ErrProviderUnavailable == nil {
		t.Fatal("provider sentinel missing")
	}
	wrapped := fmt.Errorf("backend request: %w", ErrProviderUnavailable)
	if !IsProviderUnavailable(wrapped) {
		t.Fatal("wrapped provider error was not classified")
	}
}
