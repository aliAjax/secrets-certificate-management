package domain

import (
	"fmt"
	"testing"
)

func TestIsChainConflictRecognizesWrappedError(t *testing.T) {
	if !IsChainConflict(fmt.Errorf("append audit event: %w", ErrChainConflict)) {
		t.Fatal("wrapped chain conflict was not recognized")
	}
}
