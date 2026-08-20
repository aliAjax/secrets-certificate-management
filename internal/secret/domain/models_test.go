package domain

import (
	"fmt"
	"testing"
)

func TestIsSecretNotFoundRecognizesNestedError(t *testing.T) {
	if !IsSecretNotFound(fmt.Errorf("read failed: %w", ErrSecretNotFound)) {
		t.Fatal("nested not-found error was not recognized")
	}
}
