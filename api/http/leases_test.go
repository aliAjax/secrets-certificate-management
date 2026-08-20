package httpapi

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestLeaseRequestContextKeepsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("POST", "/v1/leases/id/renew", nil).WithContext(ctx)
	select {
	case <-leaseRequestContext(r).Done():
	default:
		t.Fatal("handler discarded canceled context")
	}
}
