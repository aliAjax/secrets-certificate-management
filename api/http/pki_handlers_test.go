package httpapi

import "testing"

func TestCertificateEnvelopeHandlesNilCertificate(t *testing.T) {
	defer func() {
		if recover() != nil {
			t.Error("nil certificate panicked")
		}
	}()
	out := certificateEnvelope(nil)
	if out["status"] != "unavailable" {
		t.Fatalf("status=%v", out["status"])
	}
}
