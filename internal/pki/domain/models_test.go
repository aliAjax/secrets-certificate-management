package domain

import "testing"

func TestCAReadyRequiresPrivateKeyMaterial(t *testing.T) {
	if (CA{CertificatePEM: "pem"}).ReadyForIssuance() {
		t.Fatal("CA without key material reported ready")
	}
}
