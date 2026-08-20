package application

import "testing"

func TestValidateSigningMaterialRejectsNilKeys(t *testing.T) {
	if validateSigningMaterial(nil, nil, nil) == nil {
		t.Fatal("nil signing material accepted")
	}
}
