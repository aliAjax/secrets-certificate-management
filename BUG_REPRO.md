# Bug Reproduction

Run the four targeted commands from the project root. Each exits 1:

* `TestCAReadyRequiresPrivateKeyMaterial`: `models_test.go:7: CA without key material reported ready`
* `TestValidateSigningMaterialRejectsNilKeys`: `service_test.go:7: nil signing material accepted`
* `TestInitializeCAPolicyMakesWritableMap`: `repository_test.go:11: CA policy map is nil`
* `TestCertificateEnvelopeHandlesNilCertificate`: `pki_handlers_test.go:8: nil certificate panicked`

These failures reproduce the nil-material, nil-policy, and nil-certificate paths that can panic during certificate issuance. The red evidence run made no code changes.
