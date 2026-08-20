# Bug Reproduction

Run the four targeted commands from the project root. Each exits 1:

* `TestCloneCapabilitiesDoesNotAliasInput`: `models_test.go:10: capability clone mutated input`
* `TestCloneConditionsDoesNotShareMap`: `service_test.go:10: condition clone mutated input`
* `TestPolicyForStorageOwnsNestedData`: `repository_test.go:14: stored policy aliases caller data`
* `TestRequestConditionsAreDetached`: `policies_test.go:10: request conditions share storage`

The failures reproduce nested slice/map aliasing across policy creation, persistence, and HTTP request handling. The red evidence run made no code changes.
