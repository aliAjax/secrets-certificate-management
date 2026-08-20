# Bug Reproduction

Run the four targeted commands from the project root. Each exits 1:

* `TestContextErrorSeesCancellation`: `models_test.go:13: cancellation ignored`
* `TestRenewalContextKeepsDeadline`: `service_test.go:14: renewal discarded request context`
* `TestCanceledStorageContextIsPreserved`: `repository_test.go:14: repository replaced canceled context`
* `TestLeaseRequestContextKeepsCancellation`: `leases_test.go:16: handler discarded canceled context`

The failures show cancellation and deadlines being discarded at the domain, application, storage, and HTTP boundaries. This is a diagnosis task; the red evidence run made no code changes.
