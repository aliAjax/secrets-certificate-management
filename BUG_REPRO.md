# Bug Reproduction

Run the four targeted `go test` commands from the project root. Each exits 1:

* `TestIsSecretNotFoundRecognizesNestedError`: `models_test.go:10: nested not-found error was not recognized`
* `TestServiceReadPreservesNotFound`: `service_test.go:12: service lost not-found category`
* `TestRepositoryNotFoundWrap`: `repository_test.go:12: repository lost not-found sentinel`
* `TestSecretReadNotFoundMapsTo404`: `secrets_test.go:13: status=500 want=404`

The four failures show that a not-found error is lost across domain, application, storage, and HTTP boundaries. The red evidence run made no code changes.
