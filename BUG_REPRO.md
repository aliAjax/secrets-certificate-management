# Bug Reproduction

Run the three targeted commands from the project root. Each exits 1:

* `TestEncryptPreservesProviderError`: `service_test.go:36: lost provider error: encrypt: crypto provider unavailable`
* `TestProviderUnavailableIsStable`: `types_test.go:14: wrapped provider error was not classified`
* `TestSensitiveBufferClear`: `software_test.go:10: buffer not cleared`

The failures reproduce loss of the provider error category and failure to clear a sensitive temporary buffer. The red evidence run made no code changes.
