# Bug Reproduction

Run the four commands from the project root. All four currently exit 1.

* `TestRecordRetriesChainConflict`: `service_test.go:50: record should retry chain conflict: audit chain conflict`
* `TestIsChainConflictRecognizesWrappedError`: `models_test.go:10: wrapped chain conflict was not recognized`
* `TestAuditConflictErrorWrap`: `errors_test.go:12: chain conflict sentinel was lost`
* `TestAuditAppendUsesTransactionChainLock`: `lock_test.go:10: audit append does not use a transaction-scoped chain lock`

The failures reproduce the concurrent audit append chain-conflict, wrapped-error classification, and transaction-lock behavior described in the task. The red evidence run made no code changes.
