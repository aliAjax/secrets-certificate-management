# Bug Reproduction

Run `go test ./internal/platform/config -run '^TestLoadDoesNotReuseEnvironment$' -count=1` from the project root. It exits 1:

`config_test.go:23: environment leaked: first= :19090  second= :19090`

The second configuration load retains the address from the first environment-backed load, reproducing cross-load state leakage. The red evidence run made no code changes.
