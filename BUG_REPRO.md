# Bug Reproduction

Run `go test ./internal/cli -run '^TestClientPreservesHTTPStatusError$' -count=1` from the project root. It exits 1:

`client_test.go:21: lost status error: server returned 403 Forbidden: forbidden`

The failure shows that a rejected HTTP response is flattened and its status error is not preserved for callers. The red evidence run made no code changes.
