# Bug Reproduction

Run `go test -race ./api/grpc -run '^TestRequestSnapshotIsolated$' -count=1` from the project root. It exits 1 with `WARNING: DATA RACE`, repeated `request fences missing`, `request state was shared`, and `testing.go:1398: race detected during execution of test`.

The race evidence shows concurrent requests sharing mutable maps and nested metadata. The red evidence run made no code changes.
