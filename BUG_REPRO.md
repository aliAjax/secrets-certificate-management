# Bug Reproduction

Run the three targeted commands from the project root. Each exits 1:

* `TestSlidingWindowLimiterPerClient`: `middleware_test.go:14: different client should have its own burst`
* `TestSlidingWindowLimiterWindowIsolation`: `middleware_test.go:24: another client must not inherit alpha's count`
* `TestRateLimitKeyUsesFirstForwardedClient`: `middleware_test.go:32: rate limit key = "192.0.2.1:1234", want "tenant-a"`

The failures reproduce shared limiter windows and incorrect forwarded-client identity selection. The red evidence run made no code changes.
