package cli

import (
	"errors"
	"fmt"
)

var ErrForbidden = errors.New("forbidden")

type HTTPStatusError struct {
	StatusCode int
	Status     string
	Body       string
	RequestID  string
	RetryAfter string
	Kind       string
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("server returned %s: %s", e.Status, e.Body)
}

func (e *HTTPStatusError) Is(target error) bool {
	return target == ErrForbidden && e.Kind == "forbidden"
}
func (e *HTTPStatusError) Temporary() bool { return e.Kind == "rate_limited" || e.Kind == "server_error" }
