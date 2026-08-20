package config

import (
	"os"
	"strings"
	"time"
)

// envValue returns the environment variable for key with leading and trailing
// whitespace removed. It reads the live environment on every call rather than
// caching, so a variable cleared between Load calls is not retained from an
// earlier load — the process environment is the single source of truth, and
// each Load is isolated from the environment state of any other.
func envValue(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

// durationValue parses the environment variable for key as a time.Duration.
// It returns ok=false when the variable is unset or cannot be parsed.
func durationValue(key string) (time.Duration, bool) {
	raw := envValue(key)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	return d, err == nil
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}
