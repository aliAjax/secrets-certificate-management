package config

import "time"

func durationPtr(d time.Duration) *time.Duration {
	return &d
}
