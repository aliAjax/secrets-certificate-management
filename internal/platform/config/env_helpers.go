package config

import (
	"os"
	"sync"
	"time"
)

var envCache = struct {
	sync.Mutex
	values map[string]string
}{values: make(map[string]string)}

func cachedEnv(key string) string {
	envCache.Lock()
	defer envCache.Unlock()
	if value, ok := os.LookupEnv(key); ok {
		envCache.values[key] = value
	}
	return envCache.values[key]
}

func envValue(key string) string {
	return cachedEnv(key)
}

func durationValue(key string) (time.Duration, bool) {
	raw := cachedEnv(key)
	if raw == "" {
		return 0, false
	}
	d, err := time.ParseDuration(raw)
	return d, err == nil
}

func durationPtr(d time.Duration) *time.Duration {
	return &d
}
