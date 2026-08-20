package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadDoesNotReuseEnvironment(t *testing.T) {
	os.Setenv("SCP_HTTP_ADDR", " :19090 ")
	os.Setenv("SCP_REQUEST_TIMEOUT", " 20s ")
	first, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	os.Unsetenv("SCP_HTTP_ADDR")
	os.Unsetenv("SCP_REQUEST_TIMEOUT")
	second, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if first.Server.HTTPAddr != ":19090" || first.Server.RequestTimeout != 20*time.Second || second.Server.HTTPAddr != ":8080" || second.Server.RequestTimeout != 15*time.Second {
		t.Fatalf("environment leaked: first=%s second=%s", first.Server.HTTPAddr, second.Server.HTTPAddr)
	}
}
