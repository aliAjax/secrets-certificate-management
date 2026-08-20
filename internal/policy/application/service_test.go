package application

import "testing"

func TestCloneConditionsDoesNotShareMap(t *testing.T) {
	src := map[string]string{"ip": "eq:10.0.0.1"}
	got := cloneConditions(src)
	got["ip"] = "eq:10.0.0.2"
	if src["ip"] != "eq:10.0.0.1" {
		t.Fatal("condition clone mutated input")
	}
}
