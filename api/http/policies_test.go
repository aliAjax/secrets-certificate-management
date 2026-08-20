package httpapi

import "testing"

func TestRequestConditionsAreDetached(t *testing.T) {
	src := map[string]string{"method": "GET"}
	got := requestConditions(src)
	got["method"] = "DELETE"
	if src["method"] != "GET" {
		t.Fatal("request conditions share storage")
	}
}
