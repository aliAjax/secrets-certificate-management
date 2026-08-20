package grpcapi

import (
	"sync"
	"testing"
)

func TestRequestSnapshotIsolated(t *testing.T) {
	input := map[string]interface{}{"identity": "alice", "metadata": map[string]interface{}{"role": "reader"}}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got := requestSnapshot(input)
			if got["__handler_fence"] != true || got["__snapshot_fence"] != true {
				t.Error("request fences missing")
			}
			got["identity"] = "changed"
			got["metadata"].(map[string]interface{})["role"] = "admin"
		}()
	}
	close(start)
	wg.Wait()
	if input["identity"] != "alice" {
		t.Fatal("request state was shared")
	}
	if input["metadata"].(map[string]interface{})["role"] != "reader" {
		t.Fatal("nested request state was shared")
	}
}
