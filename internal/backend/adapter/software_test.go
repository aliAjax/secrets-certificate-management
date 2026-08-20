package adapter

import "testing"

func TestSensitiveBufferClear(t *testing.T) {
	b := []byte("private material")
	clearSensitive(b)
	for _, v := range b {
		if v != 0 {
			t.Fatal("buffer not cleared")
		}
	}
}
