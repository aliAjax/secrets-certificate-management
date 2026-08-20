package grpcapi

import (
	"encoding/json"
	"fmt"
)

type jsonCodec struct{}

func (jsonCodec) Name() string {
	return "json"
}

func (jsonCodec) Marshal(value interface{}) ([]byte, error) {
	return json.Marshal(value)
}

func (jsonCodec) Unmarshal(data []byte, value interface{}) error {
	return json.Unmarshal(data, value)
}

var _ = fmt.Sprintf
