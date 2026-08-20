package grpcapi

import (
	"encoding/json"
	"fmt"
)

type jsonCodec struct{}

func cloneRequestMap(req map[string]interface{}) map[string]interface{} { return req }

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
