package grpcapi

// cloneRequestMap returns a deep copy of req so that each gRPC handler owns an
// isolated request object. Concurrent calls must never share mutable map or slice
// state: a read of one call's identity/metadata while another mutates its snapshot
// is a data race, and sharing backing arrays lets one request's edits leak into
// another's. We therefore clone the whole structure (maps and slices, recursively)
// rather than the top-level map.
func cloneRequestMap(req map[string]interface{}) map[string]interface{} {
	if req == nil {
		return nil
	}
	out := make(map[string]interface{}, len(req))
	for k, v := range req {
		out[k] = cloneValue(v)
	}
	return out
}

// cloneValue copies v deeply. Reference types (maps and slices) are rebuilt with
// fresh backing storage; scalars and other immutable values are returned as-is.
func cloneValue(v interface{}) interface{} {
	switch value := v.(type) {
	case map[string]interface{}:
		clone := make(map[string]interface{}, len(value))
		for k, sub := range value {
			clone[k] = cloneValue(sub)
		}
		return clone
	case []interface{}:
		clone := make([]interface{}, len(value))
		for i, sub := range value {
			clone[i] = cloneValue(sub)
		}
		return clone
	default:
		return v
	}
}

// snapshotFence produces an isolated snapshot of the incoming request that the
// handler can mutate freely without affecting other concurrent calls.
func snapshotFence(req map[string]interface{}) map[string]interface{} {
	return cloneRequestMap(req)
}
