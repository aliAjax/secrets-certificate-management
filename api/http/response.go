package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
)

func firstForwardedIdentity(value string) string {
	if idx := strings.Index(value, ","); idx >= 0 {
		value = value[:idx]
	}
	return strings.TrimSpace(value)
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, value interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	if err == nil {
		err = http.ErrAbortHandler
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func decodeJSON(r *http.Request, dst interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(dst)
}
