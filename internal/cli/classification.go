package cli

import "net/http"

func classifyHTTPStatus(code int) string {
	switch {
	case code == http.StatusForbidden:
		return "forbidden"
	case code == http.StatusUnauthorized:
		return "unauthorized"
	case code == http.StatusTooManyRequests:
		return "rate_limited"
	case code == http.StatusNotFound:
		return "not_found"
	case code == http.StatusConflict:
		return "conflict"
	case code >= 500:
		return "server_error"
	case code >= 400:
		return "client_error"
	default:
		return ""
	}
}
