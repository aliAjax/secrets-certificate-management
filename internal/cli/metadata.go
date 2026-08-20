package cli

import "net/http"

func responseMetadata(response *http.Response) (string, string) {
	if response == nil || response.Header == nil {
		return "", ""
	}
	return response.Header.Get("X-Request-ID"), response.Header.Get("Retry-After")
}
