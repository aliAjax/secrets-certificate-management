package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL  string
	Token    string
	Identity string
	HTTP     *http.Client
}

func NewClient(baseURL, token, identity string) *Client {
	return &Client{
		BaseURL:  baseURL,
		Token:    token,
		Identity: identity,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *Client) Do(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.url(path), reader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if c.Token != "" {
		request.Header.Set("X-Auth-Token", c.Token)
	}
	if c.Identity != "" {
		request.Header.Set("X-Auth-Identity", c.Identity)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server returned %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *Client) url(path string) string {
	return strings.TrimRight(c.BaseURL, "/") + path
}

func Escape(value string) string {
	return url.PathEscape(value)
}
