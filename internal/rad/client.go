package rad

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	userAgent    = "rad-security/image-scanner"
	tokenTTL     = 3*time.Hour + 55*time.Minute
	httpTimeout  = 30 * time.Second
	authPath     = "/authentication/authenticate"
	sessionPrefx = "ory_st_"
)

type Client struct {
	cfg        Config
	httpClient *http.Client

	mu           sync.Mutex
	cachedTok    string
	cachedExpiry time.Time
}

func NewClient(cfg Config) *Client {
	return &Client{
		cfg:        cfg,
		httpClient: &http.Client{Timeout: httpTimeout},
	}
}

func (c *Client) AccountIDs() []string {
	return c.cfg.AccountIDs
}

func (c *Client) token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.cachedTok != "" && time.Now().Before(c.cachedExpiry) {
		return c.cachedTok, nil
	}

	body, err := json.Marshal(map[string]string{
		"access_key_id": c.cfg.AccessKeyID,
		"secret_key":    c.cfg.SecretKey,
	})
	if err != nil {
		return "", fmt.Errorf("marshaling auth body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.APIURL+authPath, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("rad auth: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("rad auth failed: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return "", fmt.Errorf("parsing auth response: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("rad auth returned empty token")
	}

	c.cachedTok = out.Token
	c.cachedExpiry = time.Now().Add(tokenTTL)
	return c.cachedTok, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	token, err := c.token(ctx)
	if err != nil {
		return err
	}

	u := c.cfg.APIURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	if strings.HasPrefix(token, sessionPrefx) {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("Cookie", "ory_kratos_session="+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("rad request %s: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("rad GET %s failed: HTTP %d: %s", path, resp.StatusCode, truncate(string(respBody), 512))
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
