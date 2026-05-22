package rad

import (
	"os"
	"strings"
)

const (
	EnvAccessKeyID = "RAD_ACCESS_KEY_ID"
	EnvSecretKey   = "RAD_SECRET_KEY"
	EnvAccountIDs  = "RAD_ACCOUNT_IDS"
	EnvAPIURL      = "RAD_API_URL"

	DefaultAPIURL = "https://api.rad.security"
)

type Config struct {
	AccessKeyID string
	SecretKey   string
	AccountIDs  []string
	APIURL      string
}

func ConfigFromEnv() Config {
	c := Config{
		AccessKeyID: os.Getenv(EnvAccessKeyID),
		SecretKey:   os.Getenv(EnvSecretKey),
		APIURL:      os.Getenv(EnvAPIURL),
	}
	if c.APIURL == "" {
		c.APIURL = DefaultAPIURL
	}
	if raw := os.Getenv(EnvAccountIDs); raw != "" {
		for _, id := range strings.Split(raw, ",") {
			if id = strings.TrimSpace(id); id != "" {
				c.AccountIDs = append(c.AccountIDs, id)
			}
		}
	}
	return c
}

func (c Config) Enabled() bool {
	return c.AccessKeyID != "" && c.SecretKey != ""
}
