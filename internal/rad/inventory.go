package rad

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const (
	pageSize        = 100
	maxPagesPerAcct = 50 // hard ceiling to avoid runaway pagination
)

// DeployedImage is one row from /accounts/{id}/data/scanned_images.
// Only the fields we use are kept; ignored fields like upgrade_opportunities,
// has_chainguard_image, vulnerability_diff are intentionally dropped.
type DeployedImage struct {
	AccountID       string    `json:"account_id"`
	Digest          string    `json:"digest"`
	Name            string    `json:"name"`
	Repo            string    `json:"repo"`
	Tags            []string  `json:"tags"`
	CriticalCount   int       `json:"critical_count"`
	HighCount       int       `json:"high_count"`
	MediumCount     int       `json:"medium_count"`
	LowCount        int       `json:"low_count"`
	NegligibleCount int       `json:"negligible_count"`
	TotalCount      int       `json:"total_count"`
	Distro          string    `json:"distro"`
	DistroEOLDate   time.Time `json:"distro_eol_date"`
	DistroEOLStatus string    `json:"distro_eol_status"`
	ScannedAt       time.Time `json:"scanned_at"`

	// Placement is populated by AttachPlacement from the inventory_containers
	// endpoint; it is not part of the scanned_images API response.
	Placement *Placement `json:"placement,omitempty"`
}

type scannedImagesResponse struct {
	Items []struct {
		Data DeployedImage `json:"data"`
	} `json:"items"`
	HasMore bool `json:"has_more"`
}

// FindDeployed queries every configured account in parallel and returns the
// union of matching deployed images. name and repo are matched exactly.
func (c *Client) FindDeployed(ctx context.Context, name, repo string) ([]DeployedImage, error) {
	if len(c.cfg.AccountIDs) == 0 {
		return nil, nil
	}

	type result struct {
		images []DeployedImage
		err    error
	}

	var wg sync.WaitGroup
	results := make([]result, len(c.cfg.AccountIDs))

	for i, accountID := range c.cfg.AccountIDs {
		wg.Add(1)
		go func(i int, accountID string) {
			defer wg.Done()
			imgs, err := c.findDeployedInAccount(ctx, accountID, name, repo)
			results[i] = result{images: imgs, err: err}
		}(i, accountID)
	}
	wg.Wait()

	var out []DeployedImage
	for i, r := range results {
		if r.err != nil {
			return nil, fmt.Errorf("account %s: %w", c.cfg.AccountIDs[i], r.err)
		}
		out = append(out, r.images...)
	}
	return out, nil
}

func (c *Client) findDeployedInAccount(ctx context.Context, accountID, name, repo string) ([]DeployedImage, error) {
	path := fmt.Sprintf("/accounts/%s/data/scanned_images", accountID)
	filter := fmt.Sprintf(`name:%q AND repo:%q`, name, repo)

	var out []DeployedImage
	offset := 0
	for range maxPagesPerAcct {
		q := url.Values{}
		q.Set("filters_query", filter)
		q.Set("limit", strconv.Itoa(pageSize))
		q.Set("offset", strconv.Itoa(offset))

		var resp scannedImagesResponse
		if err := c.get(ctx, path, q, &resp); err != nil {
			return nil, err
		}
		for _, item := range resp.Items {
			item.Data.AccountID = accountID // server sometimes omits in scoped queries
			out = append(out, item.Data)
		}
		if !resp.HasMore || len(resp.Items) == 0 {
			break
		}
		offset += len(resp.Items)
	}
	return out, nil
}
