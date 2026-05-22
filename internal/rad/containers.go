package rad

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"sync"
)

// Container is one row from /accounts/{id}/inventory_containers. Only the
// fields used for deployment-placement context are kept.
type Container struct {
	Name           string `json:"name"`
	ImageDigest    string `json:"image_digest"`
	OwnerUID       string `json:"owner_uid"`
	OwnerKind      string `json:"owner_kind"`
	OwnerName      string `json:"owner_name"`
	OwnerNamespace string `json:"owner_namespace"`
	ClusterID      string `json:"cluster_id"`
	ClusterName    string `json:"cluster_name"`
}

// Workload is a deduplicated Kubernetes owner (Pod, Deployment, ...) that runs
// the image.
type Workload struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Cluster   string `json:"cluster"`
}

// Placement aggregates where a deployed image is actually running.
type Placement struct {
	ContainerCount int        `json:"container_count"`
	ClusterCount   int        `json:"cluster_count"`
	Clusters       []string   `json:"clusters"`
	Namespaces     []string   `json:"namespaces"`
	Workloads      []Workload `json:"workloads"`
}

type inventoryContainersResponse struct {
	Entries []Container `json:"entries"`
	HasMore bool        `json:"has_more"`
}

// FindContainers returns every running container in the account whose image
// matches the given digest.
func (c *Client) FindContainers(ctx context.Context, accountID, digest string) ([]Container, error) {
	path := fmt.Sprintf("/accounts/%s/inventory_containers", accountID)

	var out []Container
	offset := 0
	for range maxPagesPerAcct {
		q := url.Values{}
		q.Set("filters", "image_digest:"+digest)
		q.Set("limit", strconv.Itoa(pageSize))
		q.Set("offset", strconv.Itoa(offset))

		var resp inventoryContainersResponse
		if err := c.get(ctx, path, q, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Entries...)
		if !resp.HasMore || len(resp.Entries) == 0 {
			break
		}
		offset += len(resp.Entries)
	}
	return out, nil
}

// AttachPlacement fills the Placement field of every deployed image by
// querying inventory_containers. Lookups run in parallel, one per image.
func (c *Client) AttachPlacement(ctx context.Context, deployed []DeployedImage) error {
	var wg sync.WaitGroup
	errs := make([]error, len(deployed))

	for i := range deployed {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := &deployed[i]
			containers, err := c.FindContainers(ctx, d.AccountID, d.Digest)
			if err != nil {
				errs[i] = err
				return
			}
			pl := buildPlacement(containers)
			d.Placement = &pl
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			return fmt.Errorf("placement for digest %s: %w", deployed[i].Digest, err)
		}
	}
	return nil
}

func buildPlacement(containers []Container) Placement {
	clusterSet := map[string]struct{}{}
	nsSet := map[string]struct{}{}
	workloadSeen := map[string]struct{}{}
	var workloads []Workload

	for _, ct := range containers {
		if ct.ClusterName != "" {
			clusterSet[ct.ClusterName] = struct{}{}
		}
		if ct.OwnerNamespace != "" {
			nsSet[ct.OwnerNamespace] = struct{}{}
		}
		key := ct.OwnerUID
		if key == "" {
			key = ct.OwnerKind + "/" + ct.OwnerNamespace + "/" + ct.OwnerName + "@" + ct.ClusterName
		}
		if _, seen := workloadSeen[key]; !seen {
			workloadSeen[key] = struct{}{}
			workloads = append(workloads, Workload{
				Kind:      ct.OwnerKind,
				Name:      ct.OwnerName,
				Namespace: ct.OwnerNamespace,
				Cluster:   ct.ClusterName,
			})
		}
	}

	return Placement{
		ContainerCount: len(containers),
		ClusterCount:   len(clusterSet),
		Clusters:       sortedKeys(clusterSet),
		Namespaces:     sortedKeys(nsSet),
		Workloads:      workloads,
	}
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
