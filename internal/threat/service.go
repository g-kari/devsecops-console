package threat

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/model"
)

const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// Service fetches structured threat feeds through an injectable HTTP client.
type Service struct {
	Client  *http.Client
	Timeout time.Duration
}

func (s Service) client() *http.Client {
	if s.Client != nil {
		return s.Client
	}
	return &http.Client{Timeout: s.Timeout}
}

// FetchKEV downloads and parses a CISA KEV response.
func (s Service) FetchKEV(ctx context.Context, endpoint string, at time.Time) (map[string]model.ThreatSnapshot, error) {
	b, err := s.fetch(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	return ParseKEV(b, at)
}

// FetchEPSS downloads and parses an EPSS CSV response.
func (s Service) FetchEPSS(ctx context.Context, endpoint string, at time.Time) (map[string]model.ThreatSnapshot, error) {
	b, err := s.fetch(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b {
		zr, zerr := gzip.NewReader(bytes.NewReader(b))
		if zerr != nil {
			return nil, zerr
		}
		b, zerr = io.ReadAll(io.LimitReader(zr, 32<<20))
		_ = zr.Close()
		if zerr != nil {
			return nil, zerr
		}
	}
	return ParseEPSS(strings.NewReader(string(b)), at)
}

func (s Service) fetch(ctx context.Context, endpoint string) ([]byte, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("threat endpoint is empty")
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "https" && !(s.Client != nil && u.Scheme == "http")) || u.Hostname() == "" {
		return nil, fmt.Errorf("threat endpoint must use https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("threat feed status: %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, err
	}
	return b, nil
}
