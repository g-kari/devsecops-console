// Package feed はRSS/Atomフィードを安全に正規化する。
package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Item はRSS/Atomの共通記事モデル。
type Item struct {
	FeedURL    string
	ExternalID string
	Title      string
	Link       string
	Summary    string
	Published  time.Time
	CVEIDs     []string
}

// FetchOptions は取得時の制限。
type FetchOptions struct {
	Timeout             time.Duration
	MaxItems            int
	MaxBytes            int64
	AllowHTTP           bool
	AllowPrivateNetwork bool // テスト用。通常運用ではfalse。
	HTTPClient          *http.Client
	ETag                string
	LastModified        string
}

// FetchResult distinguishes a parsed response from an unchanged feed.
type FetchResult struct {
	Items        []Item
	NotModified  bool
	ETag         string
	LastModified string
}

// HTTPStatusError carries retry information for a rate-limited response.
type HTTPStatusError struct {
	StatusCode int
	Status     string
	RetryAt    time.Time
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("フィードHTTPステータス: %s", e.Status)
}

func retryAt(header string, now time.Time) time.Time {
	due := now.Add(15 * time.Minute)
	if seconds, err := strconv.ParseInt(strings.TrimSpace(header), 10, 64); err == nil && seconds >= 0 {
		if seconds > 86400 {
			seconds = 86400
		}
		due = now.Add(time.Duration(seconds) * time.Second)
	} else if date, err := http.ParseTime(header); err == nil {
		due = date
	}
	if due.Before(now) {
		return now
	}
	if due.After(now.Add(24 * time.Hour)) {
		return now.Add(24 * time.Hour)
	}
	return due
}

var cvePattern = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,}\b`)

type rssDocument struct {
	Channel struct {
		Title string    `xml:"title"`
		Items []rssItem `xml:"item"`
	} `xml:"channel"`
}
type rssItem struct {
	GUID        string `xml:"guid"`
	About       string `xml:"http://www.w3.org/1999/02/22-rdf-syntax-ns# about,attr"`
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	DCDate      string `xml:"http://purl.org/dc/elements/1.1/ date"`
}
type atomDocument struct {
	Entries []atomEntry `xml:"entry"`
}
type atomEntry struct {
	ID        string     `xml:"id"`
	Title     string     `xml:"title"`
	Summary   string     `xml:"summary"`
	Content   string     `xml:"content"`
	Updated   string     `xml:"updated"`
	Published string     `xml:"published"`
	Links     []atomLink `xml:"link"`
}
type atomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

// Fetch downloads and parses one feed.
func Fetch(ctx context.Context, feedURL string, opt FetchOptions) ([]Item, error) {
	result, err := FetchWithCache(ctx, feedURL, opt)
	return result.Items, err
}

// FetchWithCache applies conditional validators and a deadline to all I/O.
func FetchWithCache(ctx context.Context, feedURL string, opt FetchOptions) (FetchResult, error) {
	if opt.Timeout <= 0 {
		opt.Timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if opt.MaxItems <= 0 {
		opt.MaxItems = 100
	}
	if opt.MaxBytes <= 0 {
		opt.MaxBytes = 2 << 20
	}
	u, err := url.Parse(feedURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("フィードURL解析失敗: %w", err)
	}
	if u.Scheme != "https" && !(opt.AllowHTTP && u.Scheme == "http") {
		return FetchResult{}, fmt.Errorf("HTTPS以外のフィードURLは許可されていません")
	}
	if u.User != nil {
		return FetchResult{}, fmt.Errorf("userinfo付きフィードURLは許可されていません")
	}
	if !opt.AllowPrivateNetwork {
		if err := validateHost(ctx, u.Hostname()); err != nil {
			return FetchResult{}, err
		}
	}
	client := opt.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opt.Timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("リダイレクト回数超過")
			}
			if req.URL.Scheme != "https" && !(opt.AllowHTTP && req.URL.Scheme == "http") {
				return fmt.Errorf("リダイレクト先がHTTPSではありません")
			}
			if !opt.AllowPrivateNetwork {
				return validateHost(req.Context(), req.URL.Hostname())
			}
			return nil
		}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("フィード要求作成失敗: %w", err)
	}
	req.Header.Set("User-Agent", "security-notice/1.0")
	if opt.ETag != "" {
		req.Header.Set("If-None-Match", opt.ETag)
	}
	if opt.LastModified != "" {
		req.Header.Set("If-Modified-Since", opt.LastModified)
	}
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("フィード取得失敗: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotModified {
		if opt.ETag == "" && opt.LastModified == "" {
			return FetchResult{}, fmt.Errorf("条件なしの要求に304が返されました")
		}
		etag, modified := resp.Header.Get("ETag"), resp.Header.Get("Last-Modified")
		if etag == "" {
			etag = opt.ETag
		}
		if modified == "" {
			modified = opt.LastModified
		}
		return FetchResult{NotModified: true, ETag: etag, LastModified: modified}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := &HTTPStatusError{StatusCode: resp.StatusCode, Status: resp.Status}
		if resp.StatusCode == http.StatusTooManyRequests {
			status.RetryAt = retryAt(resp.Header.Get("Retry-After"), time.Now().UTC())
		}
		return FetchResult{}, status
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, opt.MaxBytes+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("フィード読込失敗: %w", err)
	}
	if int64(len(body)) > opt.MaxBytes {
		return FetchResult{}, fmt.Errorf("フィードサイズ上限超過")
	}
	items, err := parse(body, opt.MaxItems)
	if err != nil {
		return FetchResult{}, err
	}
	base := u
	if resp.Request != nil && resp.Request.URL != nil {
		base = resp.Request.URL
	}
	for i := range items {
		if items[i].Link == "" {
			continue
		}
		linkURL, linkErr := url.Parse(items[i].Link)
		if linkErr != nil {
			items[i].Link = ""
			continue
		}
		resolved := base.ResolveReference(linkURL)
		if resolved.Scheme != "http" && resolved.Scheme != "https" {
			items[i].Link = ""
		} else {
			items[i].Link = resolved.String()
		}
	}
	return FetchResult{Items: items, ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}, nil
}

func parse(body []byte, maxItems int) ([]Item, error) {
	var root struct {
		XMLName xml.Name
		Channel *struct {
			Items []rssItem `xml:"item"`
		} `xml:"channel"`
		Entries []atomEntry `xml:"entry"`
		Items   []rssItem   `xml:"item"`
	}
	if err := xml.Unmarshal(body, &root); err != nil {
		return nil, fmt.Errorf("フィードXML解析失敗: %w", err)
	}
	items := make([]Item, 0, maxItems)
	if root.XMLName.Local == "RDF" {
		for _, v := range root.Items {
			if len(items) >= maxItems {
				break
			}
			items = append(items, normalizeRSS(v))
		}
	} else if root.Channel != nil {
		for _, v := range root.Channel.Items {
			if len(items) >= maxItems {
				break
			}
			items = append(items, normalizeRSS(v))
		}
	} else {
		for _, v := range root.Entries {
			if len(items) >= maxItems {
				break
			}
			items = append(items, normalizeAtom(v))
		}
	}
	if len(items) == 0 && root.Channel == nil && len(root.Entries) == 0 && !(root.XMLName.Local == "RDF" && len(root.Items) > 0) {
		return nil, fmt.Errorf("RSS channel、RDF itemまたはAtom entryがありません")
	}
	return items, nil
}

func normalizeRSS(v rssItem) Item {
	id := v.GUID
	if id == "" {
		id = v.About
	}
	date := v.PubDate
	if date == "" {
		date = v.DCDate
	}
	return makeItem(id, v.Title, v.Link, v.Description, parseTime(date))
}
func normalizeAtom(v atomEntry) Item {
	link := ""
	for _, l := range v.Links {
		if l.Rel == "alternate" || link == "" {
			link = l.Href
		}
	}
	tm := parseTime(v.Published)
	if tm.IsZero() {
		tm = parseTime(v.Updated)
	}
	summary := v.Summary
	if summary == "" {
		summary = v.Content
	}
	return makeItem(v.ID, v.Title, link, summary, tm)
}
func makeItem(id, title, link, summary string, published time.Time) Item {
	id = strings.TrimSpace(id)
	if id == "" {
		h := sha256.Sum256([]byte(title + "\x00" + link + "\x00" + summary + "\x00" + published.UTC().String()))
		id = "hash:" + hex.EncodeToString(h[:])
	}
	ids := cvePattern.FindAllString(strings.ToUpper(title+"\n"+summary), -1)
	sort.Strings(ids)
	out := ids[:0]
	for _, v := range ids {
		if len(out) == 0 || out[len(out)-1] != v {
			out = append(out, v)
		}
	}
	return Item{ExternalID: id, Title: stripText(title), Link: link, Summary: stripText(summary), Published: published, CVEIDs: out}
}
func stripText(v string) string {
	return strings.TrimSpace(regexp.MustCompile(`<[^>]*>`).ReplaceAllString(v, " "))
}
func parseTime(v string) time.Time {
	for _, layout := range []string{time.RFC3339, time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822} {
		if t, err := time.Parse(layout, strings.TrimSpace(v)); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
func validateHost(ctx context.Context, host string) error {
	if host == "" {
		return fmt.Errorf("フィードホストが空です")
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return fmt.Errorf("フィードホスト解決失敗: %w", err)
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("非公開IPのフィードは許可されていません")
		}
		if ip.String() == "169.254.169.254" {
			return fmt.Errorf("メタデータIPのフィードは許可されていません")
		}
	}
	return nil
}
