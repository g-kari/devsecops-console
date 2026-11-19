package enrichmentrefresh

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/g-kari/dependabot-alert-notice/internal/store"
)

type boundedRoundTripFunc func(*http.Request) (*http.Response, error)

func (f boundedRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type boundedContractBody struct {
	reader io.Reader
	eof    bool
	closes int
}

func (b *boundedContractBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	if err == io.EOF {
		b.eof = true
	}
	return n, err
}

func (b *boundedContractBody) Close() error {
	b.closes++
	return nil
}

func assertBoundedContractFetch(t *testing.T, source, endpoint, encoding string, encoded, decoded []byte) {
	t.Helper()
	ctx := context.Background()
	want := bytes.Clone(decoded)
	body := &boundedContractBody{reader: bytes.NewReader(encoded)}
	calls := 0
	transport := boundedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Context() != ctx || request.Method != http.MethodGet || request.URL.String() != endpoint || request.URL.User != nil || request.URL.RawQuery != "" || request.URL.Fragment != "" || request.Header.Get("Accept-Encoding") != "identity" || (request.Body != nil && request.Body != http.NoBody) {
			t.Fatalf("request escaped fixed source/context/header contract: %+v", request)
		}
		for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie"} {
			if request.Header.Get(name) != "" {
				t.Fatalf("unexpected credential header %s", name)
			}
		}
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header),
			ContentLength: int64(len(encoded)), Body: body,
		}, nil
	})
	fetcher, err := NewBoundedHTTPFetcher(transport, map[string]HTTPSourceProfile{
		source: {URL: endpoint, Encoding: encoding},
	})
	if err != nil {
		t.Fatalf("explicit synthetic profile rejected: %v", err)
	}
	got, err := fetcher.Fetch(ctx, source)
	if err != nil {
		t.Fatalf("bounded contract fetch failed: %v", err)
	}
	if !bytes.Equal(got, want) || calls != 1 || !body.eof || body.closes != 1 {
		t.Fatalf("incomplete bytes/EOF/close/one-call result: bytes=%d calls=%d eof=%v closes=%d", len(got), calls, body.eof, body.closes)
	}
	// Returned bytes must be owned independently of the supplied body storage.
	if len(encoded) != 0 {
		encoded[0] ^= 0xff
	}
	if !bytes.Equal(got, want) {
		t.Fatal("returned parser-input bytes alias the supplied body storage")
	}
}

func TestBoundedHTTPFetcherContractIdentityReturnsCompleteSyntheticInput(t *testing.T) {
	// Authored projection-minimal catalog JSON, not retrieved provider data.
	data := []byte(`{"catalogVersion":"synthetic-transport.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`)
	assertBoundedContractFetch(t, "kev", "https://fixture.invalid/synthetic/kev.json", "identity", data, data)
}

func TestBoundedHTTPFetcherContractSingleGzipReturnsDecodedSyntheticInput(t *testing.T) {
	// Authored metadata-bearing CSV accepted by the existing offline parser.
	data := []byte("#model_version:synthetic-transport,score_date:2026-11-10\ncve,epss,percentile\nCVE-2026-1234,0,0\n")
	var encoded bytes.Buffer
	writer := gzip.NewWriter(&encoded)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	assertBoundedContractFetch(t, "epss", "https://fixture.invalid/synthetic/epss.csv.gz", "gzip", encoded.Bytes(), data)
}

type boundedProbeBody struct {
	reader   io.Reader
	closeErr error
	mu       sync.Mutex
	closes   int
	read     int
}

func (b *boundedProbeBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.mu.Lock()
	b.read += n
	b.mu.Unlock()
	return n, err
}

func (b *boundedProbeBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closes++
	return b.closeErr
}

func (b *boundedProbeBody) counts() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closes, b.read
}

type boundedReadFunc func([]byte) (int, error)

func (f boundedReadFunc) Read(p []byte) (int, error) { return f(p) }

func boundedGzip(t *testing.T, input []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(input); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(output.Bytes())
}

func boundedFake(t *testing.T, encoding string, response *http.Response, responseErr error) (*BoundedHTTPFetcher, *int) {
	t.Helper()
	calls := 0
	f, err := NewBoundedHTTPFetcher(boundedRoundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		return response, responseErr
	}), map[string]HTTPSourceProfile{"epss": {URL: "https://fixture.invalid/synthetic/input", Encoding: encoding}})
	if err != nil {
		t.Fatal(err)
	}
	return f, &calls
}

func TestBoundedHTTPFetcherRequiresExplicitImmutableProfiles(t *testing.T) {
	valid := func() map[string]HTTPSourceProfile {
		return map[string]HTTPSourceProfile{"epss": {URL: "https://fixture.invalid/first", Encoding: "identity"}}
	}
	var absent boundedRoundTripFunc
	for _, kind := range []string{"nil-transport", "typed-nil", "no-sources", "unknown-source", "http", "userinfo", "query", "empty-query", "fragment", "empty-fragment", "host", "encoding", "no-encoding"} {
		t.Run(kind, func(t *testing.T) {
			profiles := valid()
			var transport http.RoundTripper = boundedRoundTripFunc(func(*http.Request) (*http.Response, error) {
				t.Fatal("constructor performed I/O")
				return nil, nil
			})
			p := profiles["epss"]
			switch kind {
			case "nil-transport":
				transport = nil
			case "typed-nil":
				transport = absent
			case "no-sources":
				profiles = nil
			case "unknown-source":
				profiles["unknown"] = p
			case "http":
				p.URL = "http://fixture.invalid/input"
			case "userinfo":
				p.URL = "https://synthetic:PRIVATE@fixture.invalid/input"
			case "query":
				p.URL += "?cve=CVE-2026-1234"
			case "empty-query":
				p.URL += "?"
			case "fragment":
				p.URL += "#PRIVATE"
			case "empty-fragment":
				p.URL += "#"
			case "host":
				p.URL = "https:///input"
			case "encoding":
				p.Encoding = "br"
			case "no-encoding":
				p.Encoding = ""
			}
			if profiles != nil {
				profiles["epss"] = p
			}
			f, err := NewBoundedHTTPFetcher(transport, profiles)
			if err == nil || f != nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("invalid constructor kind=%s fetcher=%v err=%v", kind, f, err)
			}
		})
	}

	profiles := valid()
	body := &boundedProbeBody{reader: strings.NewReader("synthetic")}
	calls := 0
	f, err := NewBoundedHTTPFetcher(boundedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.URL.String() != "https://fixture.invalid/first" {
			t.Fatal("caller map mutation changed fixed endpoint")
		}
		return &http.Response{StatusCode: 200, ContentLength: 9, Body: body}, nil
	}), profiles)
	if err != nil {
		t.Fatal(err)
	}
	profiles["epss"] = HTTPSourceProfile{URL: "https://fixture.invalid/changed", Encoding: "gzip"}
	delete(profiles, "epss")
	for _, source := range []string{"kev", "CVE-2026-1234", "EPSS"} {
		data, err := f.Fetch(context.Background(), source)
		if err == nil || data != nil || calls != 0 {
			t.Fatal("unknown source reached transport")
		}
	}
	got, err := f.Fetch(context.Background(), "epss")
	if err != nil || string(got) != "synthetic" || calls != 1 {
		t.Fatalf("copied profile failed: %q %v", got, err)
	}
}

func TestBoundedHTTPFetcherRejectsResponseAndLengthFailuresWithoutBytes(t *testing.T) {
	for _, kind := range []string{"status-206", "redirect", "uncompressed", "http-gzip", "stacked-coding", "duplicate-coding", "short", "long", "oversize-header", "negative-length", "length-header-mismatch", "length-header-duplicate", "length-header-syntax", "read-error", "close-error", "roundtrip-error", "nil-body", "nil-response"} {
		t.Run(kind, func(t *testing.T) {
			body := &boundedProbeBody{reader: strings.NewReader("abc")}
			response := &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: 3, Body: body}
			var cause error
			switch kind {
			case "status-206":
				response.StatusCode = 206
			case "redirect":
				response.StatusCode = 302
				response.Header.Set("Location", "https://fixture.invalid/never")
			case "uncompressed":
				response.Uncompressed = true
			case "http-gzip":
				response.Header.Set("Content-Encoding", "gzip")
			case "stacked-coding":
				response.Header.Set("Content-Encoding", "identity, gzip")
			case "duplicate-coding":
				response.Header["Content-Encoding"] = []string{"identity"}
				response.Header["content-encoding"] = []string{"identity"}
			case "short":
				response.ContentLength = 4
			case "long":
				response.ContentLength = 2
			case "oversize-header":
				response.ContentLength = boundedHTTPMaxEncoded + 1
			case "negative-length":
				response.ContentLength = -2
			case "length-header-mismatch":
				response.Header.Set("Content-Length", "4")
			case "length-header-duplicate":
				response.Header["Content-Length"] = []string{"3", "3"}
			case "length-header-syntax":
				response.Header.Set("Content-Length", "+3")
			case "read-error":
				body.reader = io.MultiReader(strings.NewReader("abc"), boundedReadFunc(func([]byte) (int, error) { return 0, errors.New("PRIVATE-read-error") }))
			case "close-error":
				body.closeErr = errors.New("PRIVATE-close-error")
			case "roundtrip-error":
				cause = errors.New("PRIVATE-roundtrip-error")
			case "nil-body":
				response.Body = nil
			case "nil-response":
				response = nil
			}
			f, calls := boundedFake(t, "identity", response, cause)
			data, err := f.Fetch(context.Background(), "epss")
			if err == nil || data != nil || *calls != 1 || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("failure leaked/returned bytes/retried kind=%s bytes=%d calls=%d err=%v", kind, len(data), *calls, err)
			}
			wantCloses := 1
			if kind == "nil-body" || kind == "nil-response" {
				wantCloses = 0
			}
			if closes, _ := body.counts(); closes != wantCloses {
				t.Fatalf("kind=%s body closes=%d want=%d", kind, closes, wantCloses)
			}
		})
	}
}

func TestBoundedHTTPFetcherEncodedAndDecodedCapsUseSentinels(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip"} {
		cap := boundedHTTPMaxEncoded
		if encoding == "gzip" {
			cap = boundedHTTPMaxDecoded
		}
		for _, delta := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("%s/%d", encoding, delta), func(t *testing.T) {
				want := bytes.Repeat([]byte("x"), cap+delta)
				encoded := want
				if encoding == "gzip" {
					encoded = boundedGzip(t, want)
				}
				body := &boundedProbeBody{reader: bytes.NewReader(encoded)}
				// Unknown ContentLength exercises the actual cap+1 read, not
				// only the early known-length rejection.
				f, _ := boundedFake(t, encoding, &http.Response{StatusCode: 200, ContentLength: -1, Body: body}, nil)
				data, err := f.Fetch(context.Background(), "epss")
				if delta <= 0 {
					if err != nil || !bytes.Equal(data, want) {
						t.Fatalf("at/below cap rejected: bytes=%d err=%v", len(data), err)
					}
				} else if err == nil || data != nil {
					t.Fatal("cap+1 input returned bytes")
				}
				closes, read := body.counts()
				if closes != 1 || read > boundedHTTPMaxEncoded+1 {
					t.Fatalf("body not closed or encoded sentinel exceeded: close=%d read=%d", closes, read)
				}
				if encoding == "identity" && delta > 0 && read != boundedHTTPMaxEncoded+1 {
					t.Fatalf("encoded overflow not detected at cap+1: %d", read)
				}
			})
		}
	}
}

func TestBoundedHTTPFetcherGzipRequiresOneCompleteMember(t *testing.T) {
	single := boundedGzip(t, []byte("synthetic decoded bytes"))
	for _, kind := range []string{"header", "trailer", "crc", "isize", "trailing", "whitespace", "concatenated", "empty-second", "nested"} {
		t.Run(kind, func(t *testing.T) {
			raw := bytes.Clone(single)
			switch kind {
			case "header":
				raw = raw[:5]
			case "trailer":
				raw = raw[:len(raw)-1]
			case "crc":
				raw[len(raw)-8] ^= 1
			case "isize":
				raw[len(raw)-4] ^= 1
			case "trailing":
				raw = append(raw, 'x')
			case "whitespace":
				raw = append(raw, '\n')
			case "concatenated":
				raw = append(raw, single...)
			case "empty-second":
				raw = append(raw, boundedGzip(t, nil)...)
			case "nested":
				raw = boundedGzip(t, single)
			}
			body := &boundedProbeBody{reader: bytes.NewReader(raw)}
			f, _ := boundedFake(t, "gzip", &http.Response{StatusCode: 200, ContentLength: int64(len(raw)), Body: body}, nil)
			data, err := f.Fetch(context.Background(), "epss")
			if err == nil || data != nil {
				t.Fatalf("gzip kind=%s returned partial/ambiguous bytes", kind)
			}
			if closes, _ := body.counts(); closes != 1 {
				t.Fatalf("gzip kind=%s close=%d", kind, closes)
			}
		})
	}
}

type boundedCancelBody struct {
	started chan struct{}
	closed  chan struct{}
	start   sync.Once
	close   sync.Once
	mu      sync.Mutex
	closes  int
}

func (b *boundedCancelBody) Read([]byte) (int, error) {
	b.start.Do(func() { close(b.started) })
	<-b.closed
	return 0, errors.New("PRIVATE-blocked-read")
}

func (b *boundedCancelBody) Close() error {
	b.mu.Lock()
	b.closes++
	b.mu.Unlock()
	b.close.Do(func() { close(b.closed) })
	return nil
}

func TestBoundedHTTPFetcherCancellationClosesBodyAndReturnsNoBytes(t *testing.T) {
	t.Run("before-request", func(t *testing.T) {
		body := &boundedProbeBody{reader: strings.NewReader("abc")}
		f, calls := boundedFake(t, "identity", &http.Response{StatusCode: 200, ContentLength: 3, Body: body}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		data, err := f.Fetch(ctx, "epss")
		if !errors.Is(err, context.Canceled) || data != nil || *calls != 0 {
			t.Fatal("pre-canceled request reached transport")
		}
	})
	t.Run("blocked-read", func(t *testing.T) {
		body := &boundedCancelBody{started: make(chan struct{}), closed: make(chan struct{})}
		f, _ := boundedFake(t, "identity", &http.Response{StatusCode: 200, ContentLength: -1, Body: body}, nil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		type outcome struct {
			data []byte
			err  error
		}
		done := make(chan outcome, 1)
		go func() { data, err := f.Fetch(ctx, "epss"); done <- outcome{data, err} }()
		select {
		case <-body.started:
		case <-time.After(time.Second):
			_ = body.Close()
			t.Fatal("fake body read not reached")
		}
		cancel()
		select {
		case out := <-done:
			if !errors.Is(out.err, context.Canceled) || out.data != nil {
				t.Fatalf("canceled read returned bytes: %d %v", len(out.data), out.err)
			}
		case <-time.After(time.Second):
			_ = body.Close()
			t.Fatal("cancel did not close cooperative fake body")
		}
		body.mu.Lock()
		defer body.mu.Unlock()
		if body.closes != 1 {
			t.Fatalf("cancel/main cleanup closed body %d times", body.closes)
		}
	})
	for _, stage := range []string{"roundtrip", "read-eof", "close"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body := &boundedProbeBody{reader: strings.NewReader("abc")}
			if stage == "read-eof" {
				body.reader = boundedReadFunc(func(p []byte) (int, error) { cancel(); return copy(p, "abc"), io.EOF })
			}
			calls := 0
			f, err := NewBoundedHTTPFetcher(boundedRoundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if stage == "roundtrip" {
					cancel()
				}
				var responseBody io.ReadCloser = body
				if stage == "close" {
					responseBody = boundedCloseCancelBody{boundedProbeBody: body, cancel: cancel}
				}
				return &http.Response{StatusCode: 200, ContentLength: 3, Body: responseBody}, nil
			}), map[string]HTTPSourceProfile{"epss": {URL: "https://fixture.invalid/input", Encoding: "identity"}})
			if err != nil {
				t.Fatal(err)
			}
			data, err := f.Fetch(ctx, "epss")
			if !errors.Is(err, context.Canceled) || data != nil || calls != 1 {
				t.Fatalf("cancel stage=%s bytes=%d calls=%d err=%v", stage, len(data), calls, err)
			}
			if closes, _ := body.counts(); closes != 1 {
				t.Fatalf("cancel stage=%s close=%d", stage, closes)
			}
		})
	}
}

type boundedCloseCancelBody struct {
	*boundedProbeBody
	cancel context.CancelFunc
}

func (b boundedCloseCancelBody) Close() error {
	b.cancel()
	return b.boundedProbeBody.Close()
}

func TestBoundedHTTPFetcherSyntheticSQLiteKeepsDecodedDigestAndKnownFacts(t *testing.T) {
	for _, source := range []string{"epss", "kev"} {
		t.Run(source, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			decoded := []byte(contractEPSS)
			encoding := "gzip"
			if source == "kev" {
				decoded = []byte(`{"catalogVersion":"synthetic-transport.1","dateReleased":"2026-11-10T00:00:00Z","count":1,"vulnerabilities":[{"cveID":"CVE-2026-1234","dateAdded":"2026-11-09"}]}`)
				encoding = "identity"
			}
			encoded := decoded
			if encoding == "gzip" {
				encoded = boundedGzip(t, decoded)
			}
			body := &boundedProbeBody{reader: bytes.NewReader(encoded)}
			f, err := NewBoundedHTTPFetcher(boundedRoundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.Context().Err() != nil {
					t.Fatal("fetch received canceled context")
				}
				bounded, stop := context.WithTimeout(request.Context(), time.Second)
				defer stop()
				if _, err := db.QuerySecurityEnrichmentRefreshTargets(bounded, "", 200); err != nil {
					t.Fatalf("SQL lock retained over fake fetch: %v", err)
				}
				return &http.Response{StatusCode: 200, ContentLength: int64(len(encoded)), Body: body}, nil
			}), map[string]HTTPSourceProfile{source: {URL: "https://fixture.invalid/synthetic/input", Encoding: encoding}})
			if err != nil {
				t.Fatal(err)
			}
			h.service.Fetcher = f
			h.repo.completeAfter, h.repo.reconcileError = true, true
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: source + "_feed", Limit: 200})
			assertPending(t, h, out, err)
			if out.Pending.Completion == nil {
				t.Fatal("decoded completion not retained")
			}
			c := *out.Pending.Completion
			if c.OriginalDigest != fmt.Sprintf("sha256:%x", sha256.Sum256(decoded)) || c.Feed.Source != source || !c.Feed.ObservedAt.Equal(h.times[1]) || c.Feed.PublishedAt.Equal(c.Feed.ObservedAt) {
				t.Fatalf("decoded digest/source/independent clock changed: %+v", c)
			}
			if encoding == "gzip" && c.OriginalDigest == fmt.Sprintf("sha256:%x", sha256.Sum256(encoded)) {
				t.Fatal("compressed input digest mislabeled as decoded parser digest")
			}
			state, err := db.ReconcileSecurityEnrichmentRefresh(context.Background(), c)
			if err != nil || state.State != "success" || state.Receipt == "" {
				t.Fatalf("decoded completion failed receipt verification: %+v %v", state, err)
			}
			page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 200})
			if err != nil || len(page.Items) != 1 {
				t.Fatalf("common read failed: %+v %v", page, err)
			}
			e := page.Enrichments[page.Items[0].ID]
			if source == "epss" {
				if e.EPSS == nil || e.EPSS.Source != "epss" || e.EPSS.EPSS == nil || *e.EPSS.EPSS != 0 || e.EPSS.RunID != c.Attempt.RunID {
					t.Fatal("known zero EPSS/provenance absent")
				}
			} else if e.KEV == nil || e.KEV.Source != "kev" || !e.KEV.KEV || e.KEV.RunID != c.Attempt.RunID {
				t.Fatal("known positive KEV/provenance absent")
			}
		})
	}
}

func TestBoundedHTTPFetcherFailuresPersistOnlyClosedCodes(t *testing.T) {
	for _, kind := range []string{"read-error", "missing-metadata"} {
		t.Run(kind, func(t *testing.T) {
			db := contractStore(t, true)
			h := harness(t, db)
			body := &boundedProbeBody{reader: strings.NewReader("PRIVATE-synthetic-body")}
			length := int64(len("PRIVATE-synthetic-body"))
			wantCode := "parse_failed"
			if kind == "read-error" {
				body.reader = boundedReadFunc(func([]byte) (int, error) { return 0, errors.New("PRIVATE-synthetic-read-error") })
				length, wantCode = -1, "fetch_failed"
			}
			f, _ := boundedFake(t, "identity", &http.Response{StatusCode: 200, ContentLength: length, Body: body}, nil)
			h.service.Fetcher = f
			out, err := h.service.RefreshOnce(context.Background(), Request{Connector: "epss_feed", Limit: 200})
			if err != nil || out.Outcome != "failed" || out.Code != wantCode || out.Advance {
				t.Fatalf("failure code changed: %+v %v", out, err)
			}
			runs, err := db.QueryIngestRuns(context.Background())
			if err != nil || strings.Contains(jsonValue(t, runs), "PRIVATE") || strings.Contains(jsonValue(t, out), "PRIVATE") {
				t.Fatalf("untrusted error/body persisted in receipt: %+v %v", runs, err)
			}
			page, err := db.QueryFindingsPage(context.Background(), store.FindingQuery{Limit: 200})
			if err != nil || len(page.Enrichments) != 0 {
				t.Fatal("invalid input created enrichment observations")
			}
		})
	}
}

type boundedDecodeCancelContext struct {
	context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	rawEOF bool
	checks int
}

func (c *boundedDecodeCancelContext) Err() error {
	c.mu.Lock()
	if c.rawEOF {
		c.checks++
	}
	cancelNow := c.rawEOF && c.checks == 3
	c.mu.Unlock()
	if cancelNow {
		c.cancel()
	}
	return c.Context.Err()
}

func TestBoundedHTTPFetcherChecksContextAtDecodeBoundary(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &boundedDecodeCancelContext{Context: base, cancel: cancel}
	raw := boundedGzip(t, []byte("synthetic decoded bytes"))
	reader := bytes.NewReader(raw)
	body := &boundedProbeBody{reader: boundedReadFunc(func(p []byte) (int, error) {
		n, err := reader.Read(p)
		if err == io.EOF {
			ctx.mu.Lock()
			ctx.rawEOF = true
			ctx.mu.Unlock()
		}
		return n, err
	})}
	// After raw EOF: read's post-check, the raw-boundary check, then the
	// decoder's context-aware Read check. Cancel without timers or live I/O.
	f, _ := boundedFake(t, "gzip", &http.Response{StatusCode: 200, ContentLength: int64(len(raw)), Body: body}, nil)
	data, err := f.Fetch(ctx, "epss")
	if !errors.Is(err, context.Canceled) || data != nil || base.Err() == nil {
		t.Fatalf("decode-boundary cancellation became data: %d %v", len(data), err)
	}
	if closes, _ := body.counts(); closes != 1 {
		t.Fatalf("decode-boundary body closes=%d", closes)
	}
}

func TestBoundedHTTPFetcherValidHeadersAndContextErrors(t *testing.T) {
	body := &boundedProbeBody{reader: strings.NewReader("abc")}
	response := &http.Response{StatusCode: 200, ContentLength: 3, Body: body, Header: http.Header{"content-length": {"3"}, "content-encoding": {" Identity "}}}
	f, _ := boundedFake(t, "identity", response, nil)
	data, err := f.Fetch(context.Background(), "epss")
	if err != nil || string(data) != "abc" {
		t.Fatalf("valid explicit length/identity coding rejected: %q %v", data, err)
	}
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		body := &boundedProbeBody{reader: strings.NewReader("abc")}
		f, _ := boundedFake(t, "identity", &http.Response{StatusCode: 200, ContentLength: 3, Body: body}, cause)
		data, err := f.Fetch(context.Background(), "epss")
		if !errors.Is(err, cause) || data != nil {
			t.Fatalf("context cause lost: %d %v", len(data), err)
		}
		if closes, _ := body.counts(); closes != 1 {
			t.Fatalf("context error body closes=%d", closes)
		}
	}
	var nilBody *boundedProbeBody
	f, _ = boundedFake(t, "identity", &http.Response{StatusCode: 200, Body: nilBody}, nil)
	if data, err := f.Fetch(context.Background(), "epss"); err == nil || data != nil {
		t.Fatal("typed-nil body accepted")
	}
	for _, zero := range []*BoundedHTTPFetcher{nil, {}} {
		if data, err := zero.Fetch(context.Background(), "epss"); err == nil || data != nil {
			t.Fatal("zero-value fetcher acquired a default transport")
		}
	}
	if data, err := f.Fetch(nil, "epss"); err == nil || data != nil { //nolint:staticcheck // nil context is the test input: Fetch must reject it explicitly
		t.Fatal("nil context accepted")
	}
}
