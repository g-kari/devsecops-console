package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/g-kari/dependabot-alert-notice/internal/enrichmentrefresh"
)

const manualAPIRoot = "/api/tui/enrichment-refresh"
const manualAPIMaxBody = 1024

// SetManualEnrichmentController installs one explicitly created controller.
// Nil clearing and replacement with a different instance are rejected; repeating
// the same pointer is a no-op. It never constructs Service dependencies.
func (s *Server) SetManualEnrichmentController(controller *enrichmentrefresh.ManualController) error {
	if s == nil || controller == nil {
		return errors.New("manual enrichment API: controller is required")
	}
	s.manualRefreshMu.Lock()
	defer s.manualRefreshMu.Unlock()
	if s.manualRefreshController != nil && s.manualRefreshController != controller {
		return errors.New("manual enrichment API: controller already set")
	}
	s.manualRefreshController = controller
	return nil
}

func (s *Server) manualEnrichmentControllerSnapshot() *enrichmentrefresh.ManualController {
	s.manualRefreshMu.RLock()
	defer s.manualRefreshMu.RUnlock()
	return s.manualRefreshController
}

type manualAPIRequest struct {
	OperationID string
	Connector   string
	After       string
	Limit       int
}

type manualAPIBinding struct {
	Connector string `json:"connector"`
	After     string `json:"after"`
	Limit     int    `json:"limit"`
}

// Deliberately no embedded ManualOperation/Result or internal Pending fields.
type manualAPIResponse struct {
	OperationID string           `json:"operation_id"`
	Request     manualAPIBinding `json:"request"`
	State       string           `json:"state"`
	Replay      bool             `json:"replay"`
	Outcome     string           `json:"outcome"`
	Code        string           `json:"code"`
	RunID       string           `json:"run_id"`
	Scanned     int              `json:"scanned"`
	TargetCount int              `json:"target_count"`
	NextAfter   string           `json:"next_after"`
	Advance     bool             `json:"advance"`
	Exhausted   bool             `json:"exhausted"`
}

func manualAPIWrite(w http.ResponseWriter, r *http.Request, status int, value any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		// The controller already owns the outcome. Never redispatch on a write
		// failure, and never log response bytes or underlying error text.
		slog.ErrorContext(r.Context(), "manual enrichment API response failed")
	}
}

func manualAPIError(w http.ResponseWriter, r *http.Request, status int, code string) {
	manualAPIWrite(w, r, status, struct {
		Code string `json:"code"`
	}{Code: code})
}

func manualAPINamespace(value string) bool {
	return value == manualAPIRoot || strings.HasPrefix(value, manualAPIRoot+"/")
}

// serveManualEnrichmentAPI is a narrow outer dispatcher. No patterns are added
// to the legacy mux, whose GET / subtree conflicts with methodless API patterns.
// Matching even an unclean path before ServeMux also prevents its redirects.
func (s *Server) serveManualEnrichmentAPI(w http.ResponseWriter, r *http.Request) bool {
	clean := path.Clean(r.URL.Path)
	if !manualAPINamespace(r.URL.Path) && !manualAPINamespace(clean) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if message, _ := localTUIRequestFailure(r); message != "" {
		manualAPIError(w, r, http.StatusForbidden, "local_access_denied")
		return true
	}
	if r.Context().Err() != nil {
		manualAPIError(w, r, http.StatusRequestTimeout, "canceled")
		return true
	}
	if r.URL.RawPath != "" || r.URL.Path != clean || r.URL.RawQuery != "" || r.URL.ForceQuery {
		manualAPIError(w, r, http.StatusBadRequest, "invalid_request")
		return true
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, manualAPIRoot), "/")
	kind, method, id := "", "", ""
	switch {
	case len(parts) == 2 && parts[1] == "operations":
		kind, method = "call", http.MethodPost
	case len(parts) == 3 && parts[1] == "operations":
		kind, method, id = "snapshot", http.MethodGet, parts[2]
	case len(parts) == 4 && parts[1] == "operations" && parts[3] == "reconcile":
		kind, method, id = "reconcile", http.MethodPost, parts[2]
	default:
		manualAPIError(w, r, http.StatusNotFound, "not_found")
		return true
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		manualAPIError(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return true
	}
	if id != "" && !manualAPIOperationID(id) {
		manualAPIError(w, r, http.StatusBadRequest, "invalid_request")
		return true
	}
	if !manualAPIMedia(r, method == http.MethodPost) {
		manualAPIError(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return true
	}
	data, status := manualAPIReadBody(r)
	if status != 0 {
		code := "invalid_request"
		switch status {
		case http.StatusRequestEntityTooLarge:
			code = "body_too_large"
		case http.StatusRequestTimeout:
			code = "canceled"
		}
		manualAPIError(w, r, status, code)
		return true
	}
	var request manualAPIRequest
	if kind == "call" {
		var ok bool
		request, ok = manualAPIParseCall(data)
		if !ok {
			manualAPIError(w, r, http.StatusBadRequest, "invalid_request")
			return true
		}
	} else if kind == "reconcile" {
		if _, ok := manualAPIObject(data); !ok {
			manualAPIError(w, r, http.StatusBadRequest, "invalid_request")
			return true
		}
	} else if len(data) != 0 {
		manualAPIError(w, r, http.StatusBadRequest, "invalid_request")
		return true
	}
	if r.Context().Err() != nil {
		manualAPIError(w, r, http.StatusRequestTimeout, "canceled")
		return true
	}
	controller := s.manualEnrichmentControllerSnapshot()
	if controller == nil {
		manualAPIError(w, r, http.StatusServiceUnavailable, "disabled")
		return true
	}
	switch kind {
	case "call":
		operation, replay, err := controller.Call(r.Context(), request.OperationID, enrichmentrefresh.Request{Connector: request.Connector, After: request.After, Limit: request.Limit})
		manualAPIWriteOperation(w, r, operation, replay, err)
	case "snapshot":
		operation, ok := controller.Snapshot(id)
		if !ok {
			manualAPIError(w, r, http.StatusNotFound, "not_found")
		} else {
			manualAPIWriteOperation(w, r, operation, false, nil)
		}
	case "reconcile":
		operation, err := controller.Reconcile(r.Context(), id)
		manualAPIWriteOperation(w, r, operation, false, err)
	}
	return true
}

func manualAPIHeaderValues(header http.Header, name string) []string {
	var values []string
	for key, value := range header {
		if strings.EqualFold(key, name) {
			values = append(values, value...)
		}
	}
	return values
}

func manualAPIMedia(r *http.Request, post bool) bool {
	coding := manualAPIHeaderValues(r.Header, "Content-Encoding")
	if len(coding) > 1 || (len(coding) == 1 && coding[0] != "" && !strings.EqualFold(coding[0], "identity")) {
		return false
	}
	values := manualAPIHeaderValues(r.Header, "Content-Type")
	if !post {
		return len(values) == 0
	}
	if len(values) != 1 {
		return false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" || len(params) > 1 {
		return false
	}
	for key, value := range params {
		if key != "charset" || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func manualAPIReadBody(r *http.Request) ([]byte, int) {
	if r.ContentLength < -1 {
		return nil, http.StatusBadRequest
	}
	if r.ContentLength > manualAPIMaxBody {
		return nil, http.StatusRequestEntityTooLarge
	}
	var data []byte
	var err error
	if r.Body != nil {
		data, err = io.ReadAll(io.LimitReader(r.Body, manualAPIMaxBody+1))
	}
	if r.Context().Err() != nil {
		return nil, http.StatusRequestTimeout
	}
	if len(data) > manualAPIMaxBody {
		return nil, http.StatusRequestEntityTooLarge
	}
	if err != nil || (r.ContentLength >= 0 && int64(len(data)) != r.ContentLength) || !utf8.Valid(data) {
		return nil, http.StatusBadRequest
	}
	return data, 0
}

func manualAPIOperationID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i, c := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func manualAPIParseCall(data []byte) (manualAPIRequest, bool) {
	values, ok := manualAPIObject(data, "operation_id", "connector", "after", "limit")
	if !ok {
		return manualAPIRequest{}, false
	}
	id, a := values["operation_id"].(string)
	connector, b := values["connector"].(string)
	after, c := values["after"].(string)
	number, d := values["limit"].(json.Number)
	limit, err := strconv.Atoi(string(number))
	if !a || !b || !c || !d || err != nil || !manualAPIOperationID(id) || (connector != "epss_feed" && connector != "kev_feed") || limit < 1 || limit > 200 || len(after) > 128 || !utf8.ValidString(after) || strings.ContainsFunc(after, func(c rune) bool { return unicode.IsControl(c) || unicode.Is(unicode.Cf, c) }) {
		return manualAPIRequest{}, false
	}
	return manualAPIRequest{OperationID: id, Connector: connector, After: after, Limit: limit}, true
}

// manualAPIObject accepts exactly one flat object with exactly the named fields.
// Tokens preserve types (not null-to-zero conversions) and decoded duplicate keys.
func manualAPIObject(data []byte, fields ...string) (map[string]any, bool) {
	if !manualAPIStringEncoding(data) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	values := make(map[string]any, len(fields))
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, stringKey := keyToken.(string)
		if err != nil || !stringKey {
			return nil, false
		}
		known := false
		for _, name := range fields {
			known = known || key == name
		}
		if _, duplicate := values[key]; !known || duplicate {
			return nil, false
		}
		value, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		if _, nested := value.(json.Delim); nested {
			return nil, false
		}
		values[key] = value
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(values) != len(fields) {
		return nil, false
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, false
	}
	return values, true
}

// Reject malformed UTF-16 escapes rather than encoding/json's replacement rune.
// Valid pairs remain equivalent to the corresponding literal UTF-8 scalar.
func manualAPIStringEncoding(data []byte) bool {
	if !utf8.Valid(data) {
		return false
	}
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		} else if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
	}
	return !inString
}

func manualAPIErrorStatus(err error) (int, string) {
	switch {
	case err == nil:
		return http.StatusOK, ""
	case errors.Is(err, enrichmentrefresh.ErrPending):
		return http.StatusConflict, "pending"
	case errors.Is(err, enrichmentrefresh.ErrManualBusy):
		return http.StatusConflict, "busy"
	case errors.Is(err, enrichmentrefresh.ErrManualConflict):
		return http.StatusConflict, "operation_conflict"
	case errors.Is(err, enrichmentrefresh.ErrManualPendingSource):
		return http.StatusConflict, "source_pending"
	case errors.Is(err, enrichmentrefresh.ErrManualCapacity):
		return http.StatusServiceUnavailable, "retention_full"
	case errors.Is(err, enrichmentrefresh.ErrManualNotFound):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, enrichmentrefresh.ErrManualInvalid):
		return http.StatusBadRequest, "invalid_request"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return http.StatusRequestTimeout, "canceled"
	case errors.Is(err, enrichmentrefresh.ErrManualExecution):
		return http.StatusInternalServerError, "execution_failed"
	default:
		return http.StatusInternalServerError, "internal_error"
	}
}

func manualAPIResultCode(code string) string {
	switch code {
	case "", "invalid_context", "missing_dependency", "invalid_source", "invalid_query", "scan_failed", "invalid_page", "invalid_clock", "invalid_uuid", "begin_unknown", "begin_replay", "begin_readback_unknown", "canceled", "fetch_failed", "invalid_metadata", "parse_failed", "failure_unknown", "completion_unknown":
		return code
	default:
		return "operation_error"
	}
}

func manualAPIWriteOperation(w http.ResponseWriter, r *http.Request, operation enrichmentrefresh.ManualOperation, replay bool, err error) {
	status, code := manualAPIErrorStatus(err)
	if operation.OperationID == "" {
		if code == "" {
			status, code = http.StatusInternalServerError, "internal_error"
		}
		manualAPIError(w, r, status, code)
		return
	}
	switch operation.State {
	case "calling", "pending", "resolved":
	default:
		manualAPIError(w, r, http.StatusInternalServerError, "internal_error")
		return
	}
	if code == "" {
		code = manualAPIResultCode(operation.Result.Code)
	}
	manualAPIWrite(w, r, status, manualAPIResponse{
		OperationID: operation.OperationID,
		Request:     manualAPIBinding{Connector: operation.Request.Connector, After: operation.Request.After, Limit: operation.Request.Limit},
		State:       operation.State, Replay: replay, Outcome: operation.Result.Outcome,
		Code: code, RunID: operation.Result.RunID, Scanned: operation.Result.Scanned,
		TargetCount: operation.Result.Targets, NextAfter: operation.Result.NextAfter,
		Advance: operation.Result.Advance, Exhausted: operation.Result.Exhausted,
	})
}
