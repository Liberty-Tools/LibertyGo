// Package libertygo provides a native Go client for ER:LC Private Server API v2
// and Liberty Tools webhook/Poll connections.
package libertygo

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultAPIURL = "https://api.erlc.gg/v2/"
	DefaultLibertyAPIURL = "https://api.libertytools.dev/"
	DefaultWebhookPublicKey = "MCowBQYDK2VwAyEAjSICb9pp0kHizGQtdG8ySWsDChfGqi+gyFCttigBNOA="
)

type ServerOption string

const (
	Players ServerOption = "Players"
	Staff ServerOption = "Staff"
	JoinLogs ServerOption = "JoinLogs"
	Queue ServerOption = "Queue"
	KillLogs ServerOption = "KillLogs"
	CommandLogs ServerOption = "CommandLogs"
	ModCalls ServerOption = "ModCalls"
	EmergencyCalls ServerOption = "EmergencyCalls"
	Vehicles ServerOption = "Vehicles"
)

var validOptions = map[ServerOption]bool{Players: true, Staff: true, JoinLogs: true, Queue: true, KillLogs: true, CommandLogs: true, ModCalls: true, EmergencyCalls: true, Vehicles: true}

type Options struct {
	ServerKey string
	GlobalAPIKey string
	Authorization string // alias for GlobalAPIKey
	APIURL string
	WebhookURL string
	WebhookID string
	WebhookToken string // alias for WebhookID
	WebhookIngestURL string
	PollSubscriptionID string
	PollToken string
	LibertyAPIURL string
	WebhookPublicKey string // base64 DER/SPKI Ed25519 public key
	MaxRateLimitRetries int
	DisableRateLimitRetries bool
	HTTPClient *http.Client
}

type Client struct {
	ServerKey string
	GlobalAPIKey string
	BaseURL string
	HTTP *http.Client
	MaxRateLimitRetries int
	webhookBase string
	webhookID string
	ingestURL string
	pollSubscriptionID string
	pollToken string
	webhookPublicKey string
	mu sync.Mutex
	forbiddenErrors int
}

func New(serverKey string) *Client {
	c, _ := NewWithOptions(Options{ServerKey: serverKey, APIURL: DefaultAPIURL, LibertyAPIURL: DefaultLibertyAPIURL, MaxRateLimitRetries: 3})
	return c
}

func NewWithOptions(options Options) (*Client, error) {
	if strings.TrimSpace(options.ServerKey) == "" { return nil, errors.New("server key is required") }
	if options.GlobalAPIKey != "" && options.Authorization != "" && options.GlobalAPIKey != options.Authorization { return nil, errors.New("GlobalAPIKey and Authorization must match") }
	if options.MaxRateLimitRetries < 0 { return nil, errors.New("MaxRateLimitRetries must be non-negative") }
	if options.MaxRateLimitRetries == 0 && !options.DisableRateLimitRetries { options.MaxRateLimitRetries = 3 }
	global := options.GlobalAPIKey
	if global == "" { global = options.Authorization }
	apiURL := options.APIURL
	if apiURL == "" { apiURL = DefaultAPIURL }
	apiURL, err := normalizeBaseURL(apiURL)
	if err != nil { return nil, fmt.Errorf("invalid APIURL: %w", err) }
	c := &Client{ServerKey: options.ServerKey, GlobalAPIKey: global, BaseURL: apiURL, HTTP: options.HTTPClient, MaxRateLimitRetries: options.MaxRateLimitRetries, webhookPublicKey: options.WebhookPublicKey}
	if c.HTTP == nil { c.HTTP = http.DefaultClient }
	if c.webhookPublicKey == "" { c.webhookPublicKey = DefaultWebhookPublicKey }
	libertyURL := options.LibertyAPIURL
	if libertyURL == "" { libertyURL = DefaultLibertyAPIURL }
	if options.PollSubscriptionID != "" || options.PollToken != "" {
		if options.PollSubscriptionID == "" || options.PollToken == "" { return nil, errors.New("PollSubscriptionID and PollToken are both required") }
		c.webhookBase, err = normalizeBaseURL(libertyURL)
		if err != nil { return nil, fmt.Errorf("invalid LibertyAPIURL: %w", err) }
		c.pollSubscriptionID, c.pollToken = options.PollSubscriptionID, options.PollToken
		if options.WebhookIngestURL != "" { c.ingestURL, err = normalizeURL(options.WebhookIngestURL); if err != nil { return nil, fmt.Errorf("invalid WebhookIngestURL: %w", err) } }
	} else {
		webhookID := options.WebhookID
		if webhookID == "" { webhookID = options.WebhookToken }
		if options.WebhookID != "" && options.WebhookToken != "" && extractWebhookID(options.WebhookID) != extractWebhookID(options.WebhookToken) { return nil, errors.New("WebhookID and WebhookToken must identify the same webhook") }
		if options.WebhookURL != "" && webhookID == "" { return nil, errors.New("WebhookID is required when WebhookURL is configured") }
		if webhookID != "" {
			if options.WebhookURL != "" { c.webhookBase, err = normalizeBaseURL(options.WebhookURL) } else { c.webhookBase, err = normalizeBaseURL(libertyURL) }
			if err != nil { return nil, fmt.Errorf("invalid WebhookURL: %w", err) }
			c.webhookID = extractWebhookID(webhookID)
		}
	}
	return c, nil
}

func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil { return "", err }
	if u.Scheme == "" || u.Host == "" { return "", errors.New("URL must be absolute") }
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	return u.String(), nil
}

func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" { return "", errors.New("URL must be absolute") }
	return u.String(), nil
}

func extractWebhookID(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" { return "" }
	u, err := url.Parse(raw)
	if err == nil && u.Path != "" { raw = u.Path }
	parts := strings.Split(strings.Trim(raw, "/"), "/")
	if len(parts) == 0 { return "" }
	if strings.EqualFold(parts[len(parts)-1], "events") && len(parts) > 1 { return parts[len(parts)-2] }
	return parts[len(parts)-1]
}

func (c *Client) GetPrivateServerAPI(ctx context.Context, fields []ServerOption) (any, error) {
	u, err := url.Parse(c.BaseURL + "server")
	if err != nil { return nil, err }
	q := u.Query(); seen := map[ServerOption]bool{}
	for _, field := range fields { if validOptions[field] && !seen[field] { q.Set(string(field), "true"); seen[field] = true } }
	u.RawQuery = q.Encode()
	return c.request(ctx, http.MethodGet, u.String(), nil, nil)
}

type CommandSummary struct {
	Successes int `json:"successes"`
	Failures int `json:"failures"`
	FailureReasons []any `json:"failureReasons"`
	Results []map[string]any `json:"results"`
}

func (c *Client) SendPrivateServerCommand(ctx context.Context, commands []string) (CommandSummary, error) {
	summary := CommandSummary{FailureReasons: []any{}, Results: []map[string]any{}}
	if len(commands) == 0 { return summary, errors.New("commands must contain at least one item") }
	for _, raw := range commands {
		command := strings.TrimSpace(raw)
		if command == "" { summary.Failures++; summary.FailureReasons = append(summary.FailureReasons, map[string]any{"command": raw, "error": "Command must be a non-empty string"}); continue }
		response, err := c.request(ctx, http.MethodPost, c.BaseURL+"server/command", map[string]string{"command": command}, nil)
		if err != nil { return summary, err }
		summary.Results = append(summary.Results, map[string]any{"command": command, "response": response})
		if object, ok := response.(map[string]any); ok { if _, failed := object["error"]; failed { summary.Failures++; summary.FailureReasons = append(summary.FailureReasons, map[string]any{"command": command, "status": object["status"], "code": object["code"], "apiResponse": object["apiResponse"]}); continue } }
		summary.Successes++
	}
	return summary, nil
}

func (c *Client) request(ctx context.Context, method, endpoint string, payload any, extraHeaders http.Header) (any, error) {
	if strings.TrimSpace(c.ServerKey) == "" { return nil, errors.New("server key is required") }
	isERLC := sameOrigin(endpoint, c.BaseURL)
	if isERLC {
		c.mu.Lock(); suspended := c.forbiddenErrors >= 3; c.mu.Unlock()
		if suspended { return map[string]any{"error":"forbidden","message":"Repeated authentication failures; API calls for this server key are suspended","status":403},nil }
	}
	var body []byte
	var err error
	if payload != nil { body, err = json.Marshal(payload); if err != nil { return nil, err } }
	for attempt := 0; attempt <= c.MaxRateLimitRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body)); if err != nil { return nil, err }
		if extraHeaders != nil { req.Header = extraHeaders.Clone() }
		if isERLC {
			req.Header.Set("server-key", c.ServerKey)
			if c.GlobalAPIKey != "" { req.Header.Set("Authorization", c.GlobalAPIKey) }
		}
		if payload != nil { req.Header.Set("Content-Type", "application/json") }
		resp, err := c.HTTP.Do(req)
		if err != nil { if ctx.Err() != nil { return map[string]any{"error":"network-error","message":"Request aborted"}, nil }; return map[string]any{"error":"network-error","message":fmt.Sprintf("Network error: %v", err)}, nil }
		dataBytes, readErr := io.ReadAll(resp.Body); resp.Body.Close(); if readErr != nil { return nil, readErr }
		var decoded any; if len(dataBytes) > 0 { _ = json.Unmarshal(dataBytes, &decoded) }
		if resp.StatusCode == http.StatusTooManyRequests && attempt < c.MaxRateLimitRetries {
			delay := retryAfter(resp, decoded)
			if err := waitContext(ctx, delay); err != nil { return map[string]any{"error":"network-error","message":"Request aborted"}, nil }
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			code := any(nil); if m, ok := decoded.(map[string]any); ok { code = m["code"] }
			kind := "api-error"; if resp.StatusCode == http.StatusTooManyRequests { kind = "rate-limited" }
			result := map[string]any{"error":kind,"message":fmt.Sprintf("HTTP %d %s", resp.StatusCode, resp.Status),"status":resp.StatusCode,"statusText":http.StatusText(resp.StatusCode),"headers":headersMap(resp.Header),"apiResponse":decoded}
			if code != nil { result["code"] = code }; if resp.StatusCode == http.StatusTooManyRequests { result["retryAfter"] = retryAfter(resp, decoded).Seconds() }
			if resp.StatusCode == http.StatusForbidden && isERLC {
				if m, ok := decoded.(map[string]any); ok {
					switch fmt.Sprint(m["code"]) { case "2000", "2001", "2002", "2003", "2004": c.mu.Lock(); c.forbiddenErrors++; c.mu.Unlock() }
				}
			}
			return result, nil
		}
		c.mu.Lock(); c.forbiddenErrors = 0; c.mu.Unlock()
		return decoded, nil
	}
	return nil, errors.New("unreachable retry state")
}

func sameOrigin(a, b string) bool { ua, ea := url.Parse(a); ub, eb := url.Parse(b); return ea == nil && eb == nil && ua.Scheme == ub.Scheme && ua.Host == ub.Host }
func headersMap(h http.Header) map[string]string { out := map[string]string{}; for k, v := range h { if len(v)>0 { out[strings.ToLower(k)] = v[0] } }; return out }
func retryAfter(resp *http.Response, data any) time.Duration {
	if raw := resp.Header.Get("Retry-After"); raw != "" { if seconds, err := strconv.ParseFloat(raw,64); err == nil && seconds >= 0 { return time.Duration(seconds*float64(time.Second)) } }
	if m, ok := data.(map[string]any); ok { if raw, ok := m["retry_after"]; ok { if seconds, err := strconv.ParseFloat(fmt.Sprint(raw),64); err == nil && seconds >= 0 { return time.Duration(seconds*float64(time.Second)) } } }
	if raw := resp.Header.Get("X-RateLimit-Reset"); raw != "" { if epoch, err := strconv.ParseFloat(raw,64); err == nil { d := time.Until(time.UnixMilli(int64(epoch*1000))); if d > 0 { return d }; return 0 } }
	return time.Second
}
func waitContext(ctx context.Context, d time.Duration) error { timer:=time.NewTimer(d); defer timer.Stop(); select { case <-ctx.Done(): return ctx.Err(); case <-timer.C: return nil } }

// WebhookURL returns the configured ER:LC webhook ingest/forward URL, if any.
func (c *Client) WebhookURL() string {
	if c.ingestURL != "" { return c.ingestURL }
	if c.pollSubscriptionID != "" || c.webhookID == "" { return "" }
	u, _ := url.Parse(c.webhookBase); u.Path = strings.TrimRight(u.Path,"/")+"/webhook/"+url.PathEscape(c.webhookID); return u.String()
}

func (c *Client) WebhookStatus(ctx context.Context) (any,error) {
	if c.webhookBase == "" { return map[string]any{"error":"webhook_disabled","message":"Webhook relay is not configured"},nil }
	return c.request(ctx,http.MethodGet,c.webhookBase+"health",nil,nil)
}

type EventListOptions struct { Cursor string; Limit int }

func (c *Client) ListEvents(ctx context.Context, options EventListOptions) (any,error) {
	if c.webhookBase == "" { return map[string]any{"error":"webhook_disabled","message":"Webhook relay is not configured"},nil }
	if options.Limit != 0 && (options.Limit < 1 || options.Limit > 100) { return nil,errors.New("limit must be between 1 and 100") }
	var path string
	if c.pollSubscriptionID != "" { path="v1/poll/subscriptions/"+url.PathEscape(c.pollSubscriptionID)+"/events" } else { if c.webhookID=="" { return map[string]any{"error":"webhook_disabled","message":"Webhook relay is not configured"},nil }; path="webhook/"+url.PathEscape(c.webhookID)+"/events" }
	u,_:=url.Parse(c.webhookBase+path); q:=u.Query(); if c.pollSubscriptionID!="" { if options.Cursor!="" {q.Set("cursor",options.Cursor)}; if options.Limit>0 {q.Set("limit",strconv.Itoa(options.Limit))} }; u.RawQuery=q.Encode()
	headers:=http.Header{}; if c.pollToken!="" {headers.Set("Authorization","Bearer "+c.pollToken)}
	return c.request(ctx,http.MethodGet,u.String(),nil,headers)
}

func (c *Client) AcknowledgeEvents(ctx context.Context, eventIDs []string) (any,error) {
	if c.pollSubscriptionID=="" || c.pollToken=="" { return map[string]any{"error":"webhook_disabled","message":"v2 Poll mode is not configured"},nil }
	endpoint:=c.webhookBase+"v1/poll/subscriptions/"+url.PathEscape(c.pollSubscriptionID)+"/events/acknowledge"
	headers:=http.Header{}; headers.Set("Authorization","Bearer "+c.pollToken)
	return c.request(ctx,http.MethodPost,endpoint,map[string][]string{"eventIds":eventIDs},headers)
}

type WebhookVerificationInput struct { Timestamp string; Signature string; RawBody []byte; PublicKey string }

// VerifyWebhook validates ER:LC's Ed25519 signature over timestamp concatenated with the exact raw body.
func (c *Client) VerifyWebhook(input WebhookVerificationInput) bool {
	if input.Timestamp=="" || input.Signature=="" { return false }
	ts,err:=strconv.ParseFloat(input.Timestamp,64); if err!=nil {return false}; if ts>10_000_000_000 { ts/=1000 }; if mathAbs(float64(time.Now().UnixMilli())/1000-ts)>300 {return false}
	sig,err:=hex.DecodeString(input.Signature); if err!=nil {return false}
	encoded:=input.PublicKey; if encoded=="" {encoded=c.webhookPublicKey}; der,err:=base64.StdEncoding.DecodeString(encoded); if err!=nil || len(der)<ed25519.PublicKeySize {return false}
	// The key is SPKI DER: the final 32 bytes are the raw Ed25519 public key.
	key:=ed25519.PublicKey(der[len(der)-ed25519.PublicKeySize:]); message:=append([]byte(input.Timestamp),input.RawBody...)
	return ed25519.Verify(key,message,sig)
}
func mathAbs(v float64) float64 { if v<0 {return -v}; return v }

// StableEventID returns a deterministic ID for events that omit id/_id.
func StableEventID(raw any) string { encoded,_:=json.Marshal(raw); sum:=sha256.Sum256(encoded); return hex.EncodeToString(sum[:]) }

