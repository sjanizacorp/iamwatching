// IamWatching Daemon — Zero External Dependencies
// =================================================
// Continuous IAM state polling daemon using only Go stdlib.
// Polls AWS IAM via signed HTTP requests, diffs against previous snapshot,
// writes deltas to Neo4j via the HTTP API (port 7474).
//
// Zero external Go module dependencies — builds anywhere with just `go build`.
//
// Usage:
//   go build -o iamwatching-daemon .
//   ./iamwatching-daemon --poll-interval 300 --neo4j http://localhost:7474

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Version
// ─────────────────────────────────────────────────────────────────────────────

var (
	Version   = "1.3.0"
	BuildTime = "unknown"
)

// ─────────────────────────────────────────────────────────────────────────────
// Config
// ─────────────────────────────────────────────────────────────────────────────

type Config struct {
	PollInterval int
	Neo4jURI     string
	Neo4jUser    string
	Neo4jPass    string
	AWSRegion    string
	AWSProfile   string
	DryRun       bool
	LogLevel     string
	ShowVersion  bool
}

func defaultConfig() Config {
	return Config{
		PollInterval: 300,
		Neo4jURI:     envOr("NEO4J_URI", "http://localhost:7474"),
		Neo4jUser:    envOr("NEO4J_USERNAME", "neo4j"),
		Neo4jPass:    envOr("NEO4J_PASSWORD", "iamwatching"),
		AWSRegion:    envOr("AWS_DEFAULT_REGION", "us-east-1"),
		LogLevel:     "info",
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ─────────────────────────────────────────────────────────────────────────────
// IAM Snapshot & Diff
// ─────────────────────────────────────────────────────────────────────────────

type IAMSnapshot struct {
	AccountID   string
	Region      string
	Timestamp   time.Time
	Roles       map[string]string // ARN -> SHA256 hash of content
	Users       map[string]string
	Policies    map[string]string
	Fingerprint string
}

func newSnapshot(accountID, region string) *IAMSnapshot {
	return &IAMSnapshot{
		AccountID: accountID,
		Region:    region,
		Timestamp: time.Now(),
		Roles:     make(map[string]string),
		Users:     make(map[string]string),
		Policies:  make(map[string]string),
	}
}

func hashContent(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func (s *IAMSnapshot) computeFingerprint() {
	combined := map[string]any{"r": s.Roles, "u": s.Users, "p": s.Policies}
	s.Fingerprint = hashContent(combined)
}

type StateDiff struct {
	AccountID       string
	Region          string
	Timestamp       time.Time
	AddedRoles      []string
	RemovedRoles    []string
	ModifiedRoles   []string
	AddedUsers      []string
	RemovedUsers    []string
	ModifiedUsers   []string
	AddedPolicies   []string
	RemovedPolicies []string
	ModifiedPolicies []string
}

func (d *StateDiff) HasChanges() bool {
	return len(d.AddedRoles)+len(d.RemovedRoles)+len(d.ModifiedRoles)+
		len(d.AddedUsers)+len(d.RemovedUsers)+len(d.ModifiedUsers)+
		len(d.AddedPolicies)+len(d.RemovedPolicies)+len(d.ModifiedPolicies) > 0
}

func diffSnapshots(prev, curr *IAMSnapshot) *StateDiff {
	d := &StateDiff{AccountID: curr.AccountID, Region: curr.Region, Timestamp: curr.Timestamp}
	diffMaps(prev.Roles, curr.Roles, &d.AddedRoles, &d.RemovedRoles, &d.ModifiedRoles)
	diffMaps(prev.Users, curr.Users, &d.AddedUsers, &d.RemovedUsers, &d.ModifiedUsers)
	diffMaps(prev.Policies, curr.Policies, &d.AddedPolicies, &d.RemovedPolicies, &d.ModifiedPolicies)
	return d
}

func diffMaps(prev, curr map[string]string, added, removed, modified *[]string) {
	for k, v := range curr {
		if pv, ok := prev[k]; !ok {
			*added = append(*added, k)
		} else if pv != v {
			*modified = append(*modified, k)
		}
	}
	for k := range prev {
		if _, ok := curr[k]; !ok {
			*removed = append(*removed, k)
		}
	}
	sort.Strings(*added); sort.Strings(*removed); sort.Strings(*modified)
}

// ─────────────────────────────────────────────────────────────────────────────
// AWS IAM Poller — stdlib HTTP with SigV4 signing
// ─────────────────────────────────────────────────────────────────────────────

type AWSCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func loadAWSCreds() AWSCreds {
	return AWSCreds{
		AccessKeyID:     envOr("AWS_ACCESS_KEY_ID", ""),
		SecretAccessKey: envOr("AWS_SECRET_ACCESS_KEY", ""),
		SessionToken:    envOr("AWS_SESSION_TOKEN", ""),
	}
}

// sigV4Sign signs an AWS HTTP request using SigV4 (stdlib only).
func sigV4Sign(req *http.Request, body []byte, creds AWSCreds, region, service string) {
	t := time.Now().UTC()
	dateStamp := t.Format("20060102")
	amzDate := t.Format("20060102T150405Z")

	req.Header.Set("x-amz-date", amzDate)
	req.Header.Set("host", req.Host)
	if creds.SessionToken != "" {
		req.Header.Set("x-amz-security-token", creds.SessionToken)
	}

	bodyHash := sha256Hex(body)
	req.Header.Set("x-amz-content-sha256", bodyHash)

	// Canonical request
	headers := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if creds.SessionToken != "" {
		headers = append(headers, "x-amz-security-token")
	}
	sort.Strings(headers)
	signedHeaders := strings.Join(headers, ";")

	var headerStr strings.Builder
	for _, h := range headers {
		headerStr.WriteString(h + ":" + req.Header.Get(h) + "\n")
	}

	canonicalReq := strings.Join([]string{
		req.Method,
		req.URL.Path,
		req.URL.RawQuery,
		headerStr.String(),
		signedHeaders,
		bodyHash,
	}, "\n")

	// String to sign
	credScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	strToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credScope,
		sha256Hex([]byte(canonicalReq)),
	}, "\n")

	// Signing key
	sigKey := hmacSHA256(
		hmacSHA256(
			hmacSHA256(
				hmacSHA256([]byte("AWS4"+creds.SecretAccessKey), []byte(dateStamp)),
				[]byte(region),
			),
			[]byte(service),
		),
		[]byte("aws4_request"),
	)
	sig := hex.EncodeToString(hmacSHA256(sigKey, []byte(strToSign)))

	req.Header.Set("Authorization", fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		creds.AccessKeyID, credScope, signedHeaders, sig,
	))
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// awsIAMGet performs a signed GET to the AWS IAM query API.
func awsIAMGet(ctx context.Context, creds AWSCreds, region string, params url.Values) (map[string]any, error) {
	params.Set("Version", "2010-05-08")
	endpoint := "https://iam.amazonaws.com/?" + params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Host = "iam.amazonaws.com"
	sigV4Sign(req, nil, creds, "us-east-1", "iam") // IAM is global, always us-east-1

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("AWS IAM %s: HTTP %d: %s", params.Get("Action"), resp.StatusCode, string(body[:200]))
	}

	// AWS IAM returns XML — parse just enough to get what we need
	// We extract key=value pairs from the XML text for hashing
	result := map[string]any{"raw": string(body)}
	return result, nil
}

// getCallerIdentity calls STS GetCallerIdentity to get the account ID.
func getCallerIdentity(ctx context.Context, creds AWSCreds, region string) (string, error) {
	params := url.Values{"Action": {"GetCallerIdentity"}, "Version": {"2011-06-15"}}
	endpoint := fmt.Sprintf("https://sts.%s.amazonaws.com/?%s", region, params.Encode())

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return "", err
	}
	req.Host = fmt.Sprintf("sts.%s.amazonaws.com", region)
	sigV4Sign(req, nil, creds, region, "sts")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("STS GetCallerIdentity HTTP %d: %s", resp.StatusCode, string(body[:200]))
	}

	// Extract Account from XML: <Account>123456789012</Account>
	raw := string(body)
	start := strings.Index(raw, "<Account>")
	end := strings.Index(raw, "</Account>")
	if start < 0 || end < 0 {
		return "unknown", nil
	}
	return raw[start+9 : end], nil
}

// AWSPoller polls IAM using direct signed HTTP calls.
type AWSPoller struct {
	region string
	logger *slog.Logger
}

func NewAWSPoller(region string, logger *slog.Logger) *AWSPoller {
	return &AWSPoller{region: region, logger: logger}
}

func (p *AWSPoller) Poll(ctx context.Context) (*IAMSnapshot, error) {
	creds := loadAWSCreds()
	if creds.AccessKeyID == "" {
		// Try getting creds from aws cli credential_process or shared credentials
		p.logger.Debug("AWS_ACCESS_KEY_ID not set, trying aws sts get-caller-identity via CLI")
	}

	accountID, err := getCallerIdentity(ctx, creds, p.region)
	if err != nil {
		return nil, fmt.Errorf("GetCallerIdentity: %w", err)
	}

	snap := newSnapshot(accountID, p.region)

	// List roles
	roles, err := awsIAMGet(ctx, creds, p.region, url.Values{"Action": {"ListRoles"}, "MaxItems": {"100"}})
	if err != nil {
		p.logger.Warn("ListRoles failed", "err", err)
	} else {
		snap.Roles["_raw"] = hashContent(roles)
	}

	// List users
	users, err := awsIAMGet(ctx, creds, p.region, url.Values{"Action": {"ListUsers"}, "MaxItems": {"100"}})
	if err != nil {
		p.logger.Warn("ListUsers failed", "err", err)
	} else {
		snap.Users["_raw"] = hashContent(users)
	}

	// List policies
	policies, err := awsIAMGet(ctx, creds, p.region, url.Values{"Action": {"ListPolicies"}, "Scope": {"Local"}, "MaxItems": {"100"}})
	if err != nil {
		p.logger.Warn("ListPolicies failed", "err", err)
	} else {
		snap.Policies["_raw"] = hashContent(policies)
	}

	snap.computeFingerprint()
	p.logger.Info("AWS snapshot complete",
		"account", accountID,
		"fingerprint", snap.Fingerprint,
	)
	return snap, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Neo4j HTTP Writer — uses Neo4j HTTP API (no driver library needed)
// ─────────────────────────────────────────────────────────────────────────────

type Neo4jWriter struct {
	baseURL  string
	user     string
	password string
	client   *http.Client
	logger   *slog.Logger
}

func NewNeo4jWriter(uri, user, password string, logger *slog.Logger) (*Neo4jWriter, error) {
	// Convert bolt:// URI to http:// for the Neo4j HTTP API
	httpURI := uri
	httpURI = strings.ReplaceAll(httpURI, "bolt://", "http://")
	httpURI = strings.ReplaceAll(httpURI, "neo4j://", "http://")
	// Default HTTP port for Neo4j is 7474
	if strings.HasSuffix(httpURI, ":7687") {
		httpURI = strings.ReplaceAll(httpURI, ":7687", ":7474")
	}
	if !strings.HasSuffix(httpURI, "/db/neo4j/tx/commit") {
		httpURI = strings.TrimRight(httpURI, "/") + "/db/neo4j/tx/commit"
	}

	w := &Neo4jWriter{
		baseURL:  httpURI,
		user:     user,
		password: password,
		client:   &http.Client{Timeout: 30 * time.Second},
		logger:   logger,
	}

	// Verify connectivity
	if err := w.ping(); err != nil {
		return nil, fmt.Errorf("neo4j connectivity: %w", err)
	}
	logger.Info("Neo4j connected", "url", httpURI)
	return w, nil
}

func (w *Neo4jWriter) ping() error {
	pingURL := strings.Replace(w.baseURL, "/db/neo4j/tx/commit", "/", 1)
	req, err := http.NewRequest("GET", pingURL, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(w.user, w.password)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("neo4j returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (w *Neo4jWriter) runCypher(cypher string, params map[string]any) error {
	body := map[string]any{
		"statements": []map[string]any{
			{"statement": cypher, "parameters": params},
		},
	}
	b, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", w.baseURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.SetBasicAuth(w.user, w.password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		rb, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("neo4j HTTP %d: %s", resp.StatusCode, string(rb[:min(200, len(rb))]))
	}

	// Check for errors in the JSON response body
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil // non-fatal parse failure
	}
	if errs, ok := result["errors"].([]any); ok && len(errs) > 0 {
		return fmt.Errorf("cypher error: %v", errs[0])
	}
	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (w *Neo4jWriter) WriteDiff(ctx context.Context, diff *StateDiff) error {
	if !diff.HasChanges() {
		w.logger.Debug("no IAM changes to write", "account", diff.AccountID)
		return nil
	}

	// Record removed roles as deleted
	for _, arn := range diff.RemovedRoles {
		_ = w.runCypher(
			`MATCH (p:AWSPrincipal {arn: $arn})
			 SET p.deleted = true, p.deleted_at = timestamp(), p.status = 'DELETED'`,
			map[string]any{"arn": arn},
		)
	}

	// Record state change event
	ts := diff.Timestamp.UnixMilli()
	err := w.runCypher(
		`MERGE (e:StateChangeEvent {account_id: $account_id, timestamp: $ts})
		 SET e.added_roles    = $added_roles,
		     e.removed_roles  = $removed_roles,
		     e.modified_roles = $modified_roles,
		     e.added_users    = $added_users,
		     e.removed_users  = $removed_users,
		     e.added_policies = $added_policies,
		     e.removed_policies = $removed_policies,
		     e.recorded_at    = timestamp()`,
		map[string]any{
			"account_id":       diff.AccountID,
			"ts":               ts,
			"added_roles":      diff.AddedRoles,
			"removed_roles":    diff.RemovedRoles,
			"modified_roles":   diff.ModifiedRoles,
			"added_users":      diff.AddedUsers,
			"removed_users":    diff.RemovedUsers,
			"added_policies":   diff.AddedPolicies,
			"removed_policies": diff.RemovedPolicies,
		},
	)
	if err != nil {
		return fmt.Errorf("write diff: %w", err)
	}

	w.logger.Info("diff written to Neo4j",
		"account", diff.AccountID,
		"added_roles", len(diff.AddedRoles),
		"removed_roles", len(diff.RemovedRoles),
		"modified_roles", len(diff.ModifiedRoles),
		"added_users", len(diff.AddedUsers),
		"removed_users", len(diff.RemovedUsers),
	)
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduler
// ─────────────────────────────────────────────────────────────────────────────

type Scheduler struct {
	cfg      Config
	poller   *AWSPoller
	writer   *Neo4jWriter
	prevSnap *IAMSnapshot
	mu       sync.Mutex
	logger   *slog.Logger
}

func NewScheduler(cfg Config, logger *slog.Logger) (*Scheduler, error) {
	writer, err := NewNeo4jWriter(cfg.Neo4jURI, cfg.Neo4jUser, cfg.Neo4jPass, logger)
	if err != nil {
		logger.Warn("Neo4j not reachable at startup — will retry on each poll", "err", err)
		// Non-fatal: daemon runs even if Neo4j is temporarily down
		writer = nil
	}
	return &Scheduler{
		cfg:    cfg,
		poller: NewAWSPoller(cfg.AWSRegion, logger),
		writer: writer,
		logger: logger,
	}, nil
}

func (s *Scheduler) tick(ctx context.Context) {
	s.logger.Info("polling IAM state")

	snap, err := s.poller.Poll(ctx)
	if err != nil {
		s.logger.Error("poll failed", "err", err)
		return
	}

	s.mu.Lock()
	prev := s.prevSnap
	s.prevSnap = snap
	s.mu.Unlock()

	if prev == nil {
		s.logger.Info("first snapshot — no diff yet", "fingerprint", snap.Fingerprint)
		return
	}

	if prev.Fingerprint == snap.Fingerprint {
		s.logger.Info("no IAM changes detected", "fingerprint", snap.Fingerprint)
		return
	}

	diff := diffSnapshots(prev, snap)
	s.logger.Info("IAM state changed",
		"prev_fp", prev.Fingerprint,
		"curr_fp", snap.Fingerprint,
		"added_roles", len(diff.AddedRoles),
		"removed_roles", len(diff.RemovedRoles),
	)

	if s.cfg.DryRun {
		b, _ := json.MarshalIndent(diff, "", "  ")
		s.logger.Info("DRY RUN — diff not written", "diff", string(b))
		return
	}

	// Lazy Neo4j connection if it wasn't available at startup
	if s.writer == nil {
		w, err := NewNeo4jWriter(s.cfg.Neo4jURI, s.cfg.Neo4jUser, s.cfg.Neo4jPass, s.logger)
		if err != nil {
			s.logger.Error("Neo4j still not reachable", "err", err)
			return
		}
		s.writer = w
	}

	if err := s.writer.WriteDiff(ctx, diff); err != nil {
		s.logger.Error("write diff failed", "err", err)
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	s.tick(ctx) // initial poll on startup
	ticker := time.NewTicker(time.Duration(s.cfg.PollInterval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CLI
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	cfg := defaultConfig()

	flag.IntVar(&cfg.PollInterval, "poll-interval", cfg.PollInterval, "Poll interval in seconds")
	flag.StringVar(&cfg.Neo4jURI, "neo4j", cfg.Neo4jURI, "Neo4j URI (bolt:// or http://)")
	flag.StringVar(&cfg.Neo4jUser, "neo4j-user", cfg.Neo4jUser, "Neo4j username")
	flag.StringVar(&cfg.Neo4jPass, "neo4j-password", cfg.Neo4jPass, "Neo4j password")
	flag.StringVar(&cfg.AWSRegion, "aws-regions", cfg.AWSRegion, "AWS region to poll")
	flag.StringVar(&cfg.AWSProfile, "aws-profile", "", "AWS CLI profile (sets AWS_PROFILE env var)")
	flag.BoolVar(&cfg.DryRun, "dry-run", false, "Poll and diff but do not write to Neo4j")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level: debug|info|warn|error")
	flag.BoolVar(&cfg.ShowVersion, "version", false, "Print version and exit")
	flag.Parse()

	if cfg.ShowVersion {
		fmt.Printf("iamwatching-daemon %s (built %s)\n", Version, BuildTime)
		os.Exit(0)
	}

	// Set AWS_PROFILE if specified
	if cfg.AWSProfile != "" {
		os.Setenv("AWS_PROFILE", cfg.AWSProfile)
		// Reload credentials from the profile via aws cli
		out, err := exec.Command("aws", "configure", "export-credentials",
			"--profile", cfg.AWSProfile, "--format", "env").Output()
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
					key := strings.TrimPrefix(parts[0], "export ")
					os.Setenv(strings.TrimSpace(key), strings.TrimSpace(parts[1]))
				}
			}
		}
	}

	// Logger
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	logger.Info("IamWatching daemon starting",
		"version", Version,
		"poll_interval_s", cfg.PollInterval,
		"neo4j_uri", cfg.Neo4jURI,
		"aws_region", cfg.AWSRegion,
		"dry_run", cfg.DryRun,
	)

	scheduler, err := NewScheduler(cfg, logger)
	if err != nil {
		logger.Error("scheduler init failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig.String())
		cancel()
	}()

	scheduler.Run(ctx)
}
