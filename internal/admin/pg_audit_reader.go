package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/brexhq/CrabTrap/internal/db"
	"github.com/brexhq/CrabTrap/internal/builder"
	"github.com/brexhq/CrabTrap/pkg/types"
)

// sanitizeUTF8 replaces null bytes and invalid UTF-8 sequences with the
// Unicode replacement character so the string can safely be stored in a
// PostgreSQL TEXT column (which requires valid UTF-8 and forbids 0x00).
func sanitizeUTF8(s string) string {
	needsSanitization := false
	for i := 0; i < len(s); {
		if s[i] == 0x00 {
			needsSanitization = true
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			needsSanitization = true
			break
		}
		i += size
	}
	if !needsSanitization {
		return s
	}

	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] == 0x00 {
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size <= 1 {
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		b.WriteRune(r)
		i += size
	}
	return b.String()
}

// AuditReaderIface is the interface for querying and adding audit log entries.
type AuditReaderIface interface {
	Add(entry types.AuditEntry)
	Query(filter AuditFilter) []types.AuditEntry
	QueryBatched(ctx context.Context, filter AuditFilter, batchSize int, fn func([]types.AuditEntry) error) error
	Count(ctx context.Context, filter AuditFilter) (int, error)
	GetEntry(id string) (*types.AuditEntry, error)
	GetPolicyStats(policyID string) (*PolicyStats, error)
}

// PolicyStatsApprover holds per-approver counts for a single decision bucket.
type PolicyStatsApprover struct {
	ApprovedBy    string `json:"approved_by"`
	Count         int    `json:"count"`
	AvgDurationMs int    `json:"avg_duration_ms"`
}

// PolicyDecisionStats holds counts and per-approver breakdown for one decision value.
type PolicyDecisionStats struct {
	Count         int                   `json:"count"`
	AvgDurationMs int                   `json:"avg_duration_ms"`
	P50DurationMs int                   `json:"p50_duration_ms"`
	P95DurationMs int                   `json:"p95_duration_ms"`
	P99DurationMs int                   `json:"p99_duration_ms"`
	ByApprover    []PolicyStatsApprover `json:"by_approver"`
}

// TimeSeriesBucket holds per-day aggregated counts.
type TimeSeriesBucket struct {
	Bucket        time.Time `json:"bucket"`
	Total         int       `json:"total"`
	Approved      int       `json:"approved"`
	Denied        int       `json:"denied"`
	Timeout       int       `json:"timeout"`
	AvgDurationMs int       `json:"avg_duration_ms"`
}

// PolicyStats is the response shape for GET /admin/llm-policies/{id}/stats.
type PolicyStats struct {
	Total         int                             `json:"total"`
	AvgDurationMs int                             `json:"avg_duration_ms"`
	P50DurationMs int                             `json:"p50_duration_ms"`
	P95DurationMs int                             `json:"p95_duration_ms"`
	P99DurationMs int                             `json:"p99_duration_ms"`
	ByDecision    map[string]*PolicyDecisionStats `json:"by_decision"`
	TimeSeries    []TimeSeriesBucket              `json:"time_series"`
}

// AuditFilter contains filter criteria for querying audit entries.
type AuditFilter struct {
	ID              string
	UserID          string
	Decision        string
	ApprovedBy      string
	CacheHit        *bool
	Channel         string
	ExcludeChannels    []string
	ExcludeApprovedBy  []string
	Method             string
	PolicyID        string
	StartTime       time.Time
	EndTime         time.Time
	Limit           int
	Offset          int
}

// PGAuditReader implements AuditReaderIface using PostgreSQL.
type PGAuditReader struct {
	pool *pgxpool.Pool
}

// NewPGAuditReader creates a new PGAuditReader.
func NewPGAuditReader(pool *pgxpool.Pool) *PGAuditReader {
	return &PGAuditReader{pool: pool}
}

// Add inserts an audit log entry into PostgreSQL.
// It also satisfies the audit.AuditReader interface (used by audit.Logger.SetReader).
func (r *PGAuditReader) Add(entry types.AuditEntry) {
	ctx := context.Background()
	id := db.NewID("audit")

	reqHeadersJSON, _ := json.Marshal(entry.RequestHeaders)
	respHeadersJSON, _ := json.Marshal(entry.ResponseHeaders)
	var apiInfoJSON *json.RawMessage
	if entry.APIInfo != nil {
		b, _ := json.Marshal(entry.APIInfo)
		raw := json.RawMessage(b)
		apiInfoJSON = &raw
	}

	var userIDArg *string
	if entry.UserID != "" {
		userIDArg = &entry.UserID
	}

	var llmPolicyIDArg *string
	if entry.LLMPolicyID != "" {
		llmPolicyIDArg = &entry.LLMPolicyID
	}

	var llmResponseIDArg *string
	if entry.LLMResponseID != "" {
		llmResponseIDArg = &entry.LLMResponseID
	}

	var probeScoresJSON *json.RawMessage
	if len(entry.ProbeScores) > 0 {
		b, _ := json.Marshal(entry.ProbeScores)
		raw := json.RawMessage(b)
		probeScoresJSON = &raw
	}

	var probeTrippedArg *string
	if entry.ProbeTripped != "" {
		probeTrippedArg = &entry.ProbeTripped
	}

	var probeAggregationArg *string
	if entry.ProbeAggregation != "" {
		probeAggregationArg = &entry.ProbeAggregation
	}

	_, err := r.pool.Exec(ctx, `
		INSERT INTO audit_log(
			id, user_id, timestamp, request_id, method, url, operation, decision,
			cache_hit, approved_by, approved_at, channel, response_status, duration_ms,
			error, request_headers, request_body, response_headers, response_body,
			api_info, llm_response_id, llm_policy_id,
			probe_scores, probe_tripped, probe_aggregation, probe_circuit_open
		) VALUES(
			$1,$2,$3,$4,$5,$6,$7,$8,
			$9,$10,$11,$12,$13,$14,
			$15,$16,$17,$18,$19,
			$20,$21,$22,
			$23,$24,$25,$26
		)
	`,
		id, userIDArg, entry.Timestamp, entry.RequestID, entry.Method, sanitizeUTF8(entry.URL),
		entry.Operation, entry.Decision,
		entry.CacheHit, entry.ApprovedBy, entry.ApprovedAt, entry.Channel,
		entry.ResponseStatus, entry.DurationMs,
		sanitizeUTF8(entry.Error), json.RawMessage(reqHeadersJSON), sanitizeUTF8(entry.RequestBody),
		json.RawMessage(respHeadersJSON), sanitizeUTF8(entry.ResponseBody),
		apiInfoJSON, llmResponseIDArg, llmPolicyIDArg,
		probeScoresJSON, probeTrippedArg, probeAggregationArg, entry.ProbeCircuitOpen,
	)
	if err != nil {
		slog.Error("PGAuditReader.Add error", "error", err)
	}
}

// buildAuditQueryConditions builds the WHERE clause components for audit_log
// queries. Returns conditions, argument slice, and the next positional index.
func buildAuditQueryConditions(filter AuditFilter) (conds []string, args []interface{}, idx int) {
	idx = 1

	add := func(cond string, val interface{}) {
		conds = append(conds, fmt.Sprintf(cond, idx))
		args = append(args, val)
		idx++
	}

	if filter.ID != "" {
		add("al.id = $%d", filter.ID)
	}
	if filter.UserID != "" {
		add("al.user_id = $%d", filter.UserID)
	}
	if filter.Decision != "" {
		add("al.decision = $%d", filter.Decision)
	}
	if filter.ApprovedBy != "" {
		add("al.approved_by = $%d", filter.ApprovedBy)
	}
	if filter.CacheHit != nil {
		add("al.cache_hit = $%d", *filter.CacheHit)
	}
	if filter.Channel != "" {
		add("al.channel = $%d", filter.Channel)
	}
	if len(filter.ExcludeChannels) > 0 {
		placeholders := make([]string, len(filter.ExcludeChannels))
		for i, ch := range filter.ExcludeChannels {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, ch)
			idx++
		}
		conds = append(conds, fmt.Sprintf("al.channel NOT IN (%s)", strings.Join(placeholders, ", ")))
	}
	if len(filter.ExcludeApprovedBy) > 0 {
		placeholders := make([]string, len(filter.ExcludeApprovedBy))
		for i, ab := range filter.ExcludeApprovedBy {
			placeholders[i] = fmt.Sprintf("$%d", idx)
			args = append(args, ab)
			idx++
		}
		conds = append(conds, fmt.Sprintf("al.approved_by NOT IN (%s)", strings.Join(placeholders, ", ")))
	}
	if filter.Method != "" {
		add("al.method = $%d", strings.ToUpper(filter.Method))
	}
	if filter.PolicyID != "" {
		add("al.llm_policy_id = $%d", filter.PolicyID)
	}
	if !filter.StartTime.IsZero() {
		add("al.timestamp >= $%d", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		add("al.timestamp <= $%d", filter.EndTime)
	}

	return conds, args, idx
}

// auditSelectCols is the column list shared by Query and QueryBatched.
const auditSelectCols = `
		al.id, COALESCE(al.user_id,''), al.timestamp, al.request_id, al.method, al.url,
		al.operation, al.decision,
		al.cache_hit, al.approved_by, al.approved_at, al.channel,
		al.response_status, al.duration_ms,
		al.error, al.request_headers, al.request_body, al.response_headers, al.response_body,
		al.api_info, COALESCE(lr.reason,''), COALESCE(al.llm_policy_id,''),
		COALESCE(al.llm_response_id,''),
		al.probe_scores, COALESCE(al.probe_tripped,''), COALESCE(al.probe_aggregation,''),
		COALESCE(al.probe_circuit_open, false)`

// scanAuditEntry reads one audit_log row (from auditSelectCols) into an AuditEntry.
func scanAuditEntry(rows interface {
	Scan(dest ...interface{}) error
}) (types.AuditEntry, error) {
	var e types.AuditEntry
	var (
		id, userID                      string
		reqHeadersJSON, respHeadersJSON []byte
		apiInfoJSON                     *[]byte
		approvedAt                      string
		probeScoresJSON                 *[]byte
	)
	if err := rows.Scan(
		&id, &userID, &e.Timestamp, &e.RequestID, &e.Method, &e.URL, &e.Operation, &e.Decision,
		&e.CacheHit, &e.ApprovedBy, &approvedAt, &e.Channel, &e.ResponseStatus, &e.DurationMs,
		&e.Error, &reqHeadersJSON, &e.RequestBody, &respHeadersJSON, &e.ResponseBody,
		&apiInfoJSON, &e.LLMReason, &e.LLMPolicyID, &e.LLMResponseID,
		&probeScoresJSON, &e.ProbeTripped, &e.ProbeAggregation, &e.ProbeCircuitOpen,
	); err != nil {
		return types.AuditEntry{}, err
	}
	e.ID = id
	e.UserID = userID
	e.ApprovedAt = approvedAt
	if len(reqHeadersJSON) > 0 {
		var h http.Header
		if err := json.Unmarshal(reqHeadersJSON, &h); err == nil {
			e.RequestHeaders = h
		}
	}
	if len(respHeadersJSON) > 0 {
		var h http.Header
		if err := json.Unmarshal(respHeadersJSON, &h); err == nil {
			e.ResponseHeaders = h
		}
	}
	if apiInfoJSON != nil {
		var ai types.APIInfo
		if err := json.Unmarshal(*apiInfoJSON, &ai); err == nil {
			e.APIInfo = &ai
		}
	}
	if probeScoresJSON != nil && len(*probeScoresJSON) > 0 {
		var ps map[string]float64
		if err := json.Unmarshal(*probeScoresJSON, &ps); err == nil {
			e.ProbeScores = ps
		}
	}
	return e, nil
}

// Query returns audit entries matching the filter, ordered by timestamp DESC.
func (r *PGAuditReader) Query(filter AuditFilter) []types.AuditEntry {
	ctx := context.Background()

	conds, args, _ := buildAuditQueryConditions(filter)

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	limit := filter.Limit
	if limit <= 0 {
		limit = 1000
	}
	offset := filter.Offset

	q := fmt.Sprintf(`
		SELECT%s
		FROM audit_log al
		LEFT JOIN llm_responses lr ON lr.id = al.llm_response_id
		%s
		ORDER BY al.timestamp DESC
		LIMIT %d OFFSET %d
	`, auditSelectCols, where, limit, offset)

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	result := make([]types.AuditEntry, 0)
	for rows.Next() {
		e, err := scanAuditEntry(rows)
		if err != nil {
			continue
		}
		result = append(result, e)
	}
	if result == nil {
		result = []types.AuditEntry{}
	}
	return result
}

// Count returns the number of audit entries matching filter.
func (r *PGAuditReader) Count(ctx context.Context, filter AuditFilter) (int, error) {
	conds, args, _ := buildAuditQueryConditions(filter)

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	q := fmt.Sprintf(`SELECT COUNT(*) FROM audit_log al %s`, where)

	var n int
	if err := r.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("Count: %w", err)
	}
	return n, nil
}

// QueryBatched streams audit entries matching filter to fn in batches of
// batchSize, using keyset pagination on (timestamp, id) for efficiency.
// Respects filter.Limit as an overall cap (0 = unlimited).
// Stops on ctx cancellation or when fn returns an error.
func (r *PGAuditReader) QueryBatched(ctx context.Context, filter AuditFilter, batchSize int, fn func([]types.AuditEntry) error) error {
	totalLimit := filter.Limit
	delivered := 0

	var cursorTimestamp time.Time
	var cursorID string

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		fetchSize := batchSize
		if totalLimit > 0 {
			remaining := totalLimit - delivered
			if remaining <= 0 {
				break
			}
			if remaining < fetchSize {
				fetchSize = remaining
			}
		}

		conds, args, idx := buildAuditQueryConditions(filter)

		if cursorID != "" {
			conds = append(conds, fmt.Sprintf("(al.timestamp, al.id) < ($%d, $%d)", idx, idx+1))
			args = append(args, cursorTimestamp, cursorID)
		}

		where := ""
		if len(conds) > 0 {
			where = "WHERE " + strings.Join(conds, " AND ")
		}

		q := fmt.Sprintf(`
			SELECT%s
			FROM audit_log al
			LEFT JOIN llm_responses lr ON lr.id = al.llm_response_id
			%s
			ORDER BY al.timestamp DESC, al.id DESC
			LIMIT %d
		`, auditSelectCols, where, fetchSize)

		rows, err := r.pool.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("QueryBatched: %w", err)
		}

		var batch []types.AuditEntry
		for rows.Next() {
			e, err := scanAuditEntry(rows)
			if err != nil {
				rows.Close()
				return fmt.Errorf("QueryBatched scan: %w", err)
			}
			batch = append(batch, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("QueryBatched rows: %w", err)
		}

		if len(batch) == 0 {
			break
		}

		if err := fn(batch); err != nil {
			return err
		}

		delivered += len(batch)
		last := batch[len(batch)-1]
		cursorTimestamp = last.Timestamp
		cursorID = last.ID

		if len(batch) < fetchSize {
			break
		}
	}

	return nil
}

// AggregatePathGroups groups audit log entries by normalized path pattern across all channels.
// SQL handles UUID and integer normalization; Go applies a second NormalizeURL pass
// for hex and token patterns, then re-groups and returns all results sorted by count DESC.
func (r *PGAuditReader) AggregatePathGroups(
	userID string, start, end time.Time,
) []builder.PathGroup {
	ctx := context.Background()

	rows, err := r.pool.Query(ctx, `
		SELECT
		  method,
		  regexp_replace(
		    regexp_replace(
		      split_part(url, '?', 1),
		      '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
		      '{uuid}', 'gi'),
		    '/[0-9]+', '/{id}', 'g'
		  ) AS path_pattern,
		  COUNT(*) AS cnt
		FROM audit_log
		WHERE user_id = $1
		  AND channel != 'auto'
		  AND timestamp >= $2 AND timestamp <= $3
		GROUP BY method, path_pattern
		ORDER BY cnt DESC
		LIMIT 50000
	`, userID, start, end)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type key struct{ method, path string }
	counts := map[key]int{}
	for rows.Next() {
		var method, pathPattern string
		var cnt int
		if err := rows.Scan(&method, &pathPattern, &cnt); err != nil {
			continue
		}
		// Second-pass normalization for hex/token patterns.
		normalized := builder.NormalizeURL(pathPattern)
		k := key{method, normalized}
		counts[k] += cnt
	}

	groups := make([]builder.PathGroup, 0, len(counts))
	for k, cnt := range counts {
		groups = append(groups, builder.PathGroup{Method: k.method, PathPattern: k.path, Count: cnt})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Count > groups[j].Count })
	return groups
}

// SampleRequestsForPath returns recent raw requests matching the given path prefix across all channels.
// pathPrefix should be the normalized pattern up to (but not including) the first
// placeholder, e.g. "/v1/applications/" for pattern "/v1/applications/{id}".
// Body values are truncated to 1000 chars.
func (r *PGAuditReader) SampleRequestsForPath(
	userID, method, pathPrefix string,
	start, end time.Time, limit int,
) []builder.RequestSample {
	ctx := context.Background()

	rows, err := r.pool.Query(ctx, `
		SELECT url, COALESCE(LEFT(request_body, 1000), '')
		FROM audit_log
		WHERE user_id = $1 AND method = $2
		  AND channel != 'auto'
		  AND split_part(url, '?', 1) LIKE $3 || '%'
		  AND timestamp >= $4 AND timestamp <= $5
		ORDER BY timestamp DESC
		LIMIT $6
	`, userID, method, pathPrefix, start, end, limit)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var samples []builder.RequestSample
	for rows.Next() {
		var s builder.RequestSample
		if err := rows.Scan(&s.URL, &s.Body); err != nil {
			continue
		}
		samples = append(samples, s)
	}
	return samples
}

// GetEntry fetches a single audit log entry by its ID.
func (r *PGAuditReader) GetEntry(id string) (*types.AuditEntry, error) {
	entries := r.Query(AuditFilter{ID: id, Limit: 1})
	if len(entries) == 0 {
		return nil, fmt.Errorf("audit entry not found: %s", id)
	}
	return &entries[0], nil
}

// policyFilter is the condition for filtering audit entries by the policy that
// evaluated them. It matches on the llm_policy_id stored at decision time, not
// the user's current policy assignment.
const policyFilter = `llm_policy_id = $1`

// GetPolicyStats returns aggregated decision counts, latency percentiles, and
// daily time-series for all audit entries belonging to users assigned to the given policy.
func (r *PGAuditReader) GetPolicyStats(policyID string) (*PolicyStats, error) {
	ctx := context.Background()

	// 1. Counts + avg by (decision, approver).
	rows, err := r.pool.Query(ctx, `
		SELECT
			decision,
			COALESCE(approved_by, '') AS approved_by,
			COUNT(*)::int              AS count,
			ROUND(AVG(duration_ms))::int AS avg_duration_ms
		FROM audit_log
		WHERE `+policyFilter+`
		GROUP BY decision, COALESCE(approved_by, '')
		ORDER BY count DESC
	`, policyID)
	if err != nil {
		return nil, fmt.Errorf("GetPolicyStats counts: %w", err)
	}
	defer rows.Close()

	byDecision := map[string]*PolicyDecisionStats{}
	var totalCount, totalWeightedDuration int

	for rows.Next() {
		var decision, approvedBy string
		var count, avgDur int
		if err := rows.Scan(&decision, &approvedBy, &count, &avgDur); err != nil {
			return nil, fmt.Errorf("GetPolicyStats scan: %w", err)
		}

		if byDecision[decision] == nil {
			byDecision[decision] = &PolicyDecisionStats{}
		}
		d := byDecision[decision]
		d.ByApprover = append(d.ByApprover, PolicyStatsApprover{
			ApprovedBy:    approvedBy,
			Count:         count,
			AvgDurationMs: avgDur,
		})
		d.Count += count
		d.AvgDurationMs = (d.AvgDurationMs*(d.Count-count) + avgDur*count) / d.Count

		totalCount += count
		totalWeightedDuration += avgDur * count
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("GetPolicyStats rows: %w", err)
	}

	overallAvg := 0
	if totalCount > 0 {
		overallAvg = totalWeightedDuration / totalCount
	}

	// 2. Overall latency percentiles.
	var p50, p95, p99 int
	if totalCount > 0 {
		err = r.pool.QueryRow(ctx, `
			SELECT
				ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms))::int,
				ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms))::int,
				ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms))::int
			FROM audit_log
			WHERE `+policyFilter, policyID).Scan(&p50, &p95, &p99)
		if err != nil {
			return nil, fmt.Errorf("GetPolicyStats percentiles: %w", err)
		}
	}

	// 3. Per-decision latency percentiles.
	if totalCount > 0 {
		pRows, err := r.pool.Query(ctx, `
			SELECT
				decision,
				ROUND(percentile_cont(0.50) WITHIN GROUP (ORDER BY duration_ms))::int,
				ROUND(percentile_cont(0.95) WITHIN GROUP (ORDER BY duration_ms))::int,
				ROUND(percentile_cont(0.99) WITHIN GROUP (ORDER BY duration_ms))::int
			FROM audit_log
			WHERE `+policyFilter+`
			GROUP BY decision
		`, policyID)
		if err != nil {
			return nil, fmt.Errorf("GetPolicyStats decision percentiles: %w", err)
		}
		defer pRows.Close()

		for pRows.Next() {
			var dec string
			var dp50, dp95, dp99 int
			if err := pRows.Scan(&dec, &dp50, &dp95, &dp99); err != nil {
				return nil, fmt.Errorf("GetPolicyStats decision percentile scan: %w", err)
			}
			if d := byDecision[dec]; d != nil {
				d.P50DurationMs = dp50
				d.P95DurationMs = dp95
				d.P99DurationMs = dp99
			}
		}
		if err := pRows.Err(); err != nil {
			return nil, fmt.Errorf("GetPolicyStats decision percentile rows: %w", err)
		}
	}

	// 4. Daily time series (last 30 days).
	tsRows, err := r.pool.Query(ctx, `
		SELECT
			date_trunc('day', timestamp)         AS bucket,
			COUNT(*)::int                        AS total,
			COUNT(*) FILTER (WHERE decision = 'approved')::int AS approved,
			COUNT(*) FILTER (WHERE decision = 'denied')::int   AS denied,
			COUNT(*) FILTER (WHERE decision = 'timeout')::int  AS timeout,
			ROUND(AVG(duration_ms))::int         AS avg_duration_ms
		FROM audit_log
		WHERE `+policyFilter+`
		  AND timestamp >= NOW() - INTERVAL '30 days'
		GROUP BY bucket
		ORDER BY bucket
	`, policyID)
	if err != nil {
		return nil, fmt.Errorf("GetPolicyStats time_series: %w", err)
	}
	defer tsRows.Close()

	var timeSeries []TimeSeriesBucket
	for tsRows.Next() {
		var b TimeSeriesBucket
		if err := tsRows.Scan(&b.Bucket, &b.Total, &b.Approved, &b.Denied, &b.Timeout, &b.AvgDurationMs); err != nil {
			return nil, fmt.Errorf("GetPolicyStats ts scan: %w", err)
		}
		timeSeries = append(timeSeries, b)
	}
	if err := tsRows.Err(); err != nil {
		return nil, fmt.Errorf("GetPolicyStats ts rows: %w", err)
	}
	if timeSeries == nil {
		timeSeries = []TimeSeriesBucket{}
	}

	return &PolicyStats{
		Total:         totalCount,
		AvgDurationMs: overallAvg,
		P50DurationMs: p50,
		P95DurationMs: p95,
		P99DurationMs: p99,
		ByDecision:    byDecision,
		TimeSeries:    timeSeries,
	}, nil
}
