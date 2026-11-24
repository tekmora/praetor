// SPDX-FileCopyrightText: 2026 lusoris <lusoris@pm.me>
//
// SPDX-License-Identifier: EUPL-1.2

package forge

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cordanaLLM/praetor/internal/config"
	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/util"
	"go.yaml.in/yaml/v3"
)

const (
	jobTimeoutGate              = "job-timeout"
	jobTimeoutKindCancelRisk    = "cancel-risk"
	jobTimeoutKindRunaway       = "runaway"
	jobTimeoutKindStaticCeiling = "static-ceiling"
	jobTimeoutKindMissing       = "missing-timeout"
	jobTimeoutKindUnreadable    = "unreadable-timeout"
	staticCeilingMinutes        = 120
	ceilingFloorMinutes         = 30.0
	runawayMultiplier           = 4.0
	cancelRiskMultiplier        = 1.25
	maxWorkflowRuns             = 3
	jobTimeoutWarn              = "[WARN]"
	jobTimeoutFail              = "[FAIL]"
)

// JobTimeoutFailFrom ends the job-timeout gate's 14-day warn period from its landing day,
// 2026-11-24 (decision engine-job-timeouts-fail-mode). Findings fail the audit from this day on.
var JobTimeoutFailFrom = time.Date(2026, 12, 8, 0, 0, 0, 0, time.UTC)

// JobTimeoutOptions is what AuditJobTimeouts reads: the repository root, the manifest's
// exceptions list (the check reads the entries of config.ExceptionRuleJobTimeout), the day
// those entries' expiry is judged against, the forge reader, and branch. An exception's
// fingerprint, when set, must equal the finding kind; an empty fingerprint covers all kinds.
type JobTimeoutOptions struct {
	Root          string
	Exceptions    []config.Exception
	Today         time.Time
	Reader        ActionsReader
	OfflineReason string
	Branch        string
}

type jobTimeoutFinding struct {
	Workflow string
	Line     int
	JobID    string
	Kind     string
	Reason   string
}

type jobVerdict struct {
	finding    *jobTimeoutFinding
	info       string
	isMeasured bool
	isStatic   bool
}

type workflowRunMetrics struct {
	slowest      map[string]float64
	hadReadError bool
	readErr      string
}

type workflowAuditResult struct {
	findings []jobTimeoutFinding
	infos    []string
	// staticOnly lists the workflows with a job that passed on the measured path but declares a
	// value above the static ceiling, so a run without measurements (CI without a forge token, an
	// offline audit) finds it. An exception that covers such a workflow is in use on both paths.
	staticOnly      []string
	measuredCount   int
	noSuccessCount  int
	unreadableCount int
	readErr         string
}

// AuditJobTimeouts checks workflow jobs for timeout-minutes declarations and duration limits.
// Before JobTimeoutFailFrom a finding is a [WARN] line and the gate passes; from that day on it
// is a [FAIL] line and the gate returns every line as its error.
func AuditJobTimeouts(ctx context.Context, opts JobTimeoutOptions) (string, error) {
	files, err := readWorkflowFiles(ctx, opts.Root)
	if err != nil {
		return "", err
	}
	if len(files) > maxWorkflowFiles {
		files = files[:maxWorkflowFiles]
	}
	canMeasure := opts.Reader != nil && opts.OfflineReason == "" && opts.Branch != ""
	var total workflowAuditResult
	for _, file := range files {
		res, err := auditWorkflowJobTimeouts(ctx, file, opts, canMeasure)
		if err != nil {
			return "", err
		}
		addWorkflowResult(&total, res)
	}
	staticCount := total.noSuccessCount + total.unreadableCount
	lines := []string{formatJobTimeoutPathInfo(canMeasure, opts, total.measuredCount, staticCount, total.noSuccessCount, total.unreadableCount, total.readErr)}
	lines = append(lines, total.infos...)
	failing := !opts.Today.Before(JobTimeoutFailFrom)
	entries := config.ExceptionsFor(opts.Exceptions, config.ExceptionRuleJobTimeout)
	judged, findings := applyExceptions(total.findings, total.staticOnly, entries, opts.Today, failing)
	lines = append(lines, judged...)
	if findings > 0 && failing {
		return "", errors.New(strings.Join(lines, "\n"))
	}
	if findings > 0 {
		lines = append(lines, fmt.Sprintf("[INFO] %s: findings warn until %s and fail the audit from that day on",
			jobTimeoutGate, JobTimeoutFailFrom.Format(time.DateOnly)))
	}
	return strings.Join(append(lines, "[PASS] "+jobTimeoutGate), "\n"), nil
}

// addWorkflowResult adds one workflow's result to total; the first read error is kept.
func addWorkflowResult(total *workflowAuditResult, res workflowAuditResult) {
	total.findings = append(total.findings, res.findings...)
	total.infos = append(total.infos, res.infos...)
	total.staticOnly = append(total.staticOnly, res.staticOnly...)
	total.measuredCount += res.measuredCount
	total.noSuccessCount += res.noSuccessCount
	total.unreadableCount += res.unreadableCount
	if total.readErr == "" && res.readErr != "" {
		total.readErr = res.readErr
	}
}

func formatJobTimeoutPathInfo(canMeasure bool, opts JobTimeoutOptions, measured, static, noSuccess, unreadable int, readErr string) string {
	if !canMeasure {
		reason := opts.OfflineReason
		if reason == "" {
			reason = "no forge reader or branch available"
		}
		return fmt.Sprintf("[INFO] %s: static path only (%s)", jobTimeoutGate, reason)
	}
	if unreadable > 0 {
		return fmt.Sprintf("[INFO] %s: measured path for %d jobs (forge runs of %s), static path for %d jobs: %d without a successful run, %d whose runs could not be read (%s)",
			jobTimeoutGate, measured, opts.Branch, static, noSuccess, unreadable, readErr)
	}
	return fmt.Sprintf("[INFO] %s: measured path for %d jobs (forge runs of %s), static path for %d jobs (no successful run)",
		jobTimeoutGate, measured, opts.Branch, static)
}

// auditWorkflowJobTimeouts checks every job in a single workflow file for a timeout-minutes
// declaration and compares it with the maximum observed job duration from up to three successful runs.
func auditWorkflowJobTimeouts(ctx context.Context, file workflowFile, opts JobTimeoutOptions, canMeasure bool) (workflowAuditResult, error) {
	spec, err := ghworkflow.Parse(file.Data)
	if err != nil {
		return workflowAuditResult{}, err
	}
	rel := ghworkflow.Dir + "/" + file.Name
	keyLines := workflowJobKeyLines(file.Data)
	var metrics workflowRunMetrics
	if canMeasure {
		metrics = readWorkflowSlowestJobs(ctx, opts.Reader, file.Name, opts.Branch, &spec)
	}
	var res workflowAuditResult
	for _, jobID := range ghworkflow.SortedJobIDs(spec.Jobs) {
		job := spec.Jobs[jobID]
		s, hasS := metrics.slowest[jobID]
		v := judgeJob(rel, jobID, job, keyLines[jobID], hasS, s)
		accumulateJobVerdict(&res, v, metrics.hadReadError)
		if v.isMeasured && v.finding == nil && aboveStaticCeiling(job) && len(res.staticOnly) == 0 {
			res.staticOnly = []string{rel}
		}
	}
	if res.unreadableCount > 0 {
		res.readErr = metrics.readErr
	}
	return res, nil
}

func accumulateJobVerdict(res *workflowAuditResult, v jobVerdict, hadReadError bool) {
	if v.finding != nil {
		res.findings = append(res.findings, *v.finding)
	}
	if v.info != "" {
		res.infos = append(res.infos, v.info)
	}
	if v.isMeasured {
		res.measuredCount++
		return
	}
	if v.isStatic {
		if hadReadError {
			res.unreadableCount++
		} else {
			res.noSuccessCount++
		}
	}
}

// judgeJob classifies one workflow job for timeout-minutes: missing, unreadable, measured or static limits.
func judgeJob(rel, jobID string, job ghworkflow.Job, jobLine int, hasS bool, s float64) jobVerdict {
	if job.Uses != "" || len(job.Steps) == 0 {
		return jobVerdict{}
	}
	if job.TimeoutMinutes.Kind == 0 || (job.TimeoutMinutes.Value == "" && job.TimeoutMinutes.Tag == "!!null") {
		f := &jobTimeoutFinding{Workflow: rel, Line: jobLine, JobID: jobID, Kind: jobTimeoutKindMissing, Reason: "declares no timeout-minutes"}
		return jobVerdict{finding: f, isMeasured: hasS, isStatic: !hasS}
	}
	line := job.TimeoutMinutes.Line
	if line == 0 {
		line = jobLine
	}
	val := strings.TrimSpace(job.TimeoutMinutes.Value)
	if strings.Contains(val, "${{") {
		info := fmt.Sprintf("[INFO] %s: %s:%d job %s: timeout-minutes is an expression (%s), not judged",
			jobTimeoutGate, rel, line, jobID, val)
		return jobVerdict{info: info}
	}
	declared, err := strconv.Atoi(val)
	if err != nil {
		f := &jobTimeoutFinding{Workflow: rel, Line: line, JobID: jobID, Kind: jobTimeoutKindUnreadable, Reason: fmt.Sprintf("timeout-minutes %q is unreadable", val)}
		return jobVerdict{finding: f, isMeasured: hasS, isStatic: !hasS}
	}
	if hasS {
		return judgeMeasuredJob(rel, line, jobID, declared, s, jobTimeoutRunawayFloor(rel, jobID, job))
	}
	return judgeStaticJob(rel, line, jobID, declared)
}

// jobTimeoutRunawayFloor reserves the generated installation step's full budget for the
// managed API comparison job, even when recent successful runs needed little installation time.
func jobTimeoutRunawayFloor(rel, jobID string, job ghworkflow.Job) float64 {
	if rel != ghworkflow.APICompatibilityWorkflowFile || jobID != ghworkflow.APICompatibilityJobID {
		return ceilingFloorMinutes
	}
	for i := 0; i < len(job.Steps) && i < ghworkflow.MaxStepsPerJob; i++ {
		step := &job.Steps[i]
		if step.Name == ghworkflow.APICompatibilityInstallStepName && step.If == ghworkflow.HostedGateNotDraft &&
			step.TimeoutMinutes.Value == strconv.Itoa(ghworkflow.APICompatibilityInstallTimeout) &&
			strings.HasPrefix(step.Run, ghworkflow.APICompatibilityUpdateCommand+"\n"+ghworkflow.APICompatibilityInstallCommand+" ") {
			return ceilingFloorMinutes + ghworkflow.APICompatibilityInstallTimeout
		}
	}
	return ceilingFloorMinutes
}

// judgeMeasuredJob compares declared timeout-minutes against slowest measured duration s.
func judgeMeasuredJob(rel string, line int, jobID string, declared int, s, floor float64) jobVerdict {
	declFloat := float64(declared)
	if declFloat < cancelRiskMultiplier*s {
		reason := fmt.Sprintf("timeout-minutes %d is below 1.25 x measured duration %.1fm (cancel risk)", declared, s)
		f := &jobTimeoutFinding{Workflow: rel, Line: line, JobID: jobID, Kind: jobTimeoutKindCancelRisk, Reason: reason}
		return jobVerdict{finding: f, isMeasured: true}
	}
	ceil := math.Max(floor, runawayMultiplier*s)
	if declFloat > ceil {
		reason := fmt.Sprintf("timeout-minutes %d is above max(%.0f, 4 x %.1fm) bound of %.0fm (runaway)", declared, floor, s, ceil)
		f := &jobTimeoutFinding{Workflow: rel, Line: line, JobID: jobID, Kind: jobTimeoutKindRunaway, Reason: reason}
		return jobVerdict{finding: f, isMeasured: true}
	}
	return jobVerdict{isMeasured: true}
}

// aboveStaticCeiling reports whether job declares a literal timeout-minutes above the static
// ceiling, the finding judgeStaticJob makes when no measurement exists.
func aboveStaticCeiling(job ghworkflow.Job) bool {
	declared, err := strconv.Atoi(strings.TrimSpace(job.TimeoutMinutes.Value))
	return err == nil && declared > staticCeilingMinutes
}

// judgeStaticJob checks declared timeout-minutes against staticCeilingMinutes when unmeasured.
func judgeStaticJob(rel string, line int, jobID string, declared int) jobVerdict {
	if declared > staticCeilingMinutes {
		reason := fmt.Sprintf("timeout-minutes %d is above %dm bound", declared, staticCeilingMinutes)
		f := &jobTimeoutFinding{Workflow: rel, Line: line, JobID: jobID, Kind: jobTimeoutKindStaticCeiling, Reason: reason}
		return jobVerdict{finding: f, isStatic: true}
	}
	return jobVerdict{isStatic: true}
}

// applyExceptions returns the judged lines and how many of them are findings: a finding of a
// workflow without a live exception, or an entry that excuses nothing. failing marks findings
// [FAIL] instead of [WARN]; an exception's [PASS] line names only its excused jobs and kinds.
// A workflow in staticOnly also has a use for a static-ceiling entry on the offline path.
func applyExceptions(findings []jobTimeoutFinding, staticOnly []string, entries []config.Exception, today time.Time, failing bool) ([]string, int) {
	severity := jobTimeoutWarn
	if failing {
		severity = jobTimeoutFail
	}
	used := make([]bool, len(entries))
	byWorkflow, wfOrder := groupFindingsByWorkflow(findings)
	lines, count := judgeWorkflowFindings(byWorkflow, wfOrder, entries, today, used, severity)
	staticLines, staticCount := staticOnlyExceptionLines(staticOnly, byWorkflow, entries, today, used, severity)
	lines = append(lines, staticLines...)
	count += staticCount
	for i := 0; i < len(entries) && i < config.MaxExceptions; i++ {
		if !used[i] {
			why := "the workflow it names has none"
			if entries[i].Fingerprint != "" {
				why = "the workflow it names has none of kind " + entries[i].Fingerprint
			}
			detail := fmt.Sprintf("the exceptions entry (rule %s, %s) excuses no finding, because %s; remove it.",
				entries[i].Rule, entries[i].Target(), why)
			lines = append(lines, formatJobTimeoutFindingLine(severity, detail))
			count++
		}
	}
	return lines, count
}

// groupFindingsByWorkflow groups findings by workflow, keeping the first-seen workflow order.
func groupFindingsByWorkflow(findings []jobTimeoutFinding) (map[string][]jobTimeoutFinding, []string) {
	byWorkflow := make(map[string][]jobTimeoutFinding)
	var wfOrder []string
	for _, f := range findings {
		if _, exists := byWorkflow[f.Workflow]; !exists {
			wfOrder = append(wfOrder, f.Workflow)
		}
		byWorkflow[f.Workflow] = append(byWorkflow[f.Workflow], f)
	}
	return byWorkflow, wfOrder
}

// jobTimeoutExceptionFor returns the last live and first expired entries matching workflow and kind.
// Only matching entries are marked used; unknown fingerprints excuse nothing.
func jobTimeoutExceptionFor(entries []config.Exception, workflow, kind string, today time.Time, used []bool) (live, expired *config.Exception) {
	for i := 0; i < len(entries) && i < config.MaxExceptions; i++ {
		if entries[i].Fingerprint != "" && entries[i].Fingerprint != kind {
			continue
		}
		match, stale := config.ExceptionFor(entries[i:i+1], workflow, today, used[i:i+1])
		if match != nil {
			live = match
		}
		if expired == nil {
			expired = stale
		}
	}
	return live, expired
}

// judgeWorkflowFindings prints unexcused findings at severity and counts them. Pass lines
// group only findings matched by the same live entry, preserving their first-seen order.
func judgeWorkflowFindings(byWorkflow map[string][]jobTimeoutFinding, wfOrder []string, entries []config.Exception, today time.Time, used []bool, severity string) ([]string, int) {
	var lines []string
	count := 0
	for _, wf := range wfOrder {
		excused := make(map[*config.Exception][]jobTimeoutFinding)
		var order []*config.Exception
		for _, f := range byWorkflow[wf] {
			if live, _ := jobTimeoutExceptionFor(entries, wf, f.Kind, today, used); live != nil {
				if _, exists := excused[live]; !exists {
					order = append(order, live)
				}
				excused[live] = append(excused[live], f)
				continue
			}
			detail := fmt.Sprintf("%s:%d job %s: %s", f.Workflow, f.Line, auditJobID(f.JobID), f.Reason)
			lines = append(lines, formatJobTimeoutFindingLine(severity, detail))
			count++
		}
		for _, live := range order {
			lines = append(lines, fmt.Sprintf("[PASS] %s: %s excepted until %s: %s; excuses %s",
				jobTimeoutGate, wf, live.Expires, live.Reason, formatExcusedFindings(excused[live])))
		}
	}
	return lines, count
}

// formatJobTimeoutFindingLine renders one finding line at severity; a [WARN] line names the day the
// gate starts to fail, so an adopter reading a warning knows its deadline.
func formatJobTimeoutFindingLine(severity, detail string) string {
	line := severity + " " + jobTimeoutGate + ": " + detail
	if severity == jobTimeoutWarn {
		line += " (fails the audit from " + JobTimeoutFailFrom.Format(time.DateOnly) + ")"
	}
	return line
}

// staticOnlyExceptionLines reports and counts expired static-ceiling entries for workflows
// whose measured jobs passed above the static bound. A live entry still covers the offline path.
func staticOnlyExceptionLines(staticOnly []string, byWorkflow map[string][]jobTimeoutFinding, entries []config.Exception, today time.Time, used []bool, severity string) ([]string, int) {
	var lines []string
	count := 0
	for _, wf := range staticOnly {
		live, expired := jobTimeoutExceptionFor(entries, wf, jobTimeoutKindStaticCeiling, today, used)
		if live != nil {
			lines = append(lines, fmt.Sprintf("[INFO] %s: %s: the exceptions entry (until %s) covers jobs above the %dm static bound; the measured path finds none",
				jobTimeoutGate, wf, live.Expires, staticCeilingMinutes))
		} else if expired != nil && !slices.ContainsFunc(byWorkflow[wf], isStaticCeilingFinding) {
			detail := fmt.Sprintf("the exceptions entry for %s expired %s; bring the timeout back to the %dm bound or renew the entry with a reason",
				wf, expired.Expires, staticCeilingMinutes)
			lines = append(lines, formatJobTimeoutFindingLine(severity, detail))
			count++
		}
	}
	return lines, count
}

// isStaticCeilingFinding reports whether the offline bound already produced a finding.
func isStaticCeilingFinding(f jobTimeoutFinding) bool {
	return f.Kind == jobTimeoutKindStaticCeiling
}

// auditJobID returns jobID with terminal control characters replaced so audit lines cannot be forged.
// IDs exceeding the workflow reader's byte limit produce a diagnostic marker.
func auditJobID(jobID string) string {
	if len(jobID) > contextopt.MaxSourceBytes {
		return "[oversized job ID]"
	}
	var b strings.Builder
	b.Grow(len(jobID))
	for i := 0; i < len(jobID) && i < contextopt.MaxSourceBytes; {
		r, size := utf8.DecodeRuneInString(jobID[i:])
		i += size
		if unicode.IsControl(r) {
			b.WriteByte('.')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// formatExcusedFindings formats wFindings as comma-separated "job <id> <kind>" entries in finding order.
func formatExcusedFindings(wFindings []jobTimeoutFinding) string {
	n := len(wFindings)
	if n > ghworkflow.MaxJobsPerFile {
		n = ghworkflow.MaxJobsPerFile
	}
	parts := make([]string, 0, n)
	for i := 0; i < len(wFindings) && i < ghworkflow.MaxJobsPerFile; i++ {
		f := wFindings[i]
		kind := f.Kind
		if kind == "" {
			kind = "unknown"
		}
		parts = append(parts, strings.TrimSpace(fmt.Sprintf("job %s %s", auditJobID(f.JobID), kind)))
	}
	return strings.Join(parts, ", ")
}

func readWorkflowSlowestJobs(ctx context.Context, reader ActionsReader, workflow, branch string, spec *ghworkflow.Spec) workflowRunMetrics {
	history, err := reader.WorkflowRunHistory(ctx, workflow, branch)
	if err != nil {
		return workflowRunMetrics{hadReadError: true, readErr: historyReadError(err)}
	}
	slowest := make(map[string]float64)
	successfulCount := 0
	var firstErr string
	hadErr := false
	for i := 0; i < len(history.Completed) && successfulCount < maxWorkflowRuns; i++ {
		run := history.Completed[i]
		if run.Conclusion != "success" {
			continue
		}
		successfulCount++
		if run.ID == 0 {
			hadErr = true
			if firstErr == "" {
				firstErr = "run without ID"
			}
			continue
		}
		jobs, err := reader.WorkflowRunJobs(ctx, run.ID)
		if err != nil {
			hadErr = true
			if firstErr == "" {
				firstErr = jobsReadError(err)
			}
			continue
		}
		updateSlowestJobs(slowest, jobs, spec)
	}
	return workflowRunMetrics{slowest: slowest, hadReadError: hadErr, readErr: firstErr}
}

func historyReadError(err error) string {
	return err.Error()
}

func jobsReadError(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "read run jobs") {
		return msg
	}
	return "read run jobs: " + msg
}

// updateSlowestJobs records the maximum successful job duration per spec job from one run.
func updateSlowestJobs(slowest map[string]float64, jobs []WorkflowJobRecord, spec *ghworkflow.Spec) {
	for i := 0; i < len(jobs) && i < maxWorkflowRunJobs; i++ {
		jobRec := jobs[i]
		if jobRec.Conclusion != "success" {
			continue
		}
		dur, ok := parseJobDuration(jobRec.StartedAt, jobRec.CompletedAt)
		if !ok {
			continue
		}
		matchSlowestJob(slowest, jobRec.Name, dur, spec)
	}
}

// matchSlowestJob assigns dur to the matching jobs in spec. A spec job whose name holds no
// "${{" expression takes only forge records with exactly its name. A spec job whose name holds
// a "${{" expression may take prefix matches on its literal text before "${{", but never a
// record whose name exactly equals another spec job's literal name; when several expression
// jobs match by prefix, the longest literal prefix wins and ties share the record.
func matchSlowestJob(slowest map[string]float64, forgeName string, dur float64, spec *ghworkflow.Spec) {
	if spec == nil {
		return
	}
	jobIDs := ghworkflow.SortedJobIDs(spec.Jobs)
	if matchLiteralJobs(slowest, jobIDs, forgeName, dur, spec) {
		return
	}
	best := longestExpressionPrefixMatch(jobIDs, forgeName, spec)
	if best == 0 {
		return
	}
	for i := 0; i < len(jobIDs) && i < ghworkflow.MaxJobsPerFile; i++ {
		jobID := jobIDs[i]
		target := specJobTarget(jobID, spec.Jobs[jobID])
		if jobMatches(target, forgeName) && len(expressionJobPrefix(target)) == best {
			recordSlowest(slowest, jobID, dur)
		}
	}
}

// matchLiteralJobs updates every literal spec job whose name equals forgeName and reports whether any matched.
func matchLiteralJobs(slowest map[string]float64, jobIDs []string, forgeName string, dur float64, spec *ghworkflow.Spec) bool {
	matched := false
	for i := 0; i < len(jobIDs) && i < ghworkflow.MaxJobsPerFile; i++ {
		jobID := jobIDs[i]
		target := specJobTarget(jobID, spec.Jobs[jobID])
		if !strings.Contains(target, "${{") && jobMatches(target, forgeName) {
			recordSlowest(slowest, jobID, dur)
			matched = true
		}
	}
	return matched
}

// longestExpressionPrefixMatch returns the byte length of the longest matching expression-job prefix.
func longestExpressionPrefixMatch(jobIDs []string, forgeName string, spec *ghworkflow.Spec) int {
	best := 0
	for i := 0; i < len(jobIDs) && i < ghworkflow.MaxJobsPerFile; i++ {
		target := specJobTarget(jobIDs[i], spec.Jobs[jobIDs[i]])
		if jobMatches(target, forgeName) {
			if n := len(expressionJobPrefix(target)); n > best {
				best = n
			}
		}
	}
	return best
}

// specJobTarget returns job.Name when set, or jobID when the workflow omits a display name.
func specJobTarget(jobID string, job ghworkflow.Job) string {
	if job.Name != "" {
		return job.Name
	}
	return jobID
}

// recordSlowest updates jobID's maximum observed duration when dur exceeds any prior value.
func recordSlowest(slowest map[string]float64, jobID string, dur float64) {
	if prev, ok := slowest[jobID]; !ok || dur > prev {
		slowest[jobID] = dur
	}
}

// jobMatches reports whether a single spec job target matches forgeName before sibling precedence:
// a literal target requires an exact match, and an expression target requires its literal prefix before "${{".
func jobMatches(target, forgeName string) bool {
	if !strings.Contains(target, "${{") {
		return forgeName == target
	}
	prefix := expressionJobPrefix(target)
	return prefix != "" && strings.HasPrefix(forgeName, prefix)
}

// expressionJobPrefix returns the non-blank literal prefix before the first "${{" in target, or "".
func expressionJobPrefix(target string) string {
	idx := strings.Index(target, "${{")
	if idx <= 0 {
		return ""
	}
	if strings.TrimSpace(target[:idx]) == "" {
		return ""
	}
	return target[:idx]
}

func parseJobDuration(startedAt, completedAt string) (float64, bool) {
	if startedAt == "" || completedAt == "" {
		return 0, false
	}
	start, err1 := time.Parse(time.RFC3339, startedAt)
	end, err2 := time.Parse(time.RFC3339, completedAt)
	if err1 != nil || err2 != nil || !end.After(start) {
		return 0, false
	}
	return end.Sub(start).Minutes(), true
}

func workflowJobKeyLines(data []byte) map[string]int {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil
	}
	lines := make(map[string]int)
	if document.Kind != yaml.DocumentNode || len(document.Content) == 0 {
		return lines
	}
	jobs := util.YAMLMappingValue(document.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return lines
	}
	for i := 0; i+1 < len(jobs.Content) && i < 2*ghworkflow.MaxJobsPerFile; i += 2 {
		lines[jobs.Content[i].Value] = jobs.Content[i].Line
	}
	return lines
}
