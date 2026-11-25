package ruleregistry

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/gating"
	"github.com/cordanaLLM/praetor/internal/ghworkflow"
	"github.com/cordanaLLM/praetor/internal/util"
	"go.yaml.in/yaml/v3"
)

const (
	maxTestFiles        = 256
	maxAuditRules       = 256
	maxEvidencePointers = 32
)

// Status describes what the registry audit observed for one rule's declared evidence.
type Status string

const (
	// StatusPresent reports that every declared local pointer resolved structurally and no forge pointer was declared.
	StatusPresent Status = "present"
	// StatusForgeObserved reports that every declared pointer resolved, no forge setting is pending, and a forge pointer matched on live read-back.
	StatusForgeObserved Status = "forge-observed"
	// StatusForgePending reports that every local pointer resolved and a required forge setting is asserted without live read-back.
	StatusForgePending Status = "forge-pending"
	// StatusUnresolved reports that a declared pointer failed resolution, lacked evidence, or mismatched live forge state.
	StatusUnresolved Status = "unresolved"
	// StatusGuidance reports a guidance or unregistered prose-only rule with no declared enforcement pointers.
	StatusGuidance Status = "guidance"
)

// Row is one known rule's audit result.
// Status separates local structural resolution ("present"), pending forge assertions ("forge-pending"),
// live forge verification ("forge-observed"), failed resolution ("unresolved"), and prose ("guidance").
// Enforced is true only when the registry directly observed enforcement (every declared pointer resolved,
// at least one forge setting was read back and matched, and no required forge pointer of the rule is pending);
// local structural pointer resolution alone never sets Enforced.
type Row struct {
	ID        string            `json:"id"`
	Class     Class             `json:"class"`
	Status    Status            `json:"status"`
	Evidence  string            `json:"evidence"`
	Enforced  bool              `json:"enforced"`
	ProseOnly bool              `json:"prose_only"`
	Candidate bool              `json:"convert_or_delete_candidate"`
	Forge     []ForgeComparison `json:"forge,omitempty"`
}

// Report is the complete, deterministic registry audit result.
type Report struct {
	Rows     []Row    `json:"rules"`
	Problems []string `json:"problems,omitempty"`
}

// Valid reports whether all declared entries and evidence pointers resolved.
func (r *Report) Valid() bool { return r != nil && len(r.Problems) == 0 }

// Counts returns the number of known rules in each declared class.
func (r *Report) Counts() map[Class]int {
	counts := map[Class]int{}
	if r == nil {
		return counts
	}
	for i := 0; i < len(r.Rows) && i < maxAuditRules; i++ {
		counts[r.Rows[i].Class]++
	}
	return counts
}

// StatusCounts returns the number of known rules in each audit status.
func (r *Report) StatusCounts() map[Status]int {
	counts := map[Status]int{}
	if r == nil {
		return counts
	}
	for i := 0; i < len(r.Rows) && i < maxAuditRules; i++ {
		counts[r.Rows[i].Status]++
	}
	return counts
}

// ProseOnlyIDs returns every rule that currently has no executable enforcement claim.
func (r *Report) ProseOnlyIDs() []string {
	ids := []string{}
	if r == nil {
		return ids
	}
	for i := 0; i < len(r.Rows) && i < maxAuditRules; i++ {
		if r.Rows[i].ProseOnly {
			ids = append(ids, r.Rows[i].ID)
		}
	}
	return ids
}

// UnenforcedIDs returns every rule whose enforcement was not directly observed by the audit
// (Enforced is false, including rules whose status is "present" or "forge-pending").
func (r *Report) UnenforcedIDs() []string {
	ids := []string{}
	if r == nil {
		return ids
	}
	for i := 0; i < len(r.Rows) && i < maxAuditRules; i++ {
		if !r.Rows[i].Enforced {
			ids = append(ids, r.Rows[i].ID)
		}
	}
	return ids
}

// Audit classifies every known rule and resolves each declared evidence pointer.
func Audit(ctx context.Context, root string) (*Report, error) {
	return AuditWithOptions(ctx, root, AuditOptions{})
}

// AuditWithOptions classifies known rules and resolves local and live forge evidence.
func AuditWithOptions(ctx context.Context, root string, opts AuditOptions) (*Report, error) {
	known, err := KnownRules(ctx, root)
	if err != nil {
		return nil, err
	}
	registry, err := Load(ctx, root)
	if err != nil {
		return nil, err
	}
	report := &Report{}
	entries := indexEntries(registry, known, report)
	forgeStates := loadForgeStates(ctx, registry, opts, report)
	for i := 0; i < len(known) && i < maxAuditRules; i++ {
		row := auditRule(ctx, root, known[i], entries[known[i].ID], forgeStates, report)
		report.Rows = append(report.Rows, row)
	}
	if report.Valid() {
		return report, nil
	}
	return report, fmt.Errorf("rules audit: %d invalid declaration(s)", len(report.Problems))
}

// indexEntries validates registry entries against known rules and returns them keyed by rule ID.
func indexEntries(registry *Registry, known []Rule, report *Report) map[string]*Entry {
	knownIDs := make(map[string]bool, len(known))
	for i := 0; i < len(known) && i < maxAuditRules; i++ {
		knownIDs[known[i].ID] = true
	}
	entries := make(map[string]*Entry, len(registry.Rules))
	if registry.Version != 1 {
		report.Problems = append(report.Problems, fmt.Sprintf("registry version %d is unsupported", registry.Version))
	}
	for i := 0; i < len(registry.Rules) && i < maxAuditRules; i++ {
		entry := &registry.Rules[i]
		if !knownIDs[entry.ID] {
			report.Problems = append(report.Problems, fmt.Sprintf("unknown rule id %q", entry.ID))
			continue
		}
		if _, exists := entries[entry.ID]; exists {
			report.Problems = append(report.Problems, fmt.Sprintf("duplicate rule id %q", entry.ID))
			continue
		}
		entries[entry.ID] = entry
		validateEntry(entry, report)
	}
	return entries
}

// validateEntry records structural schema violations for one registry entry.
func validateEntry(entry *Entry, report *Report) {
	if !validClass(entry.Class) {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: unknown class %q", entry.ID, entry.Class))
	}
	if entry.Class == ClassGuidance && len(entry.Evidence) > 0 {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: guidance must not carry evidence", entry.ID))
	}
	if entry.Class != ClassGuidance && len(entry.Evidence) == 0 {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: %s requires evidence", entry.ID, entry.Class))
	}
	if len(entry.Evidence) > maxEvidencePointers {
		report.Problems = append(report.Problems, fmt.Sprintf("%s: evidence exceeds %d pointers", entry.ID, maxEvidencePointers))
		return
	}
	for i := 0; i < len(entry.Evidence) && i < maxEvidencePointers; i++ {
		if len(entry.Evidence[i]) > maxPointerLength {
			report.Problems = append(report.Problems, fmt.Sprintf("%s: evidence pointer exceeds %d bytes", entry.ID, maxPointerLength))
		}
	}
}

// auditRule classifies one rule and resolves its declared local and forge evidence pointers.
func auditRule(
	ctx context.Context,
	root string,
	rule Rule,
	entry *Entry,
	forgeStates map[ForgeSetting]ForgeState,
	report *Report,
) Row {
	if entry == nil {
		return proseRow(rule, ClassGuidance)
	}
	row := Row{ID: rule.ID, Class: entry.Class, Status: StatusUnresolved}
	if len(entry.Evidence) > maxEvidencePointers {
		row.Evidence = "unresolved: too many evidence pointers"
		return row
	}
	if entry.Class == ClassGuidance {
		return proseRow(rule, entry.Class)
	}
	if !validClass(entry.Class) {
		row.Evidence = "unresolved: invalid class"
		return row
	}
	if len(entry.Evidence) == 0 {
		row.Evidence = "unresolved: no evidence"
		return row
	}
	resolver := evidenceResolver{
		ctx:         ctx,
		root:        root,
		ruleID:      rule.ID,
		forgeStates: forgeStates,
		row:         &row,
		report:      report,
	}
	resolution := resolver.resolve(entry.Evidence)
	row.Status = resolveRowStatus(resolution)
	row.Enforced = row.Status == StatusForgeObserved
	row.Evidence = evidenceSummary(row.Evidence, resolution)
	return row
}

type forgeOutcome int

const (
	forgePointerFailed forgeOutcome = iota
	forgePointerPending
	forgePointerMatched
)

type evidenceResolution struct {
	localPointers int
	localResolved bool
	forgeMatched  int
	forgePending  bool
	forgeFailed   bool
}

type evidenceResolver struct {
	ctx         context.Context
	root        string
	ruleID      string
	forgeStates map[ForgeSetting]ForgeState
	row         *Row
	report      *Report
}

// resolve checks every declared pointer of one rule and tallies local and forge outcomes.
func (r evidenceResolver) resolve(pointers []string) evidenceResolution {
	result := evidenceResolution{localResolved: true}
	for i := 0; i < len(pointers) && i < maxEvidencePointers; i++ {
		pointer := pointers[i]
		if strings.HasPrefix(pointer, "forge:") {
			r.recordForgeOutcome(&result, r.resolveForgePointer(pointer))
			continue
		}
		result.localPointers++
		if err := resolve(r.ctx, r.root, pointer); err != nil {
			if result.localResolved {
				r.row.Evidence = "unresolved: " + pointer
			}
			result.localResolved = false
			r.report.Problems = append(r.report.Problems, fmt.Sprintf("%s: %v", r.ruleID, err))
		}
	}
	return result
}

// recordForgeOutcome updates result with the outcome of one forge evidence pointer.
func (r evidenceResolver) recordForgeOutcome(result *evidenceResolution, outcome forgeOutcome) {
	switch outcome {
	case forgePointerMatched:
		result.forgeMatched++
	case forgePointerPending:
		result.forgePending = true
	default:
		result.forgeFailed = true
	}
}

// resolveForgePointer evaluates one forge: pointer against the loaded forge states.
func (r evidenceResolver) resolveForgePointer(pointer string) forgeOutcome {
	setting, ok := forgeSetting(pointer)
	if !ok {
		r.report.Problems = append(r.report.Problems, fmt.Sprintf("%s: unresolved evidence pointer %q", r.ruleID, pointer))
		return forgePointerFailed
	}
	state, ok := r.forgeStates[setting]
	if !ok || state.Asserted == "" {
		r.report.Problems = append(r.report.Problems,
			fmt.Sprintf("%s: forge setting %s has no committed assertion", r.ruleID, setting))
		return forgePointerFailed
	}
	comparison := ForgeComparison{Setting: setting, Asserted: state.Asserted, Observed: state.Observed,
		Match: state.Match, ReadBack: state.ReadBack}
	r.row.Forge = append(r.row.Forge, comparison)
	if !state.AssertedEnforced {
		r.report.Problems = append(r.report.Problems,
			fmt.Sprintf("%s: forge setting %s is asserted as %s", r.ruleID, setting, state.Asserted))
		return forgePointerFailed
	}
	if !state.ReadBack {
		return forgePointerPending
	}
	if state.Match {
		return forgePointerMatched
	}
	r.report.Problems = append(r.report.Problems, fmt.Sprintf(
		"%s: forge setting %s mismatch: asserted %s, observed %s", r.ruleID, setting, state.Asserted, state.Observed))
	return forgePointerFailed
}

// resolveRowStatus maps resolved local and forge pointer outcomes to one Row Status.
func resolveRowStatus(res evidenceResolution) Status {
	switch {
	case !res.localResolved || res.forgeFailed:
		return StatusUnresolved
	case res.forgePending:
		return StatusForgePending
	case res.forgeMatched > 0:
		return StatusForgeObserved
	case res.localPointers > 0:
		return StatusPresent
	default:
		return StatusUnresolved
	}
}

// evidenceSummary formats the evidence summary string for a non-prose rule row.
func evidenceSummary(current string, res evidenceResolution) string {
	hasResolved := res.localPointers > 0 || res.forgeMatched > 0
	switch {
	case !res.localResolved:
		return current
	case res.forgeFailed:
		return "unresolved"
	case hasResolved && res.forgePending:
		return "resolved; forge asserted, not read back"
	case hasResolved:
		return "resolved"
	case res.forgePending:
		return "asserted, not read back"
	default:
		return "unresolved"
	}
}

// proseRow builds the Row for a guidance or unregistered prose-only rule.
func proseRow(rule Rule, class Class) Row {
	return Row{
		ID:        rule.ID,
		Class:     class,
		Status:    StatusGuidance,
		Evidence:  "prose-only",
		ProseOnly: true,
		Candidate: prohibited(rule.Text),
	}
}

// resolve checks that one non-forge evidence pointer resolves structurally below root.
func resolve(ctx context.Context, root, pointer string) error {
	kind, value, ok := strings.Cut(pointer, ":")
	if !ok || value == "" || len(pointer) > maxPointerLength {
		return fmt.Errorf("unresolved evidence pointer %q", pointer)
	}
	switch kind {
	case "test":
		return resolveTest(ctx, root, value)
	case "hook":
		return resolveHook(ctx, root, value)
	case "make":
		return resolveMake(ctx, root, value)
	case "workflow":
		return resolveWorkflow(ctx, root, value)
	case "gate":
		if slices.Contains(gating.StageNames(), value) {
			return nil
		}
	}
	return fmt.Errorf("unresolved evidence pointer %q", pointer)
}

// resolveMake checks that Makefile declares target with at least one prerequisite or non-empty recipe line.
func resolveMake(ctx context.Context, root, target string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(target) {
		return fmt.Errorf("unresolved evidence pointer %q", "make:"+target)
	}
	data, err := readFile(ctx, root, "Makefile")
	if err != nil {
		return fmt.Errorf("read Makefile for make:%s: %w", target, err)
	}
	if util.MakefileTargetHasBody(string(data), target) {
		return nil
	}
	return fmt.Errorf("unresolved evidence pointer %q", "make:"+target)
}

// resolveWorkflow checks that .github/workflows/<file> defines job and its if: condition is not literal false.
func resolveWorkflow(ctx context.Context, root, value string) error {
	file, job, ok := strings.Cut(value, "#")
	path := ghworkflow.Dir + "/" + filepath.ToSlash(file)
	if !ok || !safeRelative(file) || !ghworkflow.IsWorkflowPath(path) || !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(job) {
		return fmt.Errorf("unresolved evidence pointer %q", "workflow:"+value)
	}
	data, err := readWorkflow(ctx, root, file)
	if err != nil {
		return fmt.Errorf("read workflow:%s: %w", value, err)
	}
	if _, err := ghworkflow.Parse(data); err != nil {
		return fmt.Errorf("workflow:%s: %w", value, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode condition for workflow:%s: %w", value, err)
	}
	if !hasActiveWorkflowJob(&document, job) {
		return fmt.Errorf("unresolved evidence pointer %q", "workflow:"+value)
	}
	return nil
}

// readWorkflow reads a flat workflow filename from the pinned repository workflow directory.
func readWorkflow(ctx context.Context, root, file string) (data []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	dir, err := contextopt.OpenDirectoryIn(ctx, root, ghworkflow.Dir)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	return contextopt.ReadRootSnapshot(ctx, dir, file)
}

// hasActiveWorkflowJob reports whether the named job can run, following one YAML alias
// level for the job mapping and its optional scalar condition.
func hasActiveWorkflowJob(document *yaml.Node, job string) bool {
	if len(document.Content) != 1 {
		return false
	}
	jobNode := unwrapYAMLAlias(util.YAMLMappingValue(util.YAMLMappingValue(document.Content[0], "jobs"), job))
	if jobNode == nil || jobNode.Kind != yaml.MappingNode {
		return false
	}
	ifNode := util.YAMLMappingValue(jobNode, "if")
	if ifNode == nil {
		return true
	}
	ifNode = unwrapYAMLAlias(ifNode)
	if ifNode == nil || ifNode.Kind != yaml.ScalarNode {
		return false
	}
	if ifNode.ShortTag() == "!!bool" {
		var enabled bool
		return ifNode.Decode(&enabled) == nil && enabled
	}
	return !ghworkflow.NeverRuns(ifNode.Value)
}

// unwrapYAMLAlias follows one YAML alias level to its target node, returning nil for nil or a nil Alias target.
func unwrapYAMLAlias(node *yaml.Node) *yaml.Node {
	if node != nil && node.Kind == yaml.AliasNode {
		return node.Alias
	}
	return node
}

// resolveHook checks that lefthook.yml or an extended lefthook config defines hook.command.
func resolveHook(ctx context.Context, root, value string) error {
	hook, command, ok := strings.Cut(value, ".")
	if !ok || !validHookName(hook) || !validHookName(command) {
		return fmt.Errorf("unresolved evidence pointer %q", "hook:"+value)
	}
	files, err := hookFiles(ctx, root)
	if err != nil {
		return fmt.Errorf("unresolved evidence pointer %q", "hook:"+value)
	}
	for i := 0; i < len(files) && i < 16; i++ {
		data, readErr := readFile(ctx, root, files[i])
		if readErr == nil && hasHookCommand(data, hook, command) {
			return nil
		}
	}
	return fmt.Errorf("unresolved evidence pointer %q", "hook:"+value)
}

// safeRelative reports whether value is a non-empty local relative path.
func safeRelative(value string) bool {
	return value != "" && !filepath.IsAbs(value) && filepath.IsLocal(filepath.FromSlash(value))
}

// validHookName reports whether value is an allowed lefthook hook or command identifier.
func validHookName(value string) bool {
	return regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(value)
}

// hookFiles collects lefthook.yml and up to 16 extended configs below .config/lefthook/, rejecting cycles.
func hookFiles(ctx context.Context, root string) ([]string, error) {
	queue, files := []string{"lefthook.yml"}, []string{}
	seen := map[string]bool{}
	for i := 0; i < len(queue) && i < 16; i++ {
		file := queue[i]
		if seen[file] {
			return nil, fmt.Errorf("lefthook extensions form a cycle")
		}
		data, err := readFile(ctx, root, file)
		if err != nil {
			return nil, err
		}
		seen[file], files = true, append(files, file)
		extends, err := checkedExtensions(data, len(queue))
		if err != nil {
			return nil, err
		}
		queue = append(queue, extends...)
	}
	return files, nil
}

// checkedExtensions are the extends entries of one lefthook file: at most 16 files in all, each a safe relative path
// below .config/lefthook/.
func checkedExtensions(data []byte, queued int) ([]string, error) {
	extends, err := lefthookExtends(data)
	if err != nil {
		return nil, err
	}
	if queued+len(extends) > 16 {
		return nil, fmt.Errorf("lefthook extensions exceed 16 files")
	}
	for j := 0; j < len(extends) && j < 16; j++ {
		if !safeRelative(extends[j]) || !strings.HasPrefix(extends[j], ".config/lefthook/") {
			return nil, fmt.Errorf("unsafe lefthook extension")
		}
	}
	return extends, nil
}

// lefthookExtends decodes the extends list from a lefthook YAML file.
func lefthookExtends(data []byte) ([]string, error) {
	var document struct {
		Extends []string `yaml:"extends"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("decode lefthook YAML: %w", err)
	}
	return document.Extends, nil
}

// hasHookCommand reports whether a lefthook YAML document declares command under hook's commands, scripts, or jobs.
func hasHookCommand(data []byte, hook, command string) bool {
	var document yaml.Node
	if yaml.Unmarshal(data, &document) != nil || len(document.Content) != 1 {
		return false
	}
	hookNode := util.YAMLMappingValue(document.Content[0], hook)
	return util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "commands"), command) != nil ||
		util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "scripts"), command) != nil ||
		util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "jobs"), command) != nil
}
