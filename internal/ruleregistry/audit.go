package ruleregistry

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// auditDiagnostics keeps pointer and forge readback errors available while collecting report rows.
type auditDiagnostics struct {
	*Report
	causes []error
}

// Error summarizes the invalid declarations in the audit.
func (d *auditDiagnostics) Error() string {
	return fmt.Sprintf("rules audit: %d invalid declaration(s)", len(d.Problems))
}

// Unwrap returns the underlying errors from resolving evidence.
func (d *auditDiagnostics) Unwrap() []error {
	return d.causes
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
	report := &auditDiagnostics{Report: &Report{}}
	entries := indexEntries(registry, known, report.Report)
	forgeStates := loadForgeStates(ctx, registry, opts, report)
	for i := 0; i < len(known) && i < maxAuditRules; i++ {
		row := auditRule(ctx, root, known[i], entries[known[i].ID], forgeStates, report)
		report.Rows = append(report.Rows, row)
	}
	if report.Valid() {
		return report.Report, nil
	}
	return report.Report, report
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
	report *auditDiagnostics,
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
		if len(entry.Evidence) > 0 {
			// Validation already refuses this entry; the row must not claim prose-only either.
			row.Evidence = "unresolved: guidance carries evidence"
			return row
		}
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
	report      *auditDiagnostics
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
			r.report.causes = append(r.report.causes, err)
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

// resolveMake checks for a literal rule and distinguishes an unprovable body from a missing target.
func resolveMake(ctx context.Context, root, target string) error {
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(target) {
		return fmt.Errorf("unresolved evidence pointer %q: not statically provable", "make:"+target)
	}
	data, err := readAuditMakefile(ctx, root)
	if err != nil {
		return fmt.Errorf("unresolved evidence pointer %q: not statically provable: %w", "make:"+target, err)
	}
	switch util.MakefileTargetStatus(string(data), target) {
	case util.MakefileTargetPresent:
		return nil
	case util.MakefileTargetUnproven:
		return fmt.Errorf("unresolved evidence pointer %q: not statically provable", "make:"+target)
	}
	return fmt.Errorf("unresolved evidence pointer %q", "make:"+target)
}

// readAuditMakefile selects GNU Make's first default file and checks its pinned directory for remake sources.
func readAuditMakefile(ctx context.Context, root string) (data []byte, err error) {
	ctx, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	dir, err := contextopt.OpenDirectoryIn(ctx, root, ".")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for _, name := range util.DefaultMakefileNames() {
		data, exists, err := contextopt.ObserveRootSnapshot(ctx, dir, name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		if exists {
			return data, util.MakefileImplicitSourceNear(ctx, dir, name)
		}
	}
	return nil, fmt.Errorf("no default makefile: %w", os.ErrNotExist)
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
	return checkWorkflowJob(data, value, job)
}

// checkWorkflowJob resolves the effective condition through the typed parser after verifying its path.
func checkWorkflowJob(data []byte, value, job string) error {
	spec, err := ghworkflow.Parse(data)
	if err != nil {
		return fmt.Errorf("workflow:%s: %w", value, err)
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("decode condition for workflow:%s: %w", value, err)
	}
	parsed, exists := spec.Jobs[job]
	if !exists || !literalWorkflowJobPath(&document, job) || ghworkflow.NeverRuns(parsed.If) || strings.EqualFold(parsed.If, "false") {
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

// literalWorkflowJobPath verifies that the job is a mapping with an explicit path and that
// no mapping supplying its condition inherits keys. Parse supplies the effective condition.
func literalWorkflowJobPath(document *yaml.Node, job string) bool {
	if len(document.Content) != 1 {
		return false
	}
	node := document.Content[0]
	for _, key := range [...]string{"jobs", job, "if"} {
		node = unwrapYAMLAlias(node)
		if node == nil || node.Kind != yaml.MappingNode || util.YAMLMappingValue(node, "<<") != nil {
			return false
		}
		node = util.YAMLMappingValue(node, key)
	}
	if node == nil {
		return true
	}
	condition := unwrapYAMLAlias(node)
	return condition != nil && condition.Kind == yaml.ScalarNode && condition.ShortTag() != "!!null"
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
	found, err := hookCommandInFiles(ctx, root, hook, command)
	if err != nil {
		return fmt.Errorf("resolve hook:%s: %w", value, err)
	}
	if found {
		return nil
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

// hookCommandInFiles checks each snapshot for extensions and commands, validating the complete extension graph.
func hookCommandInFiles(ctx context.Context, root, hook, command string) (bool, error) {
	queue := []string{"lefthook.yml"}
	seen := map[string]bool{}
	found := false
	for i := 0; i < len(queue) && i < 16; i++ {
		file := queue[i]
		if seen[file] {
			return false, fmt.Errorf("lefthook extensions form a cycle")
		}
		data, err := readFile(ctx, root, file)
		if err != nil {
			return false, fmt.Errorf("read %s: %w", file, err)
		}
		var document yaml.Node
		if err := yaml.Unmarshal(data, &document); err != nil {
			return false, fmt.Errorf("decode %s: %w", file, err)
		}
		extends, err := checkedExtensions(&document, len(queue))
		if err != nil {
			return false, fmt.Errorf("%s: %w", file, err)
		}
		seen[file] = true
		found = found || hasHookCommand(&document, hook, command)
		queue = append(queue, extends...)
	}
	return found, nil
}

// checkedExtensions are the extends entries of one lefthook file: at most 16 files in all, each a safe relative path
// below .config/lefthook/.
func checkedExtensions(document *yaml.Node, queued int) ([]string, error) {
	var config struct {
		Extends []string `yaml:"extends"`
	}
	if err := document.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode lefthook YAML: %w", err)
	}
	extends := config.Extends
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

// hasHookCommand reports whether a lefthook YAML document declares command under hook's commands, scripts, or jobs.
func hasHookCommand(document *yaml.Node, hook, command string) bool {
	if len(document.Content) != 1 {
		return false
	}
	hookNode := util.YAMLMappingValue(document.Content[0], hook)
	return util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "commands"), command) != nil ||
		util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "scripts"), command) != nil ||
		util.YAMLMappingValue(util.YAMLMappingValue(hookNode, "jobs"), command) != nil
}
