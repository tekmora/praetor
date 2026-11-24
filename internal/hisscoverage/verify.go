package hisscoverage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	slashpath "path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/hiss"
	"github.com/cordanaLLM/praetor/internal/util"
	"go.yaml.in/yaml/v3"
)

const (
	// CatalogFile is the declared enforcement evidence, relative to the repository root.
	CatalogFile = ".config/hiss/coverage.yaml"
	// FixtureDir holds the corpus that backs every claim in the catalog. It is named testdata
	// because the HISS scanner already ignores that directory name, and these files are
	// inputs to the rules rather than source governed by them: scanning them would report
	// the engine's own test data as the repository's debt.
	FixtureDir = ".config/hiss/testdata"
	// maxCatalogBytes bounds the catalog read (HISS-02).
	maxCatalogBytes = 256 * 1024
	// maxFixturesPerBucket bounds one positive, negative, gap or measured directory (HISS-02).
	maxFixturesPerBucket = 256
	// maxFixtureMarkerLines bounds the leading comment lines inspected for a hiss-fixture marker (HISS-02).
	maxFixtureMarkerLines = 32
	// fixtureMarkerPrefix introduces an intentional gap marker inside a leading fixture comment.
	fixtureMarkerPrefix = "hiss-fixture:"
	// maxCorpusDirs bounds the directories Verify walks below FixtureDir (HISS-02).
	maxCorpusDirs = 4096
	// maxCorpusEntries bounds the entries read from one directory below FixtureDir (HISS-02).
	maxCorpusEntries = 4096
)

// Bucket names within a fixture directory. A measured fixture holds a shape the scanner
// measures and reports without enforcing it: it must yield a measurement for the rule and no
// violation. A negative fixture must yield neither.
const (
	bucketPositive = "positive"
	bucketNegative = "negative"
	bucketGap      = "gap"
	bucketMeasured = "measured"
)

// ErrCatalogAbsent reports that no catalog is present.
var ErrCatalogAbsent = errors.New("hisscoverage: no coverage catalog")

// ErrClaimUnsupported reports a claim the corpus contradicts.
var ErrClaimUnsupported = errors.New("hisscoverage: declared coverage is not supported by its fixtures")

// LoadCatalog reads and validates the declared enforcement evidence.
func LoadCatalog(ctx context.Context, rootDir string) (*Catalog, error) {
	data, err := readCatalogFile(ctx, rootDir)
	if err != nil {
		return nil, err
	}
	return parseCatalog(data)
}

// readCatalogFile reads the coverage file below rootDir, bounded by maxCatalogBytes.
func readCatalogFile(ctx context.Context, rootDir string) ([]byte, error) {
	path := filepath.Join(rootDir, filepath.FromSlash(CatalogFile))
	data, err := contextopt.ReadSnapshot(ctx, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w at %s", ErrCatalogAbsent, CatalogFile)
		}
		return nil, fmt.Errorf("read coverage catalog: %w", err)
	}
	if len(data) > maxCatalogBytes {
		return nil, fmt.Errorf("coverage catalog exceeds %d bytes", maxCatalogBytes)
	}
	return data, nil
}

// parseCatalog decodes and validates the text of a coverage file.
func parseCatalog(data []byte) (*Catalog, error) {
	catalog, err := decodeCatalog(data)
	if err != nil {
		return nil, err
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	return catalog, nil
}

// decodeCatalog parses exactly one document with no unknown fields, so a misspelled key is
// an error rather than a silently dropped claim.
func decodeCatalog(data []byte) (*Catalog, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: document is empty", ErrCatalogAbsent)
		}
		return nil, fmt.Errorf("decode coverage catalog: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: catalog must contain exactly one document", ErrInvalidCatalog)
	}
	return &catalog, nil
}

// Finding is one way the corpus contradicted the catalog.
type Finding struct {
	Rule     string
	Language string
	Bucket   string
	Fixture  string
	Detail   string
}

// String renders a finding for a terminal report, omitting empty cell or bucket segments so
// corpus-ownership findings outside a full rule/language/bucket/fixture path format cleanly.
func (f Finding) String() string {
	head := slashJoinNonEmpty(f.Rule, f.Language)
	leaf := slashJoinNonEmpty(f.Bucket, f.Fixture)
	switch {
	case head != "" && leaf != "":
		return fmt.Sprintf("%s %s: %s", head, leaf, f.Detail)
	case head != "":
		return fmt.Sprintf("%s: %s", head, f.Detail)
	case leaf != "":
		return fmt.Sprintf("%s: %s", leaf, f.Detail)
	default:
		return f.Detail
	}
}

// slashJoinNonEmpty joins a and b with a slash when both are non-empty, or returns whichever is set.
func slashJoinNonEmpty(a, b string) string {
	switch {
	case a != "" && b != "":
		return a + "/" + b
	case a != "":
		return a
	default:
		return b
	}
}

// Report is the outcome of replaying the corpus against the catalog.
type Report struct {
	Claims   int
	Fixtures int
	Findings []Finding
	// Unbacked lists claims of detection that have no positive fixture at all. They are
	// reported separately because an unbacked claim is not yet wrong, it is merely
	// undemonstrated, and the distinction matters while the corpus is being filled in.
	Unbacked []string
	// Delegated lists claims decided by a tool this package does not run. Their enforcement
	// is not proven here, only their attribution, and saying so is the point: a claim this
	// gate cannot replay must not be indistinguishable from one it verified.
	Delegated []string
	// Unexamined lists gap fixtures explicitly marked as intentionally unparsed or
	// unrecognised by the scanner, with their stated reason, so an intentional parser or
	// scope gap is surfaced rather than silently certified.
	Unexamined []string
}

// Passed reports whether every claim survived its fixtures.
func (r *Report) Passed() bool {
	return r != nil && len(r.Findings) == 0
}

// Verify replays the fixture corpus, reconciles FixtureDir against catalog, and reports every
// contradiction or unowned path.
//
// The check runs in both directions across claims and across the directory tree. A state
// claiming detection must report each of its positive fixtures, and a state claiming none must
// leave its gap fixtures undetected, stopping the catalog from quietly becoming pessimistic
// when a rule gains coverage. Walking FixtureDir in reverse ensures every file and language
// directory on disk belongs to a valid bucket of a declared rule and language cell, naming the
// path whenever an orphan fixture or misspelled directory goes unowned.
// An incomplete (unparsed or truncated) or zero-file fixture scan never certifies a
// negative, gap, measured, positive or delegated claim.
func Verify(ctx context.Context, rootDir string, catalog *Catalog) (*Report, error) {
	if ctx == nil {
		return nil, errors.New("hisscoverage: verify requires a context")
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	report := &Report{}
	for i := 0; i < len(catalog.Rules); i++ {
		rule := &catalog.Rules[i]
		for j := 0; j < len(rule.Coverage); j++ {
			if err := verifyClaim(ctx, rootDir, rule.ID, &rule.Coverage[j], report); err != nil {
				return nil, err
			}
		}
	}
	if err := verifyCorpus(ctx, rootDir, catalog, report); err != nil {
		return nil, err
	}
	sort.Slice(report.Findings, func(a, b int) bool {
		return report.Findings[a].String() < report.Findings[b].String()
	})
	return report, nil
}

// verifyClaim replays one rule/language claim against its fixture buckets.
func verifyClaim(ctx context.Context, rootDir, ruleID string, cov *Coverage, report *Report) error {
	report.Claims++
	base := filepath.Join(rootDir, filepath.FromSlash(FixtureDir), ruleID, cov.Language)
	if err := verifyMeasured(ctx, base, ruleID, cov, report); err != nil {
		return err
	}
	if !cov.ReplayedHere() {
		return verifyDelegatedClaim(ctx, base, ruleID, cov, report)
	}
	if err := verifyPositiveBucket(ctx, base, ruleID, cov, report); err != nil {
		return err
	}
	if err := verifyNegativeBucket(ctx, base, ruleID, cov, report); err != nil {
		return err
	}
	return verifyGapBucket(ctx, base, ruleID, cov, report)
}

// verifyPositiveBucket replays the positive bucket of a HISS-replayed claim.
func verifyPositiveBucket(ctx context.Context, base, ruleID string, cov *Coverage, report *Report) error {
	positives, err := replayBucket(ctx, base, bucketPositive, ruleID, report)
	if err != nil {
		return err
	}
	appendUncertified(report, ruleID, cov.Language, bucketPositive, "", positives)
	if cov.State.ClaimsDetection() {
		if len(positives) == 0 {
			report.Unbacked = append(report.Unbacked,
				fmt.Sprintf("%s/%s claims %s with no positive fixture", ruleID, cov.Language, cov.State))
		}
		appendFindings(report, ruleID, cov.Language, bucketPositive, positives, undetected,
			"declared "+string(cov.State)+" but the fixture is not reported")
		return nil
	}
	appendFindings(report, ruleID, cov.Language, bucketPositive, positives, detected,
		"declared "+string(cov.State)+" yet the fixture is reported; the catalog understates coverage")
	return nil
}

// verifyNegativeBucket replays the negative bucket of a HISS-replayed claim: every fixture must
// be completely scanned in the claim's language and yield neither a violation nor a measurement.
func verifyNegativeBucket(ctx context.Context, base, ruleID string, cov *Coverage, report *Report) error {
	negatives, err := replayBucket(ctx, base, bucketNegative, ruleID, report)
	if err != nil {
		return err
	}
	appendUncertified(report, ruleID, cov.Language, bucketNegative, "", negatives)
	appendFindings(report, ruleID, cov.Language, bucketNegative, negatives, detected,
		"legitimate code is reported; the rule over-matches")
	appendFindings(report, ruleID, cov.Language, bucketNegative, negatives, measured,
		"legitimate code is measured over a limit; the measurement over-matches")
	return nil
}

// verifyGapBucket replays the gap bucket of a HISS-replayed claim: every unmarked fixture must
// be completely scanned in the claim's language and go undetected, while a fixture explicitly
// marked unparsed or unexamined must still exhibit that non-analysed state.
func verifyGapBucket(ctx context.Context, base, ruleID string, cov *Coverage, report *Report) error {
	gaps, err := replayBucket(ctx, base, bucketGap, ruleID, report)
	if err != nil {
		return err
	}
	appendUncertified(report, ruleID, cov.Language, bucketGap, "", gaps)
	appendFindings(report, ruleID, cov.Language, bucketGap, gaps, detected,
		"a fixture recorded as an undetected gap is now reported; close the gap in the catalog")
	return nil
}

// verifyMeasured replays the measured bucket in both directions: each fixture must be
// completely scanned in the claim's language, yield a measurement for the rule, and yield no
// violation. Together with the negative bucket, whose fixtures sit exactly at the limits and
// must yield no measurement, this pins the limits from both sides.
func verifyMeasured(ctx context.Context, base, ruleID string, cov *Coverage, report *Report) error {
	results, err := replayBucket(ctx, base, bucketMeasured, ruleID, report)
	if err != nil {
		return err
	}
	appendUncertified(report, ruleID, cov.Language, bucketMeasured, "", results)
	appendFindings(report, ruleID, cov.Language, bucketMeasured, results, unmeasured,
		"declared measured but the fixture yields no measurement")
	appendFindings(report, ruleID, cov.Language, bucketMeasured, results, detected,
		"a measured fixture is reported as a violation; a measurement must never be enforced")
	return nil
}

// verifyDelegatedClaim checks a claim whose runner is not the HISS scanner.
//
// What can be verified here is the attribution, not the enforcement: the deciding tool is
// golangci-lint, gitleaks, the forge commit check or a CI step, none of which this package
// runs. So every bucket is held to one expectation -- a complete scan by the HISS scanner must
// report none of them, and for every language a HISS scanner reads it must examine at least one
// file of that language. If it reports one, or fails to complete its scan, attribution is not
// certified.
//
// The delegation itself is recorded so a reader can see which claims this gate proves and
// which it only attributes. An unreplayed claim that passes silently would be indistinguishable
// from a verified one, which is the state this whole mechanism replaced.
func verifyDelegatedClaim(ctx context.Context, base, ruleID string, cov *Coverage, report *Report) error {
	note := fmt.Sprintf("%s/%s is decided by %s, not replayed here", ruleID, cov.Language, cov.Runner)
	if !scannerLanguages[cov.Language] {
		note += fmt.Sprintf(" (no HISS scanner reads %s)", cov.Language)
	}
	report.Delegated = append(report.Delegated, note)
	buckets := [...]string{bucketPositive, bucketNegative, bucketGap}
	for i := 0; i < len(buckets); i++ {
		results, err := replayBucket(ctx, base, buckets[i], ruleID, report)
		if err != nil {
			return err
		}
		appendUncertified(report, ruleID, cov.Language, buckets[i], cov.Runner, results)
		appendFindings(report, ruleID, cov.Language, buckets[i], results, detected,
			"attributed to "+cov.Runner+" yet the HISS scanner reports it; the runner is wrong")
	}
	return nil
}

// intentionalKind names the non-analysed outcome a gap fixture explicitly marks as its subject.
type intentionalKind string

const (
	// intentionalNone means the fixture carries no non-analysed gap marker.
	intentionalNone intentionalKind = ""
	// intentionalUnparsed marks a gap fixture whose syntax error keeps the scanner from parsing it.
	intentionalUnparsed intentionalKind = "unparsed"
	// intentionalUnexamined marks a gap fixture whose path or shape the language scanner declines.
	intentionalUnexamined intentionalKind = "unexamined"
)

// nativeLanguages lists the coverage keys internal/hiss records for the native ("c") scanner.
var nativeLanguages = [...]string{"c", "cpp", "cuda", "objective-c++"}

// scannerLanguages lists the coverage language names implemented by internal/hiss scanners.
var scannerLanguages = map[string]bool{
	"go": true, "c": true, "cpp": true, "cuda": true, "objective-c++": true,
	"python": true, "rust": true, "javascript": true, "typescript": true,
	"svelte": true, "shell": true, "github-actions": true, "systemd": true, "ansible": true,
}

// commentPrefixes lists the leading comment openers a fixture header marker may sit behind.
var commentPrefixes = [...]string{"//", "#", ";", "/*", "<!--"}

// fixtureResult records what the scanner said about one fixture for one rule.
type fixtureResult struct {
	// name is the fixture file name within its bucket directory.
	name string
	// detected is true when a certified scan reported the fixture as a violation of the rule.
	detected bool
	// measured is true when a certified scan measured the fixture over a limit of the rule.
	measured bool
	// rawDetected records whether Breakdown named the rule before certification gating.
	rawDetected bool
	// incomplete states why ScanReport.Incomplete refused to certify the scan, or "".
	incomplete string
	// unexamined states why no HISS language scanner examined a file of stage.language, or "".
	unexamined string
	// unparsed is true when the scan recorded at least one unparseable file.
	unparsed bool
	// truncated is true when the scan stopped at an infraction, file or AST-depth bound.
	truncated bool
	// hasUnscanned is true when the walk observed at least one regular unscanned file.
	hasUnscanned bool
	// marked names the intentional non-analysed class declared in the fixture header, if any.
	marked intentionalKind
	// markedReason holds the mandatory explanation accompanying marked.
	markedReason string
	// markerErr describes a malformed hiss-fixture header comment, if any.
	markerErr string
}

// certified reports whether the fixture's scan completed over its declared language with no
// intentional non-analysed marker, allowing detection and measurement predicates to read it.
func (r fixtureResult) certified() bool {
	return r.incomplete == "" && r.unexamined == "" && r.markerErr == "" && r.marked == intentionalNone
}

// detected selects certified fixtures reported as violations.
func detected(r fixtureResult) bool { return r.certified() && r.detected }

// undetected selects certified fixtures not reported as violations.
func undetected(r fixtureResult) bool { return r.certified() && !r.detected }

// measured selects certified fixtures measured over a complexity limit of the rule.
func measured(r fixtureResult) bool { return r.certified() && r.measured }

// unmeasured selects certified fixtures yielding no measurement for the rule.
func unmeasured(r fixtureResult) bool { return r.certified() && !r.measured }

// appendFindings records a finding for every fixture the predicate selects.
func appendFindings(report *Report, ruleID, lang, bucket string, results []fixtureResult, selects func(fixtureResult) bool, detail string) {
	for i := 0; i < len(results); i++ {
		if selects(results[i]) {
			report.Findings = append(report.Findings, Finding{
				Rule: ruleID, Language: lang, Bucket: bucket, Fixture: results[i].name, Detail: detail,
			})
		}
	}
}

// appendUncertified records findings for fixtures whose scan could not certify their bucket's
// expectation, and records accepted intentional gap markers in report.Unexamined.
func appendUncertified(report *Report, ruleID, lang, bucket, runner string, results []fixtureResult) {
	for i := 0; i < len(results); i++ {
		r := results[i]
		if r.certified() {
			continue
		}
		detail := uncertifiedDetail(r, lang, bucket, runner)
		if detail != "" {
			report.Findings = append(report.Findings, Finding{
				Rule: ruleID, Language: lang, Bucket: bucket, Fixture: r.name, Detail: detail,
			})
			continue
		}
		if r.marked != intentionalNone {
			report.Unexamined = append(report.Unexamined,
				fmt.Sprintf("%s/%s %s/%s: intentionally %s (%s)", ruleID, lang, bucket, r.name, r.marked, r.markedReason))
		}
	}
}

// uncertifiedDetail returns the finding text for an uncertified fixture result, or "" when the
// non-analysed outcome is an accepted intentional gap or a scannerless delegated language.
func uncertifiedDetail(r fixtureResult, lang, bucket, runner string) string {
	if r.markerErr != "" {
		return "invalid fixture marker: " + r.markerErr
	}
	replayedHere := runner == "" || runner == RunnerHISS
	if r.marked != intentionalNone {
		if !replayedHere || bucket != bucketGap {
			return fmt.Sprintf("fixture is marked %s (%s), which is only valid in %s/ of a HISS-replayed claim",
				r.marked, r.markedReason, bucketGap)
		}
		return markedGapDetail(r, lang)
	}
	if !replayedHere {
		return delegatedUncertifiedDetail(r, lang, runner)
	}
	if r.incomplete != "" {
		return "fixture scan is incomplete: " + r.incomplete
	}
	return fmt.Sprintf("fixture scan examined no %s file: %s", lang, r.unexamined)
}

// delegatedUncertifiedDetail checks an uncertified fixture of a claim delegated to runner.
func delegatedUncertifiedDetail(r fixtureResult, lang, runner string) string {
	if r.incomplete != "" {
		return fmt.Sprintf("attributed to %s yet fixture scan is incomplete: %s", runner, r.incomplete)
	}
	if r.rawDetected {
		return fmt.Sprintf("attributed to %s yet the HISS scanner reports it; the runner is wrong", runner)
	}
	if !scannerLanguages[lang] && r.hasUnscanned {
		return ""
	}
	return fmt.Sprintf("attributed to %s yet fixture scan examined no %s file: %s", runner, lang, r.unexamined)
}

// markedGapDetail checks a gap fixture that explicitly declares itself unparsed or unexamined.
func markedGapDetail(r fixtureResult, lang string) string {
	if r.truncated {
		return "marked " + string(r.marked) + " yet fixture scan truncated at an analysis bound"
	}
	if r.rawDetected {
		return "a fixture recorded as an undetected gap is now reported; close the gap in the catalog"
	}
	if r.marked == intentionalUnparsed {
		if !r.unparsed {
			return fmt.Sprintf("marked unparsed (%s) yet the scanner parsed the %s fixture cleanly", r.markedReason, lang)
		}
		return ""
	}
	if r.incomplete != "" {
		return "marked unexamined yet fixture scan is incomplete: " + r.incomplete
	}
	if r.unexamined == "" {
		return fmt.Sprintf("marked unexamined (%s) yet the scanner examined the %s fixture", r.markedReason, lang)
	}
	return ""
}

// replayBucket scans every fixture in one bucket and reports whether the rule fired on it.
// An absent bucket is not an error: a claim may legitimately have no negative or gap case.
// base is the claim's directory, <FixtureDir>/<rule>/<language>, so its name is the language
// the fixtures are staged as (hiss.FixturePath).
func replayBucket(ctx context.Context, base, bucket, ruleID string, report *Report) ([]fixtureResult, error) {
	dir := filepath.Join(base, bucket)
	staged := fixtureStage{ruleID: ruleID, language: filepath.Base(base)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if util.DirectoryAbsent(dir, err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read fixtures %s: %w", dir, err)
	}
	results := make([]fixtureResult, 0, len(entries))
	for i := 0; i < len(entries) && i < maxFixturesPerBucket; i++ {
		if entries[i].IsDir() {
			continue
		}
		result, err := staged.reported(ctx, dir, entries[i].Name())
		if err != nil {
			return nil, err
		}
		report.Fixtures++
		results = append(results, result)
	}
	return results, nil
}

// fixtureStage is the rule a bucket's fixtures are replayed for and the language they are
// staged as.
type fixtureStage struct {
	ruleID   string
	language string
}

// reported scans one fixture in isolation and propagates scan completion and language
// examination into the fixtureResult before recording rule violations or measurements.
//
// Each fixture is scanned alone in a temporary directory so a finding cannot be attributed
// to a neighbouring file, and so a fixture that fails to parse cannot silently suppress the
// rest of its bucket. It is staged where the scan reads its language (hiss.FixturePath): a
// GitHub Actions workflow in .github/workflows, any other fixture at the root. An archive
// fixture (archive.go) is staged as the files it holds, each at its own path.
func (stage fixtureStage) reported(ctx context.Context, dir, name string) (result fixtureResult, err error) {
	result.name = name
	data, err := contextopt.ReadSnapshot(ctx, filepath.Join(dir, name))
	if err != nil {
		return result, fmt.Errorf("read fixture %s: %w", name, err)
	}
	result.marked, result.markedReason, result.markerErr = parseFixtureMarker(data)
	tmp, err := os.MkdirTemp("", "hiss-fixture-")
	if err != nil {
		return result, fmt.Errorf("create fixture root: %w", err)
	}
	// A cleanup failure leaves a scratch directory behind and is joined into the result
	// rather than discarded: a verifier that silently ignores its own errors is the shape
	// this package exists to detect.
	defer func() { err = errors.Join(err, os.RemoveAll(tmp)) }()
	if err := stage.stage(tmp, name, data); err != nil {
		return result, fmt.Errorf("stage fixture %s: %w", name, err)
	}
	rep, scanErr := hiss.Scan(ctx, tmp, hiss.ScanOptions{})
	if scanErr != nil {
		return result, fmt.Errorf("scan fixture %s: %w", name, scanErr)
	}
	result.recordScan(rep, stage.ruleID, stage.language)
	return result, nil
}

// recordScan propagates scan completion and language examination into r before recording
// rule findings or complexity measurements, so no predicate can read an unexamined or
// incomplete scan as clean compliance or valid detection.
func (r *fixtureResult) recordScan(rep *hiss.ScanReport, ruleID, language string) {
	if rep == nil {
		r.incomplete = "scan returned no report"
		return
	}
	r.rawDetected = rep.Breakdown[ruleID] > 0
	r.truncated = rep.Truncated
	r.unparsed = rep.Skips.Unparsed > 0
	r.hasUnscanned = rep.Coverage != nil && rep.Coverage.UnscannedFiles > 0
	r.incomplete = scanIncompleteReason(rep)
	if r.incomplete == "" && !examinedLanguage(rep.Coverage, language) {
		r.unexamined = scanUnexaminedReason(rep, language)
	}
	if !r.certified() {
		return
	}
	r.detected = r.rawDetected
	r.measured = measuresRule(rep.Complexity.Measurements, ruleID)
}

// scanIncompleteReason explains why rep.Incomplete refused to certify the scan, or returns "".
func scanIncompleteReason(rep *hiss.ScanReport) string {
	if !rep.Incomplete() {
		return ""
	}
	switch {
	case rep.Truncated && rep.Skips.Unparsed > 0:
		return fmt.Sprintf("scan truncated at an analysis bound and %d file(s) yielded no analyzable structure", rep.Skips.Unparsed)
	case rep.Truncated:
		return "scan truncated at an analysis bound"
	default:
		return fmt.Sprintf("%d file(s) yielded no analyzable structure", rep.Skips.Unparsed)
	}
}

// scanUnexaminedReason explains why no HISS scanner examined any file of language.
func scanUnexaminedReason(rep *hiss.ScanReport, language string) string {
	if !scannerLanguages[language] {
		return fmt.Sprintf("no HISS scanner reads %s", language)
	}
	if rep.Coverage != nil && rep.Coverage.UnscannedFiles > 0 {
		return fmt.Sprintf("0 %s file(s) examined (%d file(s) left unscanned)", language, rep.Coverage.UnscannedFiles)
	}
	if rep.Skips.Oversize > 0 || rep.Skips.Symlinks > 0 || rep.Skips.Irregular > 0 {
		return fmt.Sprintf("0 %s file(s) examined (skipped oversize=%d symlinks=%d irregular=%d)",
			language, rep.Skips.Oversize, rep.Skips.Symlinks, rep.Skips.Irregular)
	}
	return fmt.Sprintf("0 %s file(s) examined", language)
}

// examinedLanguage reports whether cov records at least one examined file for language.
func examinedLanguage(cov *hiss.ScanCoverage, language string) bool {
	if cov == nil || cov.FilesRead <= 0 {
		return false
	}
	if language == "c" {
		total := 0
		for i := 0; i < len(nativeLanguages); i++ {
			total += cov.LanguagesRead[nativeLanguages[i]]
		}
		return total > 0
	}
	return cov.LanguagesRead[language] > 0
}

// parseFixtureMarker reads an optional `hiss-fixture: <unparsed|unexamined>: <reason>` header
// from the leading comment lines of a fixture, returning (kind, reason, errDetail).
func parseFixtureMarker(data []byte) (intentionalKind, string, string) {
	text := string(data)
	var kind intentionalKind
	var reason string
	for i := 0; i < maxFixtureMarkerLines && text != ""; i++ {
		var line string
		line, text, _ = strings.Cut(text, "\n")
		body, stop := nextHeaderComment(line)
		if stop {
			break
		}
		spec, marked := strings.CutPrefix(body, fixtureMarkerPrefix)
		if !marked {
			continue
		}
		if kind != intentionalNone {
			return intentionalNone, "", "declares hiss-fixture marker more than once"
		}
		parsedKind, parsedReason, errDetail := parseMarkerSpec(spec)
		if errDetail != "" {
			return intentionalNone, "", errDetail
		}
		kind, reason = parsedKind, parsedReason
	}
	return kind, reason, ""
}

// nextHeaderComment classifies one leading fixture line as comment text, blank, or code start.
func nextHeaderComment(line string) (string, bool) {
	if strings.TrimSpace(line) == "" {
		return "", false
	}
	body, ok := trimFixtureComment(line)
	return body, !ok
}

// trimFixtureComment strips one leading comment opener and any closing comment token.
func trimFixtureComment(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	for i := 0; i < len(commentPrefixes); i++ {
		if rest, ok := strings.CutPrefix(trimmed, commentPrefixes[i]); ok {
			rest = strings.TrimSuffix(strings.TrimSpace(rest), "*/")
			rest = strings.TrimSuffix(strings.TrimSpace(rest), "-->")
			return strings.TrimSpace(rest), true
		}
	}
	return "", false
}

// parseMarkerSpec validates the `<unparsed|unexamined>: <reason>` payload after `hiss-fixture:`.
func parseMarkerSpec(spec string) (intentionalKind, string, string) {
	rawKind, rawReason, hasColon := strings.Cut(strings.TrimSpace(spec), ":")
	kind := intentionalKind(strings.TrimSpace(rawKind))
	if kind != intentionalUnparsed && kind != intentionalUnexamined {
		return intentionalNone, "", fmt.Sprintf("unknown hiss-fixture class %q (want unparsed or unexamined)", strings.TrimSpace(rawKind))
	}
	reason := strings.TrimSpace(rawReason)
	if !hasColon || reason == "" {
		return intentionalNone, "", fmt.Sprintf("hiss-fixture %s marker requires a non-empty ': <reason>'", kind)
	}
	return kind, reason, ""
}

// stage writes one fixture's bytes below root: an archive as the files it holds, any other
// fixture where the scan reads its language.
func (stage fixtureStage) stage(root, name string, data []byte) error {
	if filepath.Ext(name) == archiveExt {
		return stageArchive(root, data)
	}
	target := filepath.Join(root, filepath.FromSlash(hiss.FixturePath(stage.language, name)))
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o600)
}

// measuresRule reports whether any measurement belongs to ruleID.
func measuresRule(measurements []hiss.Measurement, ruleID string) bool {
	for i := 0; i < len(measurements); i++ {
		if measurements[i].RuleID == ruleID {
			return true
		}
	}
	return false
}

// corpusChecker walks FixtureDir and reports every file or directory that belongs to no
// declared rule/language cell or sits outside a valid fixture bucket.
type corpusChecker struct {
	rules    map[string]bool
	cells    map[string]bool
	report   *Report
	dirsLeft int
}

// newCorpusChecker indexes catalog's rules and rule/language cells for the corpus walk.
func newCorpusChecker(catalog *Catalog, report *Report) *corpusChecker {
	c := &corpusChecker{
		rules:    make(map[string]bool, len(catalog.Rules)),
		cells:    make(map[string]bool, len(catalog.Rules)*4),
		report:   report,
		dirsLeft: maxCorpusDirs,
	}
	for i := 0; i < len(catalog.Rules); i++ {
		rule := &catalog.Rules[i]
		c.rules[rule.ID] = true
		for j := 0; j < len(rule.Coverage); j++ {
			c.cells[rule.ID+"/"+rule.Coverage[j].Language] = true
		}
	}
	return c
}

// readDirBounded reads one directory below FixtureDir under the directory and entry bounds.
func (c *corpusChecker) readDirBounded(ctx context.Context, dir string) ([]fs.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("verify fixture corpus: %w", err)
	}
	if c.dirsLeft <= 0 {
		return nil, fmt.Errorf("fixture corpus exceeds %d directories", maxCorpusDirs)
	}
	c.dirsLeft--
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read fixture corpus %s: %w", dir, err)
	}
	if len(entries) > maxCorpusEntries {
		return nil, fmt.Errorf("fixture directory %s exceeds %d entries", dir, maxCorpusEntries)
	}
	return entries, nil
}

// verifyCorpus walks FixtureDir and records a finding for every file or directory that maps to
// no declared rule/language cell or sits outside a replayed fixture bucket.
func verifyCorpus(ctx context.Context, rootDir string, catalog *Catalog, report *Report) error {
	corpusDir := filepath.Join(rootDir, filepath.FromSlash(FixtureDir))
	checker := newCorpusChecker(catalog, report)
	entries, err := checker.readDirBounded(ctx, corpusDir)
	if err != nil {
		if util.DirectoryAbsent(corpusDir, err) {
			return nil
		}
		return err
	}
	for i := 0; i < len(entries) && i < maxCorpusEntries; i++ {
		if err := checker.checkRuleEntry(ctx, corpusDir, entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// checkRuleEntry inspects one top-level entry directly below FixtureDir.
func (c *corpusChecker) checkRuleEntry(ctx context.Context, corpusDir string, entry fs.DirEntry) error {
	ruleID := entry.Name()
	rel := slashpath.Join(FixtureDir, ruleID)
	if !entry.IsDir() {
		c.report.Findings = append(c.report.Findings, Finding{
			Fixture: ruleID, Detail: fmt.Sprintf("unowned fixture %s maps to no declared rule and language cell", rel),
		})
		return nil
	}
	ruleDir := filepath.Join(corpusDir, ruleID)
	entries, err := c.readDirBounded(ctx, ruleDir)
	if err != nil {
		return err
	}
	if len(entries) == 0 && !c.rules[ruleID] {
		c.report.Findings = append(c.report.Findings, Finding{
			Rule: ruleID, Detail: fmt.Sprintf("unowned rule directory %s: %s is not declared in %s", rel, ruleID, CatalogFile),
		})
		return nil
	}
	for i := 0; i < len(entries) && i < maxCorpusEntries; i++ {
		if err := c.checkLanguageEntry(ctx, ruleDir, ruleID, entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// checkLanguageEntry inspects one entry below FixtureDir/<rule>.
func (c *corpusChecker) checkLanguageEntry(ctx context.Context, ruleDir, ruleID string, entry fs.DirEntry) error {
	lang := entry.Name()
	rel := slashpath.Join(FixtureDir, ruleID, lang)
	if !entry.IsDir() {
		c.report.Findings = append(c.report.Findings, Finding{
			Rule: ruleID, Fixture: lang, Detail: fmt.Sprintf("unowned fixture %s maps to no declared rule and language cell", rel),
		})
		return nil
	}
	langDir := filepath.Join(ruleDir, lang)
	if !c.cells[ruleID+"/"+lang] {
		reason := fmt.Sprintf("%s/%s is not declared in %s", ruleID, lang, CatalogFile)
		target := unownedTarget{dir: langDir, rel: rel, rule: ruleID, lang: lang, kind: "language directory", reason: reason}
		return c.reportUnownedSubtree(ctx, target)
	}
	entries, err := c.readDirBounded(ctx, langDir)
	if err != nil {
		return err
	}
	for i := 0; i < len(entries) && i < maxCorpusEntries; i++ {
		if err := c.checkBucketEntry(ctx, langDir, ruleID, lang, entries[i]); err != nil {
			return err
		}
	}
	return nil
}

// isValidBucket reports whether name is one of the four replayed fixture buckets.
func isValidBucket(name string) bool {
	switch name {
	case bucketPositive, bucketNegative, bucketGap, bucketMeasured:
		return true
	default:
		return false
	}
}

// checkBucketEntry inspects one entry below a declared FixtureDir/<rule>/<language> cell.
func (c *corpusChecker) checkBucketEntry(ctx context.Context, langDir, ruleID, lang string, entry fs.DirEntry) error {
	name := entry.Name()
	rel := slashpath.Join(FixtureDir, ruleID, lang, name)
	if !entry.IsDir() {
		c.report.Findings = append(c.report.Findings, Finding{
			Rule: ruleID, Language: lang, Fixture: name, Detail: fmt.Sprintf("unowned fixture %s sits outside a fixture bucket", rel),
		})
		return nil
	}
	bucketDir := filepath.Join(langDir, name)
	if !isValidBucket(name) {
		reason := fmt.Sprintf("bucket %q is not positive, negative, gap or measured", name)
		target := unownedTarget{dir: bucketDir, rel: rel, rule: ruleID, lang: lang, bucket: name, kind: "bucket directory", reason: reason}
		return c.reportUnownedSubtree(ctx, target)
	}
	return c.checkBucketSubdirs(ctx, bucketDir, rel, ruleID, lang, name)
}

// checkBucketSubdirs flags any nested directory inside a valid bucket, since replayBucket reads
// only direct files of the bucket directory.
func (c *corpusChecker) checkBucketSubdirs(ctx context.Context, bucketDir, bucketRel, ruleID, lang, bucket string) error {
	entries, err := c.readDirBounded(ctx, bucketDir)
	if err != nil {
		return err
	}
	for i := 0; i < len(entries) && i < maxCorpusEntries; i++ {
		if !entries[i].IsDir() {
			continue
		}
		sub := entries[i].Name()
		target := unownedTarget{
			dir:    filepath.Join(bucketDir, sub),
			rel:    slashpath.Join(bucketRel, sub),
			rule:   ruleID,
			lang:   lang,
			bucket: bucket,
			kind:   "nested directory",
			reason: "nested directories inside a fixture bucket are not replayed",
		}
		if err := c.reportUnownedSubtree(ctx, target); err != nil {
			return err
		}
	}
	return nil
}

// unownedTarget describes a directory below FixtureDir whose contents belong to no replayed cell.
type unownedTarget struct {
	dir    string
	rel    string
	rule   string
	lang   string
	bucket string
	kind   string
	reason string
}

// walkFrame is one pending directory on reportUnownedSubtree's explicit stack.
type walkFrame struct {
	dir string
	rel string
	sub string
}

// reportUnownedSubtree walks target.dir iteratively without recursion, recording one finding per
// file inside it, or one finding for target.rel itself when the subtree holds no files.
func (c *corpusChecker) reportUnownedSubtree(ctx context.Context, target unownedTarget) error {
	stack := []walkFrame{{dir: target.dir, rel: target.rel}}
	files := 0
	for step := 0; len(stack) > 0 && step < maxCorpusDirs; step++ {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := c.readDirBounded(ctx, cur.dir)
		if err != nil {
			return err
		}
		for i := 0; i < len(entries) && i < maxCorpusEntries; i++ {
			entryRel := slashpath.Join(cur.rel, entries[i].Name())
			entrySub := slashJoinNonEmpty(cur.sub, entries[i].Name())
			if entries[i].IsDir() {
				stack = append(stack, walkFrame{dir: filepath.Join(cur.dir, entries[i].Name()), rel: entryRel, sub: entrySub})
				continue
			}
			files++
			c.report.Findings = append(c.report.Findings, target.fileFinding(entryRel, entrySub))
		}
	}
	if files == 0 {
		detail := fmt.Sprintf("unowned %s %s: %s", target.kind, target.rel, target.reason)
		c.report.Findings = append(c.report.Findings, Finding{
			Rule: target.rule, Language: target.lang, Bucket: target.bucket, Detail: detail,
		})
	}
	return nil
}

// fileFinding builds the Finding for one unowned file at entryRel (entrySub below target.rel).
func (t unownedTarget) fileFinding(entryRel, entrySub string) Finding {
	bucket, fixture := t.bucket, entrySub
	if bucket == "" {
		if head, rest, ok := strings.Cut(entrySub, "/"); ok {
			bucket, fixture = head, rest
		}
	}
	detail := fmt.Sprintf("unowned fixture %s: %s", entryRel, t.reason)
	return Finding{Rule: t.rule, Language: t.lang, Bucket: bucket, Fixture: fixture, Detail: detail}
}
