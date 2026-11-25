package hisscoverage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/hiss"
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
	// maxFixturesPerBucket bounds the regular files replayed in one positive, negative, gap or
	// measured directory (HISS-02). A regular file past it makes the replay incomplete.
	maxFixturesPerBucket = 256
	// maxFixtureMarkerLines bounds the leading comment lines inspected for a hiss-fixture marker (HISS-02).
	maxFixtureMarkerLines = 32
	// fixtureMarkerPrefix introduces an intentional gap marker inside a leading fixture comment.
	fixtureMarkerPrefix = "hiss-fixture:"
	// maxBucketEntries is the largest bucket listing replay can certify (HISS-02).
	// The reader requests one extra entry to detect overflow.
	maxBucketEntries = 4096
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

// hexDigits formats invalid UTF-8 bytes as lowercase \xNN sequences in escapeControl.
const hexDigits = "0123456789abcdef"

// String renders a finding for a terminal report with control characters escaped.
func (f Finding) String() string {
	return fmt.Sprintf("%s/%s %s/%s: %s",
		escapeControl(f.Rule), escapeControl(f.Language), escapeControl(f.Bucket),
		escapeControl(f.Fixture), escapeControl(f.Detail))
}

// escapeControl renders non-printable runes and invalid UTF-8 bytes with Go
// backslash escapes while leaving printable text unchanged.
func escapeControl(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, isNonPrint) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	pos := 0
	for step := 0; step < len(s) && pos < len(s); step++ {
		r, width := utf8.DecodeRuneInString(s[pos:])
		appendEscapedRune(&b, r, width, s[pos])
		pos += width
	}
	return b.String()
}

// isNonPrint reports whether r is non-printable in terminal output.
func isNonPrint(r rune) bool {
	return !strconv.IsPrint(r)
}

// appendEscapedRune writes one decoded rune or invalid UTF-8 byte with controls escaped.
func appendEscapedRune(b *strings.Builder, r rune, width int, raw byte) {
	if r == utf8.RuneError && width == 1 {
		b.WriteString(`\x`)
		b.WriteByte(hexDigits[raw>>4])
		b.WriteByte(hexDigits[raw&0x0f])
		return
	}
	if !strconv.IsPrint(r) {
		quoted := strconv.QuoteRune(r)
		b.WriteString(quoted[1 : len(quoted)-1])
		return
	}
	b.WriteRune(r)
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

// Verify replays the fixture corpus and reports every claim the corpus contradicts or leaves
// incompletely replayed.
//
// The check runs in both directions. A state claiming detection must report each of its
// positive fixtures, and a state claiming none must leave its gap fixtures undetected. The
// second direction is what stops the catalog from quietly becoming pessimistic: when a rule
// gains coverage, the gap fixture it was supposed to miss now fires and the catalog must be
// updated to say so. An incomplete (unparsed or truncated) or zero-file fixture scan never
// certifies a negative, gap, measured, positive or delegated claim.
// Each bucket replays up to maxFixturesPerBucket (256) regular files;
// nested directories are skipped without being entered or consuming that bound, non-regular
// entries (such as symlinks or devices) are skipped and reported as findings, and a bucket
// past the regular-file or directory-entry bound records an incomplete-replay finding so the
// report fails. The verdict covers the bytes captured through one pinned corpus root before
// replay. A later change to the fixture tree is outside this snapshot and shows on the next run.
// Across all buckets the snapshot retains at most 1 MiB of fixture backing arrays.
// Additional bytes spill to a private file. Capture and replay each handle one active
// fixture of at most 1 MiB of text in addition to the retained budget. The pinned Go
// version uses up to 32 KiB of copy scratch during capture.
func Verify(ctx context.Context, rootDir string, catalog *Catalog) (_ *Report, err error) {
	if ctx == nil {
		return nil, errors.New("hisscoverage: verify requires a context")
	}
	if err := catalog.Validate(); err != nil {
		return nil, err
	}
	var store fixtureStore
	defer func() { err = errors.Join(err, store.close()) }()
	corpus, err := store.openCorpusSnapshot(ctx, rootDir, catalog)
	if err != nil {
		return nil, err
	}
	if after, ok := ctx.Value(snapshotReadyKey{}).(func()); ok {
		after()
	}
	report := &Report{}
	for i := 0; i < len(catalog.Rules); i++ {
		rule := &catalog.Rules[i]
		for j := 0; j < len(rule.Coverage); j++ {
			cov := &rule.Coverage[j]
			claim := corpus[fixtureStage{ruleID: rule.ID, language: cov.Language}]
			if err := verifyClaim(ctx, claim, rule.ID, cov, report); err != nil {
				return nil, err
			}
		}
	}
	sort.Slice(report.Findings, func(a, b int) bool {
		return report.Findings[a].String() < report.Findings[b].String()
	})
	return report, nil
}

// verifyClaim replays one rule/language claim against its fixture buckets.
func verifyClaim(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	report.Claims++
	if err := verifyMeasured(ctx, claim, ruleID, cov, report); err != nil {
		return err
	}
	if !cov.ReplayedHere() {
		return verifyDelegatedClaim(ctx, claim, ruleID, cov, report)
	}
	if err := verifyPositiveBucket(ctx, claim, ruleID, cov, report); err != nil {
		return err
	}
	if err := verifyNegativeBucket(ctx, claim, ruleID, cov, report); err != nil {
		return err
	}
	return verifyGapBucket(ctx, claim, ruleID, cov, report)
}

// verifyPositiveBucket replays the positive bucket of a HISS-replayed claim.
func verifyPositiveBucket(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	positives, err := replayBucket(ctx, claim[bucketPositive], report)
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
func verifyNegativeBucket(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	negatives, err := replayBucket(ctx, claim[bucketNegative], report)
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
func verifyGapBucket(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	gaps, err := replayBucket(ctx, claim[bucketGap], report)
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
func verifyMeasured(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	results, err := replayBucket(ctx, claim[bucketMeasured], report)
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
func verifyDelegatedClaim(ctx context.Context, claim claimSnapshot, ruleID string, cov *Coverage, report *Report) error {
	note := fmt.Sprintf("%s/%s is decided by %s, not replayed here", ruleID, cov.Language, cov.Runner)
	if !scannerLanguages[cov.Language] {
		note += fmt.Sprintf(" (no HISS scanner reads %s)", cov.Language)
	}
	report.Delegated = append(report.Delegated, note)
	buckets := [...]string{bucketPositive, bucketNegative, bucketGap}
	for i := 0; i < len(buckets); i++ {
		results, err := replayBucket(ctx, claim[buckets[i]], report)
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
				fmt.Sprintf("%s/%s %s/%s: intentionally %s (%s)",
					escapeControl(ruleID), escapeControl(lang), escapeControl(bucket),
					escapeControl(r.name), escapeControl(string(r.marked)), escapeControl(r.markedReason)))
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

// replayBucket stages and scans the regular fixture bytes captured in one bucket snapshot.
// Findings about its listing and the replayed bytes come from the same capture. Changes to
// the fixture tree after capture are visible on the next Verify run.
func replayBucket(ctx context.Context, bucket bucketSnapshot, report *Report) ([]fixtureResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	report.Findings = append(report.Findings, bucket.findings...)
	results := make([]fixtureResult, 0, len(bucket.files))
	for i := 0; i < len(bucket.files); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		file := bucket.files[i]
		data, err := bucket.store.load(ctx, file)
		if err != nil {
			return nil, err
		}
		result, err := bucket.stage.reported(ctx, file.name, data)
		if err != nil {
			return nil, err
		}
		results = append(results, result)
		report.Fixtures++
	}
	return results, nil
}

// escapedError renders the full diagnostic safely while retaining its error chain.
type escapedError struct{ cause error }

// Error escapes control characters in both the fixture context and the underlying error.
func (e escapedError) Error() string { return escapeControl(e.cause.Error()) }

// Unwrap exposes the original diagnostic for errors.Is and errors.As.
func (e escapedError) Unwrap() error { return e.cause }

// recordIncompleteBucket records a non-certifying finding when a fixture bucket exceeds its
// regular-file or directory-entry bound before every entry has been replayed.
func recordIncompleteBucket(report *Report, ruleID, lang, bucket, fixture string, bound int, kind string) {
	report.Findings = append(report.Findings, Finding{
		Rule:     ruleID,
		Language: lang,
		Bucket:   bucket,
		Fixture:  fixture,
		Detail: fmt.Sprintf(
			"incomplete replay: bucket %s/%s/%s exceeds %d %s; report is non-certifying",
			ruleID, lang, bucket, bound, kind),
	})
}

// recordChangedBucket names a listed regular file that disappeared or changed kind before capture.
func recordChangedBucket(report *Report, ruleID, lang, bucket, fixture string) {
	report.Findings = append(report.Findings, Finding{
		Rule:     ruleID,
		Language: lang,
		Bucket:   bucket,
		Fixture:  fixture,
		Detail: fmt.Sprintf(
			"incomplete replay: bucket %s/%s/%s changed during verification; report is non-certifying",
			ruleID, lang, bucket),
	})
}

// recordNonRegularEntry records a finding for a bucket entry that is neither a directory
// nor a regular fixture file, such as a symbolic link or device node.
func recordNonRegularEntry(report *Report, ruleID, lang, bucket, fixture string) {
	report.Findings = append(report.Findings, Finding{
		Rule:     ruleID,
		Language: lang,
		Bucket:   bucket,
		Fixture:  fixture,
		Detail:   fmt.Sprintf("entry %s is not a regular fixture file; skipped without replay", fixture),
	})
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
func (stage fixtureStage) reported(ctx context.Context, name string, data []byte) (result fixtureResult, err error) {
	result.name = name
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
