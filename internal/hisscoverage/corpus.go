package hisscoverage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/cordanaLLM/praetor/internal/contextopt"
	"github.com/cordanaLLM/praetor/internal/util"
)

// corpusSnapshot owns the captured buckets for each catalog claim in one Verify run.
type corpusSnapshot map[fixtureStage]claimSnapshot

// claimSnapshot indexes a rule and language's captured buckets by catalog bucket name.
type claimSnapshot map[string]bucketSnapshot

// bucketSnapshot retains the captured fixture bytes and findings about the same listing.
type bucketSnapshot struct {
	stage    fixtureStage
	files    []capturedFixture
	findings []Finding
}

// capturedFixture holds the listed name and the bytes that replay stages under that name.
type capturedFixture struct {
	name string
	data []byte
}

// openCorpusSnapshot pins the corpus once, captures the catalog's buckets, then closes all
// handles before replay. Further consumers, including ownership checks, share this snapshot.
func openCorpusSnapshot(ctx context.Context, rootDir string, catalog *Catalog) (_ corpusSnapshot, err error) {
	corpus := make(corpusSnapshot)
	root, err := contextopt.OpenDirectoryIn(ctx, rootDir, filepath.FromSlash(FixtureDir))
	if err != nil {
		if util.DirectoryAbsent(filepath.Join(rootDir, filepath.FromSlash(FixtureDir)), err) {
			return corpus, nil
		}
		return nil, fmt.Errorf("open fixture corpus: %w", err)
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	for i := 0; i < len(catalog.Rules); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := corpus.captureRule(ctx, root, &catalog.Rules[i]); err != nil {
			return nil, err
		}
	}
	return corpus, nil
}

// captureRule reads a catalog rule through its directory in the pinned corpus.
func (corpus corpusSnapshot) captureRule(ctx context.Context, root *os.Root, rule *Rule) (err error) {
	dir, err := contextopt.OpenChildDirectory(ctx, root, rule.ID)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open fixture rule %s: %w", rule.ID, err)
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for i := 0; i < len(rule.Coverage); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		stage := fixtureStage{ruleID: rule.ID, language: rule.Coverage[i].Language}
		claim, err := stage.captureClaim(ctx, dir)
		if err != nil {
			return err
		}
		corpus[stage] = claim
	}
	return nil
}

// captureClaim captures each bucket relative to the pinned language directory.
func (stage fixtureStage) captureClaim(ctx context.Context, rule *os.Root) (_ claimSnapshot, err error) {
	dir, err := contextopt.OpenChildDirectory(ctx, rule, stage.language)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, escapedError{fmt.Errorf("open fixture language %s: %w", stage.language, err)}
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	names := [...]string{bucketMeasured, bucketPositive, bucketNegative, bucketGap}
	claim := make(claimSnapshot, len(names))
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bucket, err := stage.captureBucket(ctx, dir, name)
		if err != nil {
			return nil, err
		}
		claim[name] = bucket
	}
	return claim, nil
}

// captureBucket pins one bucket for both its bounded listing and its regular file reads.
func (stage fixtureStage) captureBucket(ctx context.Context, parent *os.Root, name string) (bucket bucketSnapshot, err error) {
	bucket.stage = stage
	dir, err := contextopt.OpenChildDirectory(ctx, parent, name)
	if errors.Is(err, os.ErrNotExist) {
		return bucket, nil
	}
	if err != nil {
		return bucket, fmt.Errorf("open fixture bucket %s: %w", name, err)
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	entries, err := readBucketEntries(ctx, dir)
	if err != nil {
		return bucket, err
	}
	var report Report
	for i := 0; i < len(entries) && i < maxBucketEntries; i++ {
		if err := ctx.Err(); err != nil {
			return bucket, err
		}
		stop, err := bucket.captureEntry(ctx, dir, name, entries[i], &report)
		if err != nil {
			return bucket, err
		}
		if stop {
			bucket.findings = report.Findings
			return bucket, nil
		}
	}
	if len(entries) > maxBucketEntries {
		recordIncompleteBucket(&report, stage.ruleID, stage.language, name,
			entries[maxBucketEntries].Name(), maxBucketEntries, "directory entries")
	}
	bucket.findings = report.Findings
	return bucket, nil
}

// captureEntry classifies a listed entry and captures bounded text for a regular fixture.
func (b *bucketSnapshot) captureEntry(
	ctx context.Context, dir *os.Root, bucket string, entry os.DirEntry, report *Report,
) (bool, error) {
	name := entry.Name()
	rule, lang := b.stage.ruleID, b.stage.language
	class, listed, err := classifyBucketEntry(ctx, dir, entry)
	if err != nil {
		return false, err
	}
	switch class {
	case entryDirectory:
		return false, nil
	case entryNonRegular:
		recordNonRegularEntry(report, rule, lang, bucket, name)
		return false, nil
	case entryChanged:
		recordChangedBucket(report, rule, lang, bucket, name)
		return true, nil
	}
	if len(b.files) >= maxFixturesPerBucket {
		recordIncompleteBucket(report, rule, lang, bucket, name, maxFixturesPerBucket, "regular files")
		return true, nil
	}
	bounded, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	data, err := contextopt.ReadListedSnapshot(bounded, dir, name, listed)
	if errors.Is(err, contextopt.ErrSourceNotRegular) || errors.Is(err, os.ErrNotExist) {
		recordChangedBucket(report, rule, lang, bucket, name)
		return true, nil
	}
	if err != nil {
		return false, escapedError{fmt.Errorf("read fixture %s: %w", name, err)}
	}
	b.files = append(b.files, capturedFixture{name: name, data: data})
	return false, nil
}

// snapshotReadyKey carries a test callback run after all capture handles close and before replay.
type snapshotReadyKey struct{}

// bucketReaderKey carries a test observer of a bucket's single bounded listing.
type bucketReaderKey struct{}

// bucketEntryObserver may alter the test tree or the entries returned by the pinned reader.
type bucketEntryObserver func(dir string, entries []os.DirEntry) []os.DirEntry

// readBucketEntries reads up to maxBucketEntries plus one overflow sentinel through dir.
func readBucketEntries(ctx context.Context, dir *os.Root) (_ []os.DirEntry, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listing, err := dir.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open fixture listing %s: %w", dir.Name(), err)
	}
	defer func() { err = errors.Join(err, listing.Close()) }()
	entries, err := listing.ReadDir(maxBucketEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("list fixture bucket %s: %w", dir.Name(), err)
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Name() < entries[b].Name() })
	if observe, ok := ctx.Value(bucketReaderKey{}).(bucketEntryObserver); ok {
		entries = observe(dir.Name(), entries)
	}
	return entries, nil
}

// entryClass describes a bucket entry's observed kind or a change since listing.
type entryClass uint8

const (
	entryDirectory entryClass = iota
	entryRegularFile
	entryNonRegular
	entryChanged
)

// classifyBucketEntry inspects zero and unknown type bits with the bucket's rooted Lstat.
func classifyBucketEntry(ctx context.Context, dir *os.Root, entry os.DirEntry) (entryClass, os.FileInfo, error) {
	if entry.IsDir() {
		return entryDirectory, nil, nil
	}
	typ := entry.Type() & fs.ModeType
	if typ != 0 && typ != fs.ModeIrregular {
		return entryNonRegular, nil, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}
	info, err := dir.Lstat(entry.Name())
	if errors.Is(err, os.ErrNotExist) {
		return entryChanged, nil, nil
	}
	if err != nil {
		return 0, nil, escapedError{fmt.Errorf("stat fixture %s: %w", entry.Name(), err)}
	}
	return modeClass(typ, info.Mode()), info, nil
}

// modeClass classifies the observed mode, detecting when a listed regular file changed kind.
func modeClass(listedType, mode os.FileMode) entryClass {
	if mode.IsRegular() {
		return entryRegularFile
	}
	if listedType.IsRegular() {
		return entryChanged
	}
	if mode.IsDir() {
		return entryDirectory
	}
	return entryNonRegular
}
