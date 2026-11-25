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
	store    *fixtureStore
	files    []capturedFixture
	findings []Finding
}

// openCorpusSnapshot pins the corpus once, captures the catalog's buckets, then closes all
// source directory handles before replay. Further consumers, including ownership checks, share this snapshot.
func (store *fixtureStore) openCorpusSnapshot(ctx context.Context, rootDir string, catalog *Catalog) (_ corpusSnapshot, err error) {
	corpus := make(corpusSnapshot)
	root, err := contextopt.OpenSnapshotDirectoryIn(ctx, rootDir, filepath.FromSlash(FixtureDir))
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
		if err := corpus.captureRule(ctx, root, &catalog.Rules[i], store); err != nil {
			return nil, err
		}
	}
	return corpus, nil
}

// captureRule reads a catalog rule through its directory in the pinned corpus.
func (corpus corpusSnapshot) captureRule(ctx context.Context, root *contextopt.SnapshotDirectory, rule *Rule, store *fixtureStore) (err error) {
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
		claim, err := stage.captureClaim(ctx, dir, store)
		if err != nil {
			return err
		}
		corpus[stage] = claim
	}
	return nil
}

// captureClaim captures each bucket relative to the pinned language directory.
func (stage fixtureStage) captureClaim(ctx context.Context, rule *contextopt.SnapshotDirectory, store *fixtureStore) (_ claimSnapshot, err error) {
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
		bucket, err := stage.captureBucket(ctx, dir, name, store)
		if err != nil {
			return nil, err
		}
		claim[name] = bucket
	}
	return claim, nil
}

// captureBucket pins one bucket for both its bounded listing and its regular file reads.
func (stage fixtureStage) captureBucket(ctx context.Context, parent *contextopt.SnapshotDirectory, name string, store *fixtureStore) (bucket bucketSnapshot, err error) {
	bucket.stage, bucket.store = stage, store
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
	ctx context.Context, dir *contextopt.SnapshotDirectory, bucket string, entry os.DirEntry, report *Report,
) (bool, error) {
	name := entry.Name()
	rule, lang := b.stage.ruleID, b.stage.language
	class, listed, err := classifyBucketEntry(ctx, entry)
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
	return b.captureFile(ctx, dir, bucket, name, listed, report)
}

// captureFile saves one stable regular file or records a change since listing.
func (b *bucketSnapshot) captureFile(
	ctx context.Context, dir *contextopt.SnapshotDirectory, bucket, name string, listed os.FileInfo, report *Report,
) (bool, error) {
	bounded, cancel := context.WithTimeout(ctx, contextopt.MaxDuration)
	defer cancel()
	data, err := dir.ReadListedSnapshot(bounded, name, listed)
	if errors.Is(err, contextopt.ErrSourceNotRegular) || errors.Is(err, os.ErrNotExist) {
		recordChangedBucket(report, b.stage.ruleID, b.stage.language, bucket, name)
		return true, nil
	}
	if err != nil {
		return false, escapedError{fmt.Errorf("read fixture %s: %w", name, err)}
	}
	file, err := b.store.save(bounded, name, data)
	if err != nil {
		return false, err
	}
	b.files = append(b.files, file)
	return false, nil
}

// snapshotReadyKey carries a test callback run after all capture handles close and before replay.
type snapshotReadyKey struct{}

// bucketReaderKey carries a test observer of a bucket's single bounded listing.
type bucketReaderKey struct{}

// bucketEntryObserver may alter the test tree or the entries returned by the pinned reader.
type bucketEntryObserver func(dir string, entries []os.DirEntry) []os.DirEntry

// readBucketEntries reads up to maxBucketEntries plus one overflow sentinel through dir.
func readBucketEntries(ctx context.Context, dir *contextopt.SnapshotDirectory) ([]os.DirEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	next := func(n int) ([]os.DirEntry, error) { return dir.ReadEntries(ctx, n) }
	if stub, ok := ctx.Value(bucketReaderKey{}).(func(string, int) ([]os.DirEntry, error)); ok {
		next = func(n int) ([]os.DirEntry, error) { return stub(dir.Name(), n) }
	}
	entries, err := collectBucketEntries(ctx, next)
	if err != nil {
		return nil, fmt.Errorf("list fixture bucket %s: %w", dir.Name(), err)
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].Name() < entries[b].Name() })
	if observe, ok := ctx.Value(bucketReaderKey{}).(bucketEntryObserver); ok {
		entries = observe(dir.Name(), entries)
	}
	return entries, nil
}

// collectBucketEntries consumes a single directory cursor through EOF or the overflow entry.
// Every successful nonterminal read advances by at least one entry, bounding calls at 4097.
func collectBucketEntries(ctx context.Context, next func(int) ([]os.DirEntry, error)) ([]os.DirEntry, error) {
	const limit = maxBucketEntries + 1
	var entries []os.DirEntry
	for reads := 0; reads < limit; reads++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chunk, err := next(limit - len(entries))
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		entries = append(entries, chunk...)
		if len(entries) == limit || errors.Is(err, io.EOF) {
			return entries, nil
		}
		if len(chunk) == 0 {
			return nil, io.ErrNoProgress
		}
	}
	return nil, io.ErrNoProgress
}

// entryClass describes a bucket entry's observed kind or a change since listing.
type entryClass uint8

const (
	entryDirectory entryClass = iota
	entryRegularFile
	entryNonRegular
	entryChanged
)

// classifyBucketEntry inspects zero and unknown type bits with the descriptor-relative metadata saved by the listing.
func classifyBucketEntry(ctx context.Context, entry os.DirEntry) (entryClass, os.FileInfo, error) {
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
	info, err := entry.Info()
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
