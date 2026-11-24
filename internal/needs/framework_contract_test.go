package needs

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/cordanaLLM/praetor/internal/contextopt"
)

const contractFrameworkModule = "example.com/fw"

const validContract = `version: 1
framework: example.com/fw
modules:
  - example.com/fw/core
packages:
  - import: example.com/fw/core/id
    module: example.com/fw/core
    domain: id
    capabilities: [id.uuid]
    replaces: [github.com/google/uuid]
  - import: example.com/fw/otel
    domain: otel
    capabilities: [telemetry.otel]
    replaces: [go.opentelemetry.io/otel]
  - import: example.com/fw/db/sqlite
    domain: db
    capabilities: [db.sqlite]
    replaces: [github.com/acme/kv/v2]
  - import: example.com/fw/httpx/client
    domain: httpx
    capabilities: [http.client]
    replaces: [go.opentelemetry.io/otel, github.com/acme/kv/v2]
`

// setupContractCheckout writes a framework checkout that publishes a capability contract:
// a root module with an otel adapter, a nested core module with an id package, and a db
// package whose contract replaces a versioned third-party module.
func setupContractCheckout(t *testing.T, contract string) string {
	t.Helper()
	root := setupFrameworkCheckout(t, contractFrameworkModule, "core/id", "otel", "db/sqlite", "httpx/client")
	writeFixture(t, root, "core/go.mod", "module "+contractFrameworkModule+"/core\n\ngo 1.27\n")
	writeFixture(t, root, "core/id/id.go", "package id\n\nfunc New() string { return \"id\" }\n")
	writeFixture(t, root, "otel/otel.go", "package otel\n\ntype Provider struct{}\n")
	writeFixture(t, root, "db/sqlite/sqlite.go", "package sqlite\n\nconst Driver = \"sqlite\"\n")
	writeFixture(t, root, "httpx/client/client.go", "package client\n\ntype Client struct{}\n")
	writeFixture(t, root, FrameworkContractFile, contract)
	return root
}

// setupContractConsumer writes a consumer that imports two catalog-known libraries, the
// framework's root and nested modules, a versioned module only the contract knows, and
// one library nothing covers.
func setupContractConsumer(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	requires := []string{
		"github.com/google/uuid v1.6.0",
		"go.opentelemetry.io/otel v1.30.0",
		contractFrameworkModule + " v0.10.0",
		contractFrameworkModule + "/core v0.9.0",
		"github.com/acme/kv/v3 v3.1.0",
		"github.com/unknown/gap-lib v1.0.0",
	}
	writeFixture(t, repo, "go.mod", "module example.com/consumer\n\ngo 1.27\n\nrequire (\n\t"+strings.Join(requires, "\n\t")+"\n)\n")
	imports := []string{
		"github.com/google/uuid",
		"go.opentelemetry.io/otel",
		contractFrameworkModule + "/grpc",
		contractFrameworkModule + "/core/config",
		"github.com/acme/kv/v3",
		"github.com/unknown/gap-lib",
	}
	writeFixture(t, repo, "main.go", "package main\n\nimport (\n\t_ \""+strings.Join(imports, "\"\n\t_ \"")+"\"\n)\n\nfunc main() {}\n")
	return repo
}

func demandFor(t *testing.T, report *RepoNeeds, pkg string) DependencyDemand {
	t.Helper()
	for _, dep := range report.Dependencies {
		if dep.Package == pkg {
			return dep
		}
	}
	t.Fatalf("dependency %s missing from %+v", pkg, report.Dependencies)
	return DependencyDemand{}
}

func assertDemand(t *testing.T, dep DependencyDemand, status CapabilityStatus, replacement string, capability CapabilityKey) {
	t.Helper()
	if dep.Status != status || dep.FrameworkReplacement != replacement {
		t.Errorf("%s: got status=%s replacement=%q, want %s %q", dep.Package, dep.Status, dep.FrameworkReplacement, status, replacement)
	}
	if capability != "" && dep.Capability != capability {
		t.Errorf("%s: got capability %s, want %s", dep.Package, dep.Capability, capability)
	}
}

// TestFrameworkContractObservesDeclaredPackagesAndReplacements proves declared packages, replacements and an
// ambiguous claim resolve as the contract states.
func TestFrameworkContractObservesDeclaredPackagesAndReplacements(t *testing.T) {
	root := setupContractCheckout(t, validContract)
	index, err := InspectFramework(t.Context(), acmeSource(root))
	if err != nil {
		t.Fatal(err)
	}
	if index.Contract != FrameworkContractFile || index.Basis != FrameworkSourceObserved || index.Name != contractFrameworkModule {
		t.Fatalf("contract index must stay source-observed under the checkout module: %+v", index)
	}
	id := index.Packages[contractFrameworkModule+"/core/id"]
	if id.Module != contractFrameworkModule+"/core" || !index.ProvidesCapability("id.uuid") {
		t.Fatalf("a package in a declared nested module must be observed: %+v", id)
	}
	if got := index.Replacements["github.com/acme/kv"]; len(got) != 2 || got[0] != contractFrameworkModule+"/db/sqlite" {
		t.Fatalf("replaces must be recorded without the major suffix, claimants in import order: %q", got)
	}
	report, err := ScanRepoWithFramework(t.Context(), setupContractConsumer(t), index, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertDemand(t, demandFor(t, report, "github.com/google/uuid"), StatusCovered, contractFrameworkModule+"/core/id", "id.uuid")
	// httpx/client sorts first among otel's claimants; the claimant declaring the
	// demanded capability must still win.
	assertDemand(t, demandFor(t, report, "go.opentelemetry.io/otel"), StatusCovered, contractFrameworkModule+"/otel", "telemetry.otel")
	ambiguous := demandFor(t, report, "github.com/acme/kv/v3")
	original := buildGoDemand(ambiguous.Package, ambiguous.Version)
	assertDemand(t, ambiguous, StatusGap, "", original.Capability)
	want := "ambiguous claimants for " + string(original.Capability) +
		": example.com/fw/db/sqlite, example.com/fw/httpx/client"
	if !strings.Contains(FormatLibraryRelationships(report), want) {
		t.Errorf("relationship report missing %q", want)
	}
	assertDemand(t, demandFor(t, report, contractFrameworkModule), StatusNative, "", FrameworkNativeCapability)
	assertDemand(t, demandFor(t, report, contractFrameworkModule+"/core"), StatusNative, "", FrameworkNativeCapability)
	gap := demandFor(t, report, "github.com/unknown/gap-lib")
	assertDemand(t, gap, StatusGap, "", "")
	if !strings.HasPrefix(string(gap.Capability), "custom.") {
		t.Fatalf("an unmapped library keeps its custom capability: %+v", gap)
	}
	if report.Readiness.CoveredDeps != 4 || report.Readiness.GapDeps != 2 || report.Readiness.Basis != FrameworkSourceObserved {
		t.Fatalf("four of six demands map: %+v", report.Readiness)
	}
}

const (
	claimantDependency = "example.com/third-party"
	claimantCapability = CapabilityKey("http.client")
	claimantOther      = CapabilityKey("db.sqlite")
	claimantA          = contractFrameworkModule + "/a"
	claimantB          = contractFrameworkModule + "/b"
	claimantC          = contractFrameworkModule + "/c"
	claimantD          = contractFrameworkModule + "/d"
)

type contractClaimantRole struct {
	name   string
	claims map[string][]string
	status CapabilityStatus
	kind   LibraryRelationshipKind
}

// TestFrameworkContractClaimantSelection proves exact, single and ambiguous claimant selection for every role and
// that permuting the claimant order never changes the result.
func TestFrameworkContractClaimantSelection(t *testing.T) {
	index := FrameworkIndex{
		Name: contractFrameworkModule, Basis: FrameworkSourceObserved,
		Packages: map[string]FrameworkPackage{
			claimantA: {Capabilities: []CapabilityKey{claimantOther}},
			claimantB: {Capabilities: []CapabilityKey{claimantOther}},
			claimantC: {Capabilities: []CapabilityKey{claimantCapability}},
			claimantD: {Capabilities: []CapabilityKey{claimantCapability}},
		},
		Capabilities: map[CapabilityKey][]string{claimantCapability: {claimantC, claimantD}},
	}
	beginContractIndex(&index, &frameworkContract{}, FrameworkContractFile)
	for _, role := range [...]contractClaimantRole{
		{"replaces", index.Replacements, StatusCovered, ""},
		{"adapts", index.Adaptations, StatusAdapterAvailable, ""},
		{"wrapped-by", index.Wrappers, StatusCovered, RelationshipWrappedBy},
		{"tooling", index.Tooling, StatusCovered, RelationshipTooling},
	} {
		t.Run(role.name, func(t *testing.T) {
			checkContractClaimantCases(t, &index, role)
			delete(role.claims, claimantDependency)
		})
	}
}

// checkContractClaimantCases runs the claimant cases of one contract role against the index.
func checkContractClaimantCases(t *testing.T, index *FrameworkIndex, role contractClaimantRole) {
	t.Helper()
	for _, tc := range [...]struct {
		name       string
		claimants  []string
		winner     string
		capability CapabilityKey
	}{
		{"no exact match", []string{claimantB, claimantA}, "", claimantCapability},
		{"exact match", []string{claimantA, claimantC, claimantB}, claimantC, claimantCapability},
		{"tied exact matches", []string{claimantD, claimantA, claimantC}, claimantC, claimantCapability},
		{"sole claimant", []string{claimantB}, claimantB, claimantOther},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original := DependencyDemand{Package: claimantDependency, Capability: claimantCapability, Status: StatusGap}
			role.claims[claimantDependency] = slices.Clone(tc.claimants)
			forward := original
			reconcileDependency(index, &forward)
			if !slices.Equal(role.claims[claimantDependency], tc.claimants) {
				t.Fatal("reconciliation changed the claimant order in the index")
			}
			slices.Reverse(role.claims[claimantDependency])
			backward := original
			reconcileDependency(index, &backward)
			if !reflect.DeepEqual(forward, backward) {
				t.Errorf("claimant permutation changed the demand: %+v vs %+v", forward, backward)
			}
			checkContractClaimantOutcome(t, forward, role, tc.winner, tc.capability)
		})
	}
}

// checkContractClaimantOutcome asserts the status, package and notes one resolved demand carries.
func checkContractClaimantOutcome(t *testing.T, got DependencyDemand, role contractClaimantRole, winner string, capability CapabilityKey) {
	t.Helper()
	status, replacement := role.status, winner
	if winner == "" {
		status = StatusGap
		wantNote := "capabilities.yaml: ambiguous claimants for http.client: example.com/fw/a, example.com/fw/b"
		if got.Notes != wantNote {
			t.Errorf("ambiguity note = %q, want %q", got.Notes, wantNote)
		}
	}
	var relationship *LibraryRelationship
	if role.kind != "" {
		replacement = ""
		relationship = &LibraryRelationship{Kind: role.kind, FrameworkPackage: winner, Basis: FrameworkSourceObserved}
	}
	assertDemand(t, got, status, replacement, capability)
	if !reflect.DeepEqual(got.Relationship, relationship) {
		t.Errorf("relationship = %+v, want %+v", got.Relationship, relationship)
	}
}

// TestSelectedFrameworkUsesClassifiedCapability checks claimant selection with and without a configured Go contract.
func TestSelectedFrameworkUsesClassifiedCapability(t *testing.T) {
	configured := writeFixture(t, t.TempDir(), FrameworkContractFile, uuidClaimantContract(claimantCapability))
	registry, err := LoadRegistry(t.Context(), Targets{"go": {Contract: configured}})
	if err != nil {
		t.Fatal(err)
	}
	repo := setupContractConsumer(t)
	for _, tc := range [...]struct {
		name   string
		keys   []CapabilityKey
		status CapabilityStatus
		winner string
	}{
		{"exact", []CapabilityKey{"id.uuid", claimantOther}, StatusCovered, claimantA},
		{"ambiguous", []CapabilityKey{claimantOther, claimantCapability}, StatusGap, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			index := inspectClaimantContract(t, uuidClaimantContract(tc.keys...))
			for _, r := range [...]*AnalyzerRegistry{registry, nil} {
				report, err := ScanRepoWithFramework(t.Context(), repo, index, r)
				if err != nil {
					t.Fatal(err)
				}
				got := demandFor(t, report, "github.com/google/uuid")
				assertDemand(t, got, tc.status, tc.winner, "id.uuid")
				if tc.winner == "" && !strings.Contains(got.Notes, "ambiguous claimants for id.uuid: "+claimantA+", "+claimantB) {
					t.Errorf("ambiguity note = %q", got.Notes)
				}
			}
		})
	}
	plain, err := ScanRepo(t.Context(), repo, registry)
	if err != nil {
		t.Fatal(err)
	}
	assertDemand(t, demandFor(t, plain, "github.com/google/uuid"), StatusCovered, claimantA, claimantCapability)
}

// uuidClaimantContract declares one claimant per capability, each replacing the UUID module.
func uuidClaimantContract(keys ...CapabilityKey) string {
	var contract strings.Builder
	contract.WriteString("version: 1\nframework: " + contractFrameworkModule + "\npackages:\n")
	for i, key := range keys {
		writef(&contract, "  - import: %s/%c\n    capabilities: [%s]\n    replaces: [github.com/google/uuid]\n", contractFrameworkModule, 'a'+i, key)
	}
	return contract.String()
}

// inspectClaimantContract validates and indexes a declared framework contract.
func inspectClaimantContract(t *testing.T, contract string) *FrameworkIndex {
	t.Helper()
	path := writeFixture(t, t.TempDir(), FrameworkContractFile, contract)
	index, err := InspectFramework(t.Context(), FrameworkSource{Contract: path})
	if err != nil {
		t.Fatal(err)
	}
	return index
}

// TestAmbiguousClaimantsManifestRoundTrip exercises 128 claimants across 64 Go demands.
func TestAmbiguousClaimantsManifestRoundTrip(t *testing.T) {
	const claimantCount = 128
	var requires strings.Builder
	names := make([]string, 64)
	for i := range names {
		names[i] = fmt.Sprintf("example.com/dependency%02d", i)
		writef(&requires, "\t%s v1.0.0\n", names[i])
	}
	prefix := contractFrameworkModule + "/" + strings.Repeat("claimant", 16) + "-"
	index := inspectClaimantContract(t, repeatedClaimantContract(prefix, claimantCount, names))
	repo := t.TempDir()
	writeFixture(t, repo, "go.mod", "module example.com/consumer\n\ngo 1.27\n\nrequire (\n"+requires.String()+")\n")
	report, err := ScanRepoWithFramework(t.Context(), repo, index, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteNeedsManifest(repo, report); err != nil {
		t.Fatalf("WriteNeedsManifest: %v", err)
	}
	committed, err := ReadCommittedManifest(t.Context(), repo)
	if err != nil {
		t.Fatalf("ReadCommittedManifest: %v", err)
	}
	recorded, err := parseCommittedManifest(committed)
	if err != nil || len(recorded.Dependencies) != len(names) {
		t.Fatalf("manifest lost demands: decoded=%v err=%v", recorded != nil, err)
	}
	for _, dep := range recorded.Dependencies {
		assertBoundedAmbiguityNote(t, dep, prefix, claimantCount)
	}
}

// repeatedClaimantContract gives every package the same replacement names and an unrelated capability.
func repeatedClaimantContract(prefix string, count int, names []string) string {
	var contract strings.Builder
	contract.WriteString("version: 1\nframework: " + contractFrameworkModule + "\npackages:\n")
	replaces := strings.Join(names, ", ")
	for i := count - 1; i >= 0; i-- {
		writef(&contract, "  - import: %s%03d\n    capabilities: [db.sqlite]\n    replaces: [%s]\n", prefix, i, replaces)
	}
	return contract.String()
}

// assertBoundedAmbiguityNote checks the byte ceiling, sorted prefix and exact omitted count.
func assertBoundedAmbiguityNote(t *testing.T, dep DependencyDemand, prefix string, count int) {
	t.Helper()
	assertDemand(t, dep, StatusGap, "", buildGoDemand(dep.Package, dep.Version).Capability)
	if len(dep.Notes) > 1024 {
		t.Fatalf("ambiguity note = %d bytes, want at most 1024", len(dep.Notes))
	}
	_, rest, found := strings.Cut(dep.Notes, string(dep.Capability)+": ")
	paths, omitted, hasCount := strings.Cut(rest, " (")
	shown := strings.Split(paths, ", ")
	if !found || !hasCount || len(shown) < 2 || omitted != fmt.Sprintf("%d omitted)", count-len(shown)) {
		t.Fatalf("ambiguity note lacks sorted prefix or omitted count: %q", dep.Notes)
	}
	for i, path := range shown {
		if want := fmt.Sprintf("%s%03d", prefix, i); path != want {
			t.Fatalf("claimant %d = %q, want %q", i, path, want)
		}
	}
}

// TestClaimantSelectionBounds accepts a full claim list and keeps an oversized list a gap.
func TestClaimantSelectionBounds(t *testing.T) {
	prefix := contractFrameworkModule + "/p"
	index := inspectClaimantContract(t, repeatedClaimantContract(prefix, maxFrameworkPackages, []string{claimantDependency}))
	last := fmt.Sprintf("%s%03d", prefix, maxFrameworkPackages-1)
	index.Packages[last] = FrameworkPackage{Capabilities: []CapabilityKey{claimantCapability}}
	dep := DependencyDemand{Package: claimantDependency, Capability: claimantCapability, Status: StatusGap}
	atLimit := dep
	reconcileDependency(index, &atLimit)
	assertDemand(t, atLimit, StatusCovered, last, claimantCapability)
	index.Replacements[claimantDependency] = append(index.Replacements[claimantDependency], claimantA)
	reconcileDependency(index, &dep)
	assertDemand(t, dep, StatusGap, "", claimantCapability)
	if !strings.Contains(dep.Notes, fmt.Sprintf("claimant limit of %d exceeded", maxFrameworkPackages)) {
		t.Errorf("over-limit note = %q", dep.Notes)
	}
}

// TestWriteNeedsManifestRejectsOversize checks the reader's budget without replacing the previous file.
func TestWriteNeedsManifestRejectsOversize(t *testing.T) {
	repo := t.TempDir()
	const previous = "version: 1\n"
	writeFixture(t, repo, NeedsManifestName, previous)
	tooLarge := &RepoNeeds{Repository: strings.Repeat("x", contextopt.MaxSourceBytes)}
	if err := WriteNeedsManifest(repo, tooLarge); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("exceeds %d bytes", contextopt.MaxSourceBytes)) {
		t.Errorf("WriteNeedsManifest = %v, want size error", err)
	}
	got, err := ReadCommittedManifest(t.Context(), repo)
	if err != nil || string(got) != previous {
		t.Fatalf("previous manifest changed: %q, %v", got, err)
	}
}

func TestFrameworkContractDeclarationAloneDoesNotEstablishAvailability(t *testing.T) {
	root := setupContractCheckout(t, validContract)
	writeFixture(t, root, "core/id/id.go", "// Package id is planned.\npackage id\n")
	index, err := InspectFramework(t.Context(), acmeSource(root))
	if err != nil {
		t.Fatal(err)
	}
	if _, observed := index.Packages[contractFrameworkModule+"/core/id"]; observed || index.ProvidesCapability("id.uuid") {
		t.Fatal("a contract entry without library declarations is an unavailable stub")
	}
	if offered := index.Replacements["github.com/google/uuid"]; len(offered) != 0 {
		t.Fatal("replaces of an unobserved package must not be offered")
	}
	report, err := ScanRepoWithFramework(t.Context(), setupContractConsumer(t), index, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertDemand(t, demandFor(t, report, "github.com/google/uuid"), StatusGap, "", "id.uuid")
}

func TestFrameworkContractHonoursDeclaredModulesOnly(t *testing.T) {
	root := setupContractCheckout(t, validContract)
	if err := os.Remove(filepath.Join(root, "core", "go.mod")); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "db/go.mod", "module example.com/elsewhere\n\ngo 1.27\n")
	index, err := InspectFramework(t.Context(), acmeSource(root))
	if err != nil {
		t.Fatal(err)
	}
	if index.ProvidesCapability("id.uuid") {
		t.Fatal("a declared nested module without its go.mod does not contain the package")
	}
	if index.ProvidesCapability("db.sqlite") {
		t.Fatal("a package under an undeclared nested module is outside its declared module")
	}
	if !index.ProvidesCapability("telemetry.otel") {
		t.Fatal("root-module packages remain observed")
	}
}

func TestFrameworkContractRejectsInvalidContracts(t *testing.T) {
	cases := map[string]string{
		"unsupported version":    strings.Replace(validContract, "version: 1", "version: 2", 1),
		"framework mismatch":     strings.Replace(validContract, "framework: example.com/fw", "framework: example.com/other", 1),
		"package outside":        strings.Replace(validContract, "import: example.com/fw/otel", "import: example.com/other/otel", 1),
		"undeclared module":      strings.Replace(validContract, "module: example.com/fw/core", "module: example.com/fw/lib", 1),
		"invalid capability key": strings.Replace(validContract, "[telemetry.otel]", "[Telemetry]", 1),
		"duplicate package":      strings.Replace(validContract, "import: example.com/fw/otel", "import: example.com/fw/core/id", 1),
		"invalid replaces path":  strings.Replace(validContract, "[go.opentelemetry.io/otel]", "[/abs/path]", 1),
		"malformed yaml":         "version: [1\n",
		"oversized":              validContract + "# " + strings.Repeat("x", maxContractBytes) + "\n",
	}
	for name, contract := range cases {
		t.Run(name, func(t *testing.T) {
			root := setupContractCheckout(t, contract)
			if _, err := InspectFramework(t.Context(), acmeSource(root)); err == nil {
				t.Fatal("an invalid contract must fail inspection instead of silently degrading")
			}
		})
	}
}

func contractWithPackages(count int) string {
	var sb strings.Builder
	sb.WriteString("version: 1\nframework: example.com/fw\npackages:\n")
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "  - import: example.com/fw/p%d\n    capabilities: [x.p%d]\n", i, i)
	}
	return sb.String()
}

func contractWithKeys(count int) string {
	names := make([]string, 0, count)
	for i := 0; i < count; i++ {
		names = append(names, fmt.Sprintf("x.k%d", i))
	}
	return "version: 1\nframework: example.com/fw\npackages:\n  - import: example.com/fw/otel\n    capabilities: [" + strings.Join(names, ", ") + "]\n"
}

func TestFrameworkContractBoundsAreInclusive(t *testing.T) {
	if _, err := InspectFramework(t.Context(), acmeSource(setupContractCheckout(t, contractWithPackages(maxFrameworkPackages)))); err != nil {
		t.Fatalf("package bound is inclusive: %v", err)
	}
	if _, err := InspectFramework(t.Context(), acmeSource(setupContractCheckout(t, contractWithPackages(maxFrameworkPackages+1)))); err == nil {
		t.Fatal("one package past the bound must be rejected")
	}
	if _, err := InspectFramework(t.Context(), acmeSource(setupContractCheckout(t, contractWithKeys(maxContractKeys)))); err != nil {
		t.Fatalf("capability bound is inclusive: %v", err)
	}
	if _, err := InspectFramework(t.Context(), acmeSource(setupContractCheckout(t, contractWithKeys(maxContractKeys+1)))); err == nil {
		t.Fatal("one capability past the bound must be rejected")
	}
}

func TestStripMajorSuffix(t *testing.T) {
	cases := map[string]string{
		"github.com/acme/kv/v2":     "github.com/acme/kv",
		"github.com/acme/kv/v12":    "github.com/acme/kv",
		"github.com/acme/kv":        "github.com/acme/kv",
		"github.com/acme/kv/v2/sub": "github.com/acme/kv/v2/sub",
		"gopkg.in/yaml.v3":          "gopkg.in/yaml.v3",
		"v2":                        "v2",
		"":                          "",
	}
	for input, want := range cases {
		if got := stripMajorSuffix(input); got != want {
			t.Errorf("stripMajorSuffix(%q) = %q, want %q", input, got, want)
		}
	}
}
