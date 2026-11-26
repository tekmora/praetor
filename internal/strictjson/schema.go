package strictjson

import (
	"bytes"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// CompileSchema compiles a supplied JSON Schema with local references only.
// The identity resolves relative references without allowing network or filesystem access.
func CompileSchema(identity string, raw []byte) (*jsonschema.Schema, error) {
	return compileSchema(identity, raw, false)
}

// CompileSchemaWithFormats also enforces format keywords in drafts that treat them as annotations.
func CompileSchemaWithFormats(identity string, raw []byte) (*jsonschema.Schema, error) {
	return compileSchema(identity, raw, true)
}

// compileSchema configures local-only resolution and the caller's format policy.
func compileSchema(identity string, raw []byte, assertFormats bool) (*jsonschema.Schema, error) {
	document, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode schema %s: %w", identity, err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.UseLoader(jsonschema.SchemeURLLoader{})
	if assertFormats {
		compiler.AssertFormat()
	}
	if err := compiler.AddResource(identity, document); err != nil {
		return nil, fmt.Errorf("add schema %s: %w", identity, err)
	}
	compiled, err := compiler.Compile(identity)
	if err != nil {
		return nil, fmt.Errorf("compile schema %s: %w", identity, err)
	}
	return compiled, nil
}
