package router

import (
	"sync"

	"github.com/cordanaLLM/praetor/internal/strictjson"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tekmora/epitrop/catalog"
)

const maxWindowSnapshotBytes = 64 << 20

// windowSnapshotSchema compiles the producer's embedded schema once per process.
var windowSnapshotSchema = sync.OnceValues(func() (*jsonschema.Schema, error) {
	return strictjson.CompileSchema("urn:praetor:window-snapshot", catalog.SnapshotSchema())
})

// validateWindowSnapshotSchema checks the original JSON so missing properties, repeated keys
// and unknown source statuses cannot disappear into the Go representation.
func validateWindowSnapshotSchema(data []byte) error {
	schema, err := windowSnapshotSchema()
	if err != nil {
		return err
	}
	var document any
	// All v1 containers fit within four levels (e.g. snapshot, records, record, usage_window).
	options := strictjson.Options{MaxBytes: maxWindowSnapshotBytes, MaxDepth: 4, Names: strictjson.ExactNames, UseNumber: true}
	if err := strictjson.Decode(data, &document, options); err != nil {
		return err
	}
	return schema.Validate(document)
}
