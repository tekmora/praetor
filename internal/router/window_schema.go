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
	return strictjson.CompileSchemaWithFormats("urn:praetor:window-snapshot", catalog.SnapshotSchema())
})

// windowSnapshotDocument counts records in the strict token walk before either decoder
// allocates an array. It keeps the original properties for the subsequent schema check.
func windowSnapshotDocument(data []byte) (any, error) {
	// All v1 containers fit within four levels (e.g. snapshot, records, record, usage_window).
	options := strictjson.Options{
		MaxBytes:   maxWindowSnapshotBytes,
		MaxDepth:   4,
		Names:      strictjson.ExactNames,
		UseNumber:  true,
		ArrayLimit: &strictjson.ArrayLimit{Member: "records", MaxItems: catalog.MaxSnapshotRecords},
		Messages:   strictjson.Messages{Items: "record count before decode: snapshot has %d records, exceeds %d"},
	}
	var document any
	if err := strictjson.Decode(data, &document, options); err != nil {
		return nil, err
	}
	return document, nil
}
