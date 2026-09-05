package report

import (
	"encoding/json"
	"io"

	"github.com/marshal-security/marshal/internal/findings"
)

// jsonExporter renders findings as a raw JSON array.
type jsonExporter struct{}

func (jsonExporter) Export(w io.Writer, list []findings.Finding) error {
	if list == nil {
		list = []findings.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(list)
}
