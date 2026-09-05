package report

import (
	"encoding/xml"
	"fmt"
	"io"

	"github.com/marshal-security/marshal/internal/findings"
)

type junitTestSuites struct {
	XMLName xml.Name         `xml:"testsuites"`
	Suites  []junitTestSuite `xml:"testsuite"`
}

type junitTestSuite struct {
	Name     string          `xml:"name,attr"`
	Tests    int             `xml:"tests,attr"`
	Failures int             `xml:"failures,attr"`
	Cases    []junitTestCase `xml:"testcase"`
}

type junitTestCase struct {
	Name    string        `xml:"name,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Text    string `xml:",chardata"`
}

// junitExporter renders findings as JUnit XML, grouping findings into one
// testsuite per engine so CI dashboards can distinguish detection sources.
type junitExporter struct{}

func (junitExporter) Export(w io.Writer, list []findings.Finding) error {
	suitesByEngine := make(map[findings.EngineType][]findings.Finding)
	var engineOrder []findings.EngineType
	for _, f := range list {
		if _, seen := suitesByEngine[f.Engine]; !seen {
			engineOrder = append(engineOrder, f.Engine)
		}
		suitesByEngine[f.Engine] = append(suitesByEngine[f.Engine], f)
	}

	out := junitTestSuites{}
	for _, engine := range engineOrder {
		engineFindings := suitesByEngine[engine]
		suite := junitTestSuite{
			Name:     string(engine),
			Tests:    len(engineFindings),
			Failures: len(engineFindings),
		}
		for _, f := range engineFindings {
			testcaseName := f.Location.String()
			if f.ID != "" {
				testcaseName = fmt.Sprintf("%s [%s]", testcaseName, f.ID)
			} else if f.CVE != "" {
				testcaseName = fmt.Sprintf("%s [%s]", testcaseName, f.CVE)
			} else {
				testcaseName = fmt.Sprintf("%s [%s]", testcaseName, f.Title)
			}
			suite.Cases = append(suite.Cases, junitTestCase{
				Name: testcaseName,
				Failure: &junitFailure{
					Message: f.Title,
					Type:    string(f.Severity),
					Text:    f.Description,
				},
			})
		}
		out.Suites = append(out.Suites, suite)
	}

	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	return enc.Encode(out)
}
