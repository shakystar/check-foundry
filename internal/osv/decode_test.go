package osv

import "testing"

const packageA = `{"package":{"name":"a","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{"id":"GHSA-example"}]}`

func TestDecodeDiscardsUnverifiedEvidence(t *testing.T) {
	want := map[key]bool{{"a", "1.0.0"}: true}
	for _, tc := range []struct {
		name     string
		code     int
		packages string
	}{
		{"unexpected second package", 1, packageA + `,{"package":{"name":"foreign","version":"1","ecosystem":"npm"}}`},
		{"missing second advisory ID", 1, packageA + `,{"package":{"name":"a","version":"1.0.0","ecosystem":"npm"},"vulnerabilities":[{}]}`},
		{"exit code contradicts findings", 0, packageA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte(`{"results":[{"packages":[` + tc.packages + `]}]}`)
			got, err := decode(raw, tc.code, want)
			if err == nil || got.Checked != 0 || len(got.Findings) != 0 {
				t.Fatalf("unverified result: %+v, error: %v", got, err)
			}
		})
	}
}

func TestDecodeKeepsVerifiedSubset(t *testing.T) {
	want := map[key]bool{{"a", "1.0.0"}: true, {"b", "1.0.0"}: true}
	got, err := decode([]byte(`{"results":[{"packages":[`+packageA+`,`+packageA+`]}]}`), 1, want)
	if err != nil || got.Checked != 1 || len(got.Findings) != 1 {
		t.Fatalf("subset: %+v, error: %v", got, err)
	}
}
