package osv

import "testing"

func TestInventorySelectedVersions(t *testing.T) {
	input := []byte(`{"lockfileVersion":2,"packages":{"":{"name":"private-project"},"node_modules/a/node_modules/@scope/b":{"version":"1.0.0"},"node_modules/b-alias":{"name":"@scope/b","version":"1.0.0"},"node_modules/linked":{"link":true},"node_modules/private":{"version":"1.0.0","resolved":"https://internal.example/pkg"},"node_modules/range":{"version":"^1.2.3"}}}`)
	clean, versions, excluded, err := inventory(input)
	if err != nil || excluded != 3 || len(versions) != 1 || !versions[key{"@scope/b", "1.0.0"}] {
		t.Fatalf("inventory: %v, %d excluded, %v", versions, excluded, err)
	}
	if len(clean.Packages) != 3 || clean.Packages[""].Name != "" {
		t.Fatal("unexpected metadata in scanner input")
	}
}
func TestUnsupportedLockfile(t *testing.T) {
	for _, s := range []string{`{}`, `{"lockfileVersion":1,"packages":{}}`, `not-json`} {
		if _, _, _, err := inventory([]byte(s)); err == nil {
			t.Errorf("unexpected acceptance: %s", s)
		}
	}
}
