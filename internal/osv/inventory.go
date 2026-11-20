package osv

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

type entry struct {
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Resolved string `json:"resolved,omitempty"`
	Link     bool   `json:"link,omitempty"`
}
type lockfile struct {
	Version  int              `json:"lockfileVersion"`
	Packages map[string]entry `json:"packages"`
}
type key struct{ name, version string }

var exact = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
var pkgName = regexp.MustCompile(`^(@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_][A-Za-z0-9._-]*$`)

func inventory(data []byte) (lockfile, map[key]bool, int, error) {
	var in lockfile
	clean := lockfile{Version: 3, Packages: map[string]entry{"": {}}}
	want := map[key]bool{}
	excluded := 0
	if err := json.Unmarshal(data, &in); err != nil || (in.Version != 2 && in.Version != 3) || in.Packages == nil {
		return clean, nil, 0, errors.New("expected npm lockfileVersion 2 or 3 with packages")
	}
	for path, p := range in.Packages {
		if path == "" {
			continue
		}
		_, name, ok := strings.Cut(path, "node_modules/")
		if idx := strings.LastIndex(path, "/node_modules/"); idx >= 0 {
			name = path[idx+len("/node_modules/"):]
		}
		if p.Name != "" {
			name = p.Name
		}
		if !ok || p.Link || !pkgName.MatchString(name) || !exact.MatchString(p.Version) || (p.Resolved != "" && !strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/")) {
			excluded++
			continue
		}
		clean.Packages[path] = entry{Name: name, Version: p.Version}
		want[key{name, p.Version}] = true
	}
	return clean, want, excluded, nil
}
