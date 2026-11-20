package osv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shakystar/check-foundry/internal/runner"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

type osvOutput struct {
	Results *[]struct {
		Packages []struct {
			Package         struct{ Name, Version, Ecosystem string }
			Vulnerabilities []struct{ ID, Summary string }
		}
	}
}

type Finding struct {
	Package string `json:"package"`
	Version string `json:"version"`
	ID      string `json:"id"`
	Summary string `json:"summary,omitempty"`
}

type Config struct{ Cache, Binary, Version, DatabaseSHA string }
type Result struct {
	File               string
	Excluded, Eligible int
	Evidence
}
type Evidence struct {
	Checked  int
	Findings []Finding
}

var ErrUnsupported = errors.New("unsupported input")

type unsupported string

func (e unsupported) Error() string { return string(e) }
func (e unsupported) Unwrap() error { return ErrUnsupported }

func Scan(ctx context.Context, target string, config Config) (Result, error) {
	var result Result
	cache, bin := config.Cache, config.Binary
	info, err := os.Stat(target)
	if err != nil {
		return result, err
	}
	if info.IsDir() {
		target = filepath.Join(target, "package-lock.json")
	}
	result.File = filepath.Base(target)
	if result.File != "package-lock.json" {
		return result, unsupported("expected package-lock.json")
	}
	f, err := os.Open(target)
	if os.IsNotExist(err) {
		return result, unsupported("no package-lock.json at target root")
	}
	if err != nil {
		return result, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	if err != nil || len(data) > 32<<20 {
		return result, errors.New("cannot read lockfile within 32 MiB limit")
	}
	clean, want, excluded, err := inventory(data)
	if err != nil {
		return result, err
	}
	result.Excluded, result.Eligible = excluded, len(want)
	if len(want) == 0 {
		return result, unsupported("no eligible npm versions")
	}
	db, err := os.Open(filepath.Join(cache, "osv-scalibr", "npm", "all.zip"))
	if err != nil {
		return result, errors.New("npm database unavailable; run the separate database preparation step")
	}
	h := sha256.New()
	_, err = io.Copy(h, db)
	db.Close()
	if err != nil || fmt.Sprintf("%x", h.Sum(nil)) != config.DatabaseSHA {
		return result, errors.New("npm database checksum mismatch")
	}
	bin, err = exec.LookPath(bin)
	if err != nil {
		return result, errors.New("osv-scanner executable unavailable")
	}
	bin, err = filepath.Abs(bin)
	if err != nil {
		return result, err
	}
	dir, err := os.MkdirTemp("", "check-foundry-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	env := []string{"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + cache}
	ver, code, err := runner.Run(ctx, dir, bin, env, "--version")
	if err != nil {
		return result, err
	}
	if code != 0 || !strings.Contains(string(ver), "osv-scanner version: "+strings.TrimPrefix(config.Version, "v")+"\n") {
		return result, errors.New("scanner version check or OS isolation failed")
	}
	buf, err := json.Marshal(clean)
	if err != nil {
		return result, err
	}
	if err = os.WriteFile(filepath.Join(dir, "package-lock.json"), buf, 0400); err != nil {
		return result, err
	}
	raw, code, err := runner.Run(ctx, dir, bin, env, "scan", "source", "--offline", "--all-packages", "--format", "json", "-L", "package-lock.json")
	if err != nil {
		return result, err
	}
	result.Evidence, err = decode(raw, code, want)
	return result, err
}

func decode(raw []byte, code int, want map[key]bool) (Evidence, error) {
	var verified Evidence
	if code != 0 && code != 1 {
		return Evidence{}, fmt.Errorf("OSV scan failed (exit %d)", code)
	}
	var output osvOutput
	if err := json.Unmarshal(raw, &output); err != nil || output.Results == nil {
		return Evidence{}, errors.New("invalid OSV report")
	}
	seen := map[key]bool{}
	ids := map[[3]string]bool{}
	for _, group := range *output.Results {
		for _, p := range group.Packages {
			k := key{p.Package.Name, p.Package.Version}
			if !want[k] || p.Package.Ecosystem != "npm" {
				return Evidence{}, errors.New("unexpected package in OSV report")
			}
			seen[k] = true
			for _, v := range p.Vulnerabilities {
				if v.ID == "" {
					return Evidence{}, errors.New("missing advisory identifier")
				}
				id := [3]string{k.name, k.version, v.ID}
				if !ids[id] {
					verified.Findings = append(verified.Findings, Finding{k.name, k.version, v.ID, v.Summary})
					ids[id] = true
				}
			}
		}
	}
	verified.Checked = len(seen)
	sort.Slice(verified.Findings, func(i, j int) bool {
		a, b := verified.Findings[i], verified.Findings[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.ID < b.ID
	})
	if (code == 1) != (len(ids) > 0) {
		return Evidence{}, errors.New("OSV exit status and findings disagree")
	}
	return verified, nil
}
