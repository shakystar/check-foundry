package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/shakystar/check-foundry/internal/osv"
	"os"
	"path/filepath"
	"time"
)

//go:embed config/offline.json
var frozen []byte

type database struct {
	SHA  string `json:"sha256"`
	Date string `json:"last_modified"`
}
type baseline struct {
	OSV string   `json:"osv_scanner"`
	DB  database `json:"npm_db"`
}
type report struct {
	Status   string        `json:"status"`
	Reason   string        `json:"reason,omitempty"`
	Tool     string        `json:"required_osv_version"`
	DB       database      `json:"required_db"`
	File     string        `json:"input"`
	Checked  int           `json:"unique_packages_checked"`
	Excluded int           `json:"excluded_lock_entries"`
	Findings []osv.Finding `json:"findings"`
}

func run() int {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		fmt.Fprintln(os.Stderr, "usage: check-foundry scan [-json] [-db-cache DIR] [-osv PATH] PROJECT")
		return 2
	}
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	js := fs.Bool("json", false, "emit JSON")
	cache := fs.String("db-cache", os.Getenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"), "offline cache root")
	bin := fs.String("osv", "osv-scanner", "scanner executable")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 1 {
		return 2
	}
	var pins baseline
	if json.Unmarshal(frozen, &pins) != nil {
		panic("invalid embedded baseline")
	}
	r := report{Status: "failed", Tool: pins.OSV, DB: pins.DB, Findings: []osv.Finding{}}
	if *cache == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return 2
		}
		*cache = filepath.Join(d, "check-foundry")
	}
	abs, err := filepath.Abs(*cache)
	if err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := osv.Scan(ctx, fs.Arg(0), osv.Config{Cache: abs, Binary: *bin, Version: pins.OSV, DatabaseSHA: pins.DB.SHA})
	applyOSV(&r, result, err)
	if *js {
		if json.NewEncoder(os.Stdout).Encode(r) != nil {
			return 2
		}
	} else {
		fmt.Printf("%s | %s | checked %d | excluded %d | findings %d\n", r.Status, r.File, r.Checked, r.Excluded, len(r.Findings))
		if r.Reason != "" {
			fmt.Println(r.Reason)
		}
		for _, v := range r.Findings {
			fmt.Printf("%s@%s  %s  %s\n", v.Package, v.Version, v.ID, v.Summary)
		}
	}
	if r.Status != "complete" {
		return 2
	}
	if len(r.Findings) > 0 {
		return 1
	}
	return 0
}
func main() { os.Exit(run()) }

// applyOSV presents the adapter result using the M1 CLI report contract.
func applyOSV(r *report, result osv.Result, err error) {
	r.File, r.Excluded = result.File, result.Excluded
	if err != nil {
		r.Status = "failed"
		if errors.Is(err, osv.ErrUnsupported) {
			r.Status = "unsupported"
		}
		r.Reason = err.Error()
		return
	}
	r.Checked = result.Checked
	r.Findings = append(r.Findings, result.Findings...)
	if result.Checked != result.Eligible || result.Excluded != 0 {
		r.Status = "partial"
		r.Reason = fmt.Sprintf("matched %d/%d eligible versions; excluded %d entries", result.Checked, result.Eligible, result.Excluded)
		return
	}
	r.Status = "complete"
}
