package autofill

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite driver
)

// Autofill record in output JSON
type Autofill struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	UsedAt string `json:"used_at,omitempty"` // human readable local datetime
}

// Convert timestamp to time.Time
// Chrome can store timestamps in different formats:
// - Large values (>1e15): microseconds since January 1, 1601 (Windows FILETIME)
// - Medium values (1e9-1e12): Unix timestamps in seconds or milliseconds
// - Small values: Unix timestamps in seconds
func chromiumMicrosecondsToTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}

	// If value is very large (>1e15), it's microseconds since 1601
	if ts > 1_000_000_000_000_000 {
		const epochDiff = 11644473600 // seconds between 1601 and 1970
		secs := (ts / 1_000_000) - epochDiff
		nsecs := (ts % 1_000_000) * 1000
		return time.Unix(secs, nsecs).Local()
	}
	
	// If value is large (1e12-1e15), it's milliseconds since Unix epoch
	if ts > 1_000_000_000_000 {
		secs := ts / 1000
		nsecs := (ts % 1000) * 1_000_000
		return time.Unix(secs, nsecs).Local()
	}
	
	// Otherwise, treat as Unix timestamp in seconds (most common for autofill)
	return time.Unix(ts, 0).Local()
}

// copyToTemp copies the source file to a temp file and returns the temp path
// to avoid locking issues when original DB is open by the browser.
func copyToTemp(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "webdata-*.db")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	defer tmp.Close()

	if _, err := io.Copy(tmp, in); err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

// parseAutofill reads the given Web Data DB and returns autofill entries.
// It handles date_last_used (microseconds since 1601). If not present, it will
// try other common column names.
func parseAutofill(dbPath string) ([]Autofill, error) {
	// copy DB to temp to avoid lock issues
	tmpPath, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	queries := []string{
		`SELECT name, value, date_last_used FROM autofill`,
		`SELECT name, value, last_used FROM autofill`,
		`SELECT name, value, date_created FROM autofill`,
		`SELECT name, value FROM autofill`, // fallback (no timestamp)
	}

	var rows *sql.Rows
	for _, q := range queries {
		rows, err = db.Query(q)
		if err == nil {
			// success
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("no usable autofill query succeeded: %w", err)
	}
	defer rows.Close()

	var results []Autofill

	cols, _ := rows.Columns()
	// We'll handle different column sets dynamically
	for rows.Next() {
		// prepare destinations depending on columns
		var name sql.NullString
		var value sql.NullString
		var ts sql.NullInt64 // may or may not be present

		switch len(cols) {
		case 3:
			if err := rows.Scan(&name, &value, &ts); err != nil {
				// try safe scan fallback
				continue
			}
		case 2:
			if err := rows.Scan(&name, &value); err != nil {
				continue
			}
			ts.Valid = false
		default:
			// unexpected shape
			// try generic scan into interface{}
			var scanDest []interface{}
			for range cols {
				var x interface{}
				scanDest = append(scanDest, &x)
			}
			if err := rows.Scan(scanDest...); err != nil {
				continue
			}
			// try to map first two cols
			if s, ok := (*(scanDest[0].(*interface{}))).(string); ok {
				name.String = s
				name.Valid = true
			}
			if s, ok := (*(scanDest[1].(*interface{}))).(string); ok {
				value.String = s
				value.Valid = true
			}
		}

		record := Autofill{
			Name:  "",
			Value: "",
		}
		if name.Valid {
			record.Name = name.String
		}
		if value.Valid {
			record.Value = value.String
		}

		if ts.Valid && ts.Int64 != 0 {
			t := chromiumMicrosecondsToTime(ts.Int64)
			if !t.IsZero() {
				// Format local time as "YYYY-MM-DD HH:MM:SS"
				record.UsedAt = t.Local().Format("2006-01-02 15:04:05")
			}
		}
		results = append(results, record)
	}
	return results, nil
}

// findWebData tries common candidate locations of "Web Data" within a profile folder.
func findWebData(profileDir string) (string, bool) {
	candidates := []string{
		filepath.Join(profileDir, "Web Data"),
		filepath.Join(profileDir, "Default", "Web Data"),
		filepath.Join(profileDir, "Profile 1", "Web Data"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, true
		}
	}
	return "", false
}

// scanBrowser scans a browser user-data base folder and fills output[browser][profile] = []Autofill
func scanBrowser(basePath, browser string, output map[string]map[string][]Autofill) {
	output[browser] = make(map[string][]Autofill)
	if stat, err := os.Stat(basePath); err != nil || !stat.IsDir() {
		// base doesn't exist, nothing to do
		return
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		// skip files
		if !entry.IsDir() {
			continue
		}
		profileName := entry.Name()
		profileDir := filepath.Join(basePath, profileName)
		// locate Web Data
		if dbPath, ok := findWebData(profileDir); ok {
			autofills, err := parseAutofill(dbPath)
			if err == nil && len(autofills) > 0 {
				output[browser][profileName] = autofills
			}
		}
	}
}

func Run() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("cannot determine user home:", err)
		return
	}

	var chromeBase, edgeBase, braveBase string
	switch runtime.GOOS {
	case "windows":
		chromeBase = filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data")
		edgeBase = filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data")
		braveBase = filepath.Join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")
	case "darwin":
		chromeBase = filepath.Join(home, "Library", "Application Support", "Google", "Chrome")
		edgeBase = filepath.Join(home, "Library", "Application Support", "Microsoft Edge")
		braveBase = filepath.Join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser")
	default: // linux / other
		chromeBase = filepath.Join(home, ".config", "google-chrome")
		edgeBase = filepath.Join(home, ".config", "microsoft-edge")
		braveBase = filepath.Join(home, ".config", "BraveSoftware", "Brave-Browser")
	}

	output := make(map[string]map[string][]Autofill)

	scanBrowser(chromeBase, "Chrome", output)
	scanBrowser(edgeBase, "Edge", output)
	scanBrowser(braveBase, "Brave", output)

	// Save to file
	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)

	outFile := filepath.Join(resultsDir, "autofill.json")
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Println("error creating output file:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		fmt.Println("error writing json:", err)
		return
	}

	fmt.Println("Saved autofill data to", outFile)
}