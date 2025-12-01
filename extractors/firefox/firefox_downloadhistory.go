//go:build windows
// +build windows

package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type DownloadEntry struct {
	Name        string  `json:"name"`
	Source      string  `json:"source"`
	Target      string  `json:"target"`
	State       string  `json:"state"`
	StartTime   *string `json:"start_time,omitempty"`
	EndTime     *string `json:"end_time,omitempty"`
	BytesTotal  int64   `json:"bytes_total,omitempty"`
	MimeType    string  `json:"mime_type,omitempty"`
	ReferrerURL string  `json:"referrer_url,omitempty"`
}

func parseDownloadTime(v interface{}) *string {
	if v == nil {
		return nil
	}

	var i int64
	switch t := v.(type) {
	case int64:
		i = t
	case float64:
		i = int64(t)
	default:
		return nil
	}

	if i <= 0 {
		return nil
	}

	var ts time.Time
	digits := len(strconv.FormatInt(i, 10))

	if digits >= 16 {
		ts = time.Unix(i/1000000, (i%1000000)*1000)
	} else if digits >= 13 {
		ts = time.Unix(i/1000, (i%1000)*1000000)
	} else if digits >= 10 {
		ts = time.Unix(i, 0)
	} else {
		return nil
	}

	if ts.Year() < 1970 || ts.Year() > 2100 {
		return nil
	}

	s := ts.Local().Format("2006-01-02 15:04:05")
	return &s
}

func getStateString(state int64) string {
	switch state {
	case 0:
		return "downloading"
	case 1:
		return "completed"
	case 2:
		return "failed"
	case 3:
		return "canceled"
	case 4:
		return "paused"
	default:
		return "unknown"
	}
}

func queryDownloads(dbPath string) ([]DownloadEntry, error) {
	tmp, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// Check what tables exist
	tablesQuery := `SELECT name FROM sqlite_master WHERE type='table'`
	tablesRows, err := db.Query(tablesQuery)
	if err != nil {
		return nil, err
	}

	tables := make(map[string]bool)
	for tablesRows.Next() {
		var tableName string
		tablesRows.Scan(&tableName)
		tables[tableName] = true
	}
	tablesRows.Close()

	// Try different queries based on Firefox version
	queries := []string{
		// Modern Firefox (uses moz_annos for downloads)
		`SELECT 
			p.url as source,
			p.title as name,
			a.content as target,
			p.last_visit_date as startTime
		FROM moz_places p
		JOIN moz_annos a ON p.id = a.place_id
		JOIN moz_anno_attributes aa ON a.anno_attribute_id = aa.id
		WHERE aa.name = 'downloads/destinationFileURI'
		ORDER BY p.last_visit_date DESC`,

		// Older Firefox (direct moz_downloads table)
		`SELECT 
			name,
			source,
			target,
			state,
			startTime,
			endTime,
			maxBytes,
			mimeType,
			referrer
		FROM moz_downloads
		ORDER BY startTime DESC`,
	}

	for i, query := range queries {
		rows, err := db.Query(query)
		if err != nil {
			continue
		}

		cols, _ := rows.Columns()

		result := make([]DownloadEntry, 0)
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			valPtrs := make([]interface{}, len(cols))
			for j := range vals {
				valPtrs[j] = &vals[j]
			}

			if err := rows.Scan(valPtrs...); err != nil {
				continue
			}

			getStr := func(idx int) string {
				if idx >= len(vals) || vals[idx] == nil {
					return ""
				}
				return fmt.Sprintf("%v", vals[idx])
			}

			getInt := func(idx int) int64 {
				if idx >= len(vals) || vals[idx] == nil {
					return 0
				}
				switch v := vals[idx].(type) {
				case int64:
					return v
				case float64:
					return int64(v)
				}
				return 0
			}

			entry := DownloadEntry{}

			if i == 0 {
				// Modern format
				entry.Source = getStr(0)
				entry.Name = getStr(1)
				if entry.Name == "" {
					// Extract filename from URL
					entry.Name = filepath.Base(entry.Source)
				}
				entry.Target = getStr(2)
				entry.StartTime = parseDownloadTime(vals[3])
				entry.State = "completed"
			} else {
				// Old format
				entry.Name = getStr(0)
				entry.Source = getStr(1)
				entry.Target = getStr(2)
				entry.State = getStateString(getInt(3))
				entry.StartTime = parseDownloadTime(vals[4])
				entry.EndTime = parseDownloadTime(vals[5])
				entry.BytesTotal = getInt(6)
				entry.MimeType = getStr(7)
				entry.ReferrerURL = getStr(8)
			}

			result = append(result, entry)
		}
		rows.Close()

		if len(result) > 0 {
			return result, nil
		}
	}

	return nil, fmt.Errorf("no downloads found in any table")
}

func RunDownloads() {
	fmt.Println("Extracting Firefox download history...")

	profiles := findProfiles()
	if len(profiles) == 0 {
		fmt.Println("No Firefox profiles found")
		return
	}

	result := make(map[string][]DownloadEntry)

	for _, p := range profiles {
		name := filepath.Base(p)

		// Try places.sqlite (newer Firefox versions)
		placesDB := filepath.Join(p, "places.sqlite")
		if _, err := os.Stat(placesDB); err == nil {
			if entries, err := queryDownloads(placesDB); err == nil && len(entries) > 0 {
				result[name] = entries
				fmt.Printf("Extracted %d downloads from profile %s\n", len(entries), name)
			}
		}
	}

	if len(result) == 0 {
		fmt.Println("No download history found")
		return
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, "firefox_downloads.json")

	f, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Println("Error writing JSON:", err)
		return
	}

	fmt.Println("Saved Firefox downloads to:", outputPath)
}