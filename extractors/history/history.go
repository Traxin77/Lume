package history

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Entry represents one browser history record
type Entry struct {
	Title         string `json:"title"`
	URL           string `json:"url"`
	LastVisitTime string `json:"last_visit_time"`
	VisitCount    int    `json:"visit_count"`
}

// BrowserData holds all browsers -> profiles -> entries
type BrowserData map[string]map[string][]Entry

// Get Chromium-based browser user data folder (Windows)
func getUserDataPath(browser string) string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return ""
	}

	switch browser {
	case "Chrome":
		return filepath.Join(localAppData, "Google", "Chrome", "User Data")
	case "Edge":
		return filepath.Join(localAppData, "Microsoft", "Edge", "User Data")
	case "Brave":
		return filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data")
	default:
		return ""
	}
}

// Convert Chromium timestamp to readable local time
func chromeTimeToReadable(microseconds int64) string {
	const offset = 11644473600000000
	seconds := (microseconds - offset) / 1000000
	nanos := ((microseconds - offset) % 1000000) * 1000
	t := time.Unix(seconds, nanos)
	return t.Local().Format("02 Jan 2006, 03:04 PM")
}

// Extract history entries from one profile
func extractHistory(profilePath, profileName, browser string) ([]Entry, error) {
	historyDB := filepath.Join(profilePath, "History")

	// Copy to temp (avoids lock if browser is running)
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("%s_history_%s.db", strings.ToLower(browser), profileName))
	data, err := os.ReadFile(historyDB)
	if err != nil {
		return nil, fmt.Errorf("failed to read DB: %v", err)
	}
	if err := os.WriteFile(tempCopy, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write temp DB: %v", err)
	}
	defer os.Remove(tempCopy)

	db, err := sql.Open("sqlite3", tempCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC`)
	if err != nil {
		return nil, fmt.Errorf("failed to query DB: %v", err)
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var url, title string
		var lastVisit int64
		var visitCount int
		if err := rows.Scan(&url, &title, &lastVisit, &visitCount); err == nil {
			entries = append(entries, Entry{
				Title:         title,
				URL:           url,
				LastVisitTime: chromeTimeToReadable(lastVisit),
				VisitCount:    visitCount,
			})
		}
	}

	return entries, nil
}

func Run() {
	// Create base JSON structure
	result := BrowserData{
		"Brave":  map[string][]Entry{},
		"Chrome": map[string][]Entry{},
		"Edge":   map[string][]Entry{},
	}

	browsers := []string{"Chrome", "Edge", "Brave"}

	for _, browser := range browsers {
		userDataPath := getUserDataPath(browser)
		if userDataPath == "" {
			fmt.Printf("%s user data directory not found\n", browser)
			continue
		}

		folders, err := os.ReadDir(userDataPath)
		if err != nil {
			fmt.Printf("Failed to read %s directory: %v\n", browser, err)
			continue
		}

		for _, f := range folders {
			if f.IsDir() && (strings.HasPrefix(f.Name(), "Profile") || f.Name() == "Default") {
				profilePath := filepath.Join(userDataPath, f.Name())
				entries, err := extractHistory(profilePath, f.Name(), browser)
				if err == nil {
					result[browser][f.Name()] = entries
				} else {
					fmt.Printf("Skipping %s profile %s: %v\n", browser, f.Name(), err)
				}
			}
		}
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results", "chromium")
	_ = os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, "chromium_history.json")

	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal JSON: %v\n", err)
		return
	}

	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		fmt.Printf("Failed to write output file: %v\n", err)
		return
	}

	fmt.Printf("Saved history for Chrome/Edge/Brave to %s\n", outputPath)
}
