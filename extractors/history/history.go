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

// Get Chrome user data folder (Windows)
func getChromeUserDataPath() string {
	localAppData := os.Getenv("LOCALAPPDATA")
	if localAppData == "" {
		return ""
	}
	return filepath.Join(localAppData, "Google", "Chrome", "User Data")
}

// Convert Chrome timestamp to readable local time
func chromeTimeToReadable(microseconds int64) string {
	const offset = 11644473600000000
	seconds := (microseconds - offset) / 1000000
	nanos := ((microseconds - offset) % 1000000) * 1000
	t := time.Unix(seconds, nanos)
	return t.Local().Format("02 Jan 2006, 03:04 PM")
}

// Extract history entries from one profile
func extractHistory(profilePath, profileName string) ([]Entry, error) {
	historyDB := filepath.Join(profilePath, "History")

	// Copy to temp (avoids lock if Chrome is running)
	tempCopy := filepath.Join(os.TempDir(), fmt.Sprintf("chrome_history_%s.db", profileName))
	data, err := os.ReadFile(historyDB)
	if err != nil {
		return nil, fmt.Errorf("failed to read DB: %v", err)
	}
	os.WriteFile(tempCopy, data, 0644)
	defer os.Remove(tempCopy)

	db, err := sql.Open("sqlite3", tempCopy)
	if err != nil {
		return nil, fmt.Errorf("failed to open DB: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC `)
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
			entry := Entry{
				Title:         title,
				URL:           url,
				LastVisitTime: chromeTimeToReadable(lastVisit),
				VisitCount:    visitCount,
			}
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func Run() {
	userDataPath := getChromeUserDataPath()
	if userDataPath == "" {
		fmt.Println("Chrome user data directory not found")
		return
	}

	folders, _ := os.ReadDir(userDataPath)

	// Create base JSON structure
	result := BrowserData{
		"Brave":  map[string][]Entry{},
		"Chrome": map[string][]Entry{},
		"Edge":   map[string][]Entry{},
	}

	for _, f := range folders {
		if f.IsDir() && (strings.HasPrefix(f.Name(), "Profile") || f.Name() == "Default") {
			profilePath := filepath.Join(userDataPath, f.Name())
			entries, err := extractHistory(profilePath, f.Name())
			if err == nil {
				result["Chrome"][f.Name()] = entries
			} else {
				fmt.Printf("Skipping %s: %v\n", f.Name(), err)
			}
		}
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, "browser_history.json")

	output, _ := json.MarshalIndent(result, "", "  ")
	os.WriteFile(outputPath, output, 0644)
	fmt.Println("Saved")

}
