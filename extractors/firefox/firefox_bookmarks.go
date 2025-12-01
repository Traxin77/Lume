//go:build windows
// +build windows

package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type FirefoxBookmarkEntry struct {
	URL      string    `json:"url"`
	Title    string    `json:"title"`
	Added    time.Time `json:"added,omitempty"`
	FolderID int64     `json:"folder_id,omitempty"`
}

func getBookmarksFromProfile(profilePath string) ([]FirefoxBookmarkEntry, error) {
	placesPath := filepath.Join(profilePath, "places.sqlite")
	if _, err := os.Stat(placesPath); err != nil {
		return nil, fmt.Errorf("places.sqlite not found in %s", profilePath)
	}

	tmpPath, err := copyToTemp(placesPath)
	if err != nil {
		return nil, fmt.Errorf("copy places.sqlite failed: %w", err)
	}
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	const q = `
SELECT
    b.id,
    b.title,
    p.url,
    b.dateAdded,
    b.parent
FROM moz_bookmarks b
LEFT JOIN moz_places p ON p.id = b.fk
WHERE b.type = 1
  AND p.url IS NOT NULL
ORDER BY b.dateAdded DESC;
`

	rows, err := db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("query failed: %w", err)
	}
	defer rows.Close()

	var out []FirefoxBookmarkEntry

	for rows.Next() {
		var (
			id       sql.NullInt64
			title    sql.NullString
			url      sql.NullString
			added    sql.NullInt64
			parentID sql.NullInt64
		)

		if err := rows.Scan(&id, &title, &url, &added, &parentID); err != nil {
			continue
		}

		out = append(out, FirefoxBookmarkEntry{
			URL:      url.String,
			Title:    title.String,
			Added:    ffFromMicroseconds(added),
			FolderID: parentID.Int64,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return out, nil
}

// RunBookmarks extracts Firefox bookmarks from all profiles
func RunBookmarks() {
	profiles := findProfiles()
	if len(profiles) == 0 {
		fmt.Println("No Firefox profiles found")
		return
	}

	result := make(map[string][]FirefoxBookmarkEntry)

	// Check every profile
	for _, p := range profiles {
		profileName := filepath.Base(p)
		fmt.Println("Scanning Firefox profile:", profileName)

		bm, err := getBookmarksFromProfile(p)
		if err != nil {
			fmt.Println(" - skipping:", err)
			continue
		}

		if len(bm) > 0 {
			result[profileName] = bm
			fmt.Printf(" - %d bookmarks found\n", len(bm))
		} else {
			fmt.Println(" - no bookmarks")
		}
	}

	// Save to results directory
	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)

	outFile := filepath.Join(resultsDir, "firefox_bookmarks.json")
	f, err := os.Create(outFile)
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

	fmt.Println("Saved Firefox bookmarks to", outFile)
}