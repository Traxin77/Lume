package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	_ "modernc.org/sqlite"
)

type FirefoxHistoryEntry struct {
	URL        string    `json:"url"`
	Title      string    `json:"title"`
	VisitTime  time.Time `json:"visit_time,omitempty"`
	VisitType  int       `json:"visit_type,omitempty"`
	VisitCount int       `json:"visit_count,omitempty"`
}

type ProfileHistory map[string][]FirefoxHistoryEntry

func firefoxBaseDirHistory() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox")
	default:
		return filepath.Join(home, ".mozilla", "firefox")
	}
}

func findProfilesHistory() ([]string, error) {
	base := firefoxBaseDirHistory()
	if base == "" {
		return nil, fmt.Errorf("cannot determine firefox base dir")
	}

	profilesRoot := filepath.Join(base, "Profiles")
	if fi, err := os.Stat(profilesRoot); err == nil && fi.IsDir() {
		entries, err := os.ReadDir(profilesRoot)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(profilesRoot, e.Name()))
			}
		}
		return out, nil
	}

	if fi, err := os.Stat(base); err == nil && fi.IsDir() {
		return []string{base}, nil
	}

	return nil, fmt.Errorf("no firefox profiles found (looked under %s)", profilesRoot)
}

func copyToTempHistory(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "ff_places-*.sqlite")
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

func ffFromMicroseconds(us sql.NullInt64) time.Time {
	if !us.Valid || us.Int64 <= 0 {
		return time.Time{}
	}
	return time.Unix(0, us.Int64*1000).Local()
}

func getHistoryFromProfile(profilePath string, limit int) ([]FirefoxHistoryEntry, error) {
	placesPath := filepath.Join(profilePath, "places.sqlite")
	if _, err := os.Stat(placesPath); err != nil {
		return nil, fmt.Errorf("places.sqlite not found in %s", profilePath)
	}

	tmpPath, err := copyToTempHistory(placesPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpPath)

	db, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	const q = `
SELECT
    p.url,
    p.title,
    v.visit_date,
    v.visit_type,
    p.visit_count
FROM moz_places p
JOIN moz_historyvisits v ON v.place_id = p.id
WHERE p.url IS NOT NULL
ORDER BY v.visit_date DESC
LIMIT ?;
`

	rows, err := db.Query(q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []FirefoxHistoryEntry
	for rows.Next() {
		var url sql.NullString
		var title sql.NullString
		var visitDate sql.NullInt64
		var visitType sql.NullInt64
		var visitCount sql.NullInt64

		if err := rows.Scan(&url, &title, &visitDate, &visitType, &visitCount); err != nil {
			continue
		}

		entry := FirefoxHistoryEntry{
			URL:        url.String,
			Title:      title.String,
			VisitTime:  ffFromMicroseconds(visitDate),
			VisitType:  int(visitType.Int64),
			VisitCount: int(visitCount.Int64),
		}
		out = append(out, entry)
	}
	return out, nil
}

//
// PUBLIC EXTRACTOR ENTRYPOINT
//
func RunHistory() {
	const limit = 500 // default rows per profile

	outPath := filepath.Join("results","firefox", "firefox_history.json")

	profiles, err := findProfilesHistory()
	if err != nil {
		fmt.Println("Error finding profiles:", err)
		return
	}

	result := make(ProfileHistory)

	for _, p := range profiles {
		name := filepath.Base(p)
		fmt.Println("Scanning Firefox profile:", name)

		hist, err := getHistoryFromProfile(p, limit)
		if err != nil {
			fmt.Println(" - Skipped:", err)
			continue
		}

		if len(hist) > 0 {
			result[name] = hist
			fmt.Printf(" - %d rows extracted\n", len(hist))
		}
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Println("mkdir:", err)
		return
	}

	f, err := os.Create(outPath)
	if err != nil {
		fmt.Println("create:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(result)

	fmt.Println("Saved:", outPath)
}
