//go:build windows
// +build windows

package bookmarks

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Chrome stores bookmark dates as WebKit/Chrome timestamps (microseconds since 1601).
const chromeEpochOffsetMicros = int64(11644473600000000)

type BookmarkEntry struct {
	Name      string    `json:"name"`
	URL       string    `json:"url,omitempty"`
	Type      string    `json:"type"` // "url" or "folder"
	DateAdded time.Time `json:"date_added"`
	Children  []BookmarkEntry `json:"children,omitempty"`
}

type BrowserBookmarks map[string]map[string][]BookmarkEntry

func Run() {
	log.SetFlags(0)

	localApp := os.Getenv("LOCALAPPDATA")
	if localApp == "" {
		log.Fatal("LOCALAPPDATA not set (are you on Windows?)")
	}

	candidates := map[string]string{
		filepath.Join(localApp, "Chromium", "User Data"):                      "Chromium",
		filepath.Join(localApp, "Google", "Chrome", "User Data"):              "Chrome",
		filepath.Join(localApp, "Microsoft", "Edge", "User Data"):             "Edge",
		filepath.Join(localApp, "BraveSoftware", "Brave-Browser", "User Data"): "Brave",
	}

	result := BrowserBookmarks{}

	for base, browserName := range candidates {
		if stat, err := os.Stat(base); err == nil && stat.IsDir() {
			profiles, _ := os.ReadDir(base)
			for _, p := range profiles {
				if !p.IsDir() {
					continue
				}
				profilePath := filepath.Join(base, p.Name())
				bookmarkFile := filepath.Join(profilePath, "Bookmarks")
				if exists(bookmarkFile) {
					entries, err := extractBookmarks(bookmarkFile)
					if err != nil {
						log.Printf("warning: failed to extract %s: %v", bookmarkFile, err)
						continue
					}
					if _, ok := result[browserName]; !ok {
						result[browserName] = map[string][]BookmarkEntry{}
					}
					result[browserName][p.Name()] = entries
				}
			}
		}
	}

	if len(result) == 0 {
		log.Println("no chromium bookmarks found.")
		os.Exit(1)
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)

	outputFile := filepath.Join(resultsDir, "chromium_bookmarks.json")
	f, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("cannot create output file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		log.Fatalf("json encode failed: %v", err)
	}

	fmt.Printf("Bookmarks exported to %s\n", outputFile)
}

// --- helpers ---

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Chrome's bookmarks file has a JSON structure with roots: "bookmark_bar", "other", "synced"
func extractBookmarks(filePath string) ([]BookmarkEntry, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	bytes, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(bytes, &raw); err != nil {
		return nil, err
	}

	roots := raw["roots"].(map[string]interface{})
	var results []BookmarkEntry

	for _, key := range []string{"bookmark_bar", "other", "synced"} {
		if node, ok := roots[key]; ok {
			if entry, ok := node.(map[string]interface{}); ok {
				results = append(results, parseNode(entry))
			}
		}
	}

	// Sort by name for consistency
	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results, nil
}

func parseNode(node map[string]interface{}) BookmarkEntry {
	entry := BookmarkEntry{
		Name: getString(node, "name"),
		Type: getString(node, "type"),
	}

	// Date conversion
	if da := getString(node, "date_added"); da != "" {
		if micros, err := parseInt64(da); err == nil {
			entry.DateAdded = chromeTimeToTime(micros)
		}
	}

	if entry.Type == "url" {
		entry.URL = getString(node, "url")
	} else if entry.Type == "folder" {
		if children, ok := node["children"].([]interface{}); ok {
			for _, c := range children {
				if m, ok := c.(map[string]interface{}); ok {
					entry.Children = append(entry.Children, parseNode(m))
				}
			}
		}
	}

	return entry
}

// Helpers to safely read JSON map
func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func parseInt64(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscan(s, &v)
	return v, err
}

func chromeTimeToTime(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	unixMicros := v - chromeEpochOffsetMicros
	secs := unixMicros / 1_000_000
	nsec := (unixMicros % 1_000_000) * 1000
	return time.Unix(secs, nsec).UTC()
}
