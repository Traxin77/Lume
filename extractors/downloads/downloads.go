//go:build windows
// +build windows

package downloads

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
)

const (
	chromeEpochOffsetMicros = int64(11644473600000000) // microseconds between 1601 and 1970
)

type DownloadEntry struct {
	TargetPath string    `json:"target_path"`
	URL        string    `json:"url"`
	StartTime  time.Time `json:"start_time"`
	ReceivedBytes int64  `json:"received_bytes"`
	TotalBytes    int64  `json:"total_bytes"`
	State      int       `json:"state"` // 0=in progress, 1=complete, etc.
}

type BrowserDownloads map[string]map[string][]DownloadEntry

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

	result := BrowserDownloads{}

	for base, browserName := range candidates {
		if stat, err := os.Stat(base); err == nil && stat.IsDir() {
			profiles, _ := os.ReadDir(base)
			for _, p := range profiles {
				if !p.IsDir() {
					continue
				}
				profilePath := filepath.Join(base, p.Name())
				historyPath := filepath.Join(profilePath, "History")
				if exists(historyPath) {
					entries, err := extractDownloads(historyPath)
					if err != nil {
						log.Printf("warning: failed to extract %s: %v", historyPath, err)
						continue
					}
					// sort by StartTime (newest first)
					sort.Slice(entries, func(i, j int) bool {
						return entries[i].StartTime.After(entries[j].StartTime)
					})
					if _, ok := result[browserName]; !ok {
						result[browserName] = map[string][]DownloadEntry{}
					}
					result[browserName][p.Name()] = entries
				}
			}
		}
	}

	if len(result) == 0 {
		log.Println("no chromium download history found.")
		os.Exit(1)
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)

	outputFile := filepath.Join(resultsDir, "chromium_download_history.json")
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
	fmt.Printf("Download history exported to %s\n", outputFile)
}

// --- helpers ---

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func extractDownloads(historyPath string) ([]DownloadEntry, error) {
	src, err := openFileShared(historyPath)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	tmp, err := os.CreateTemp("", "downloads-*.db")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		_ = os.Remove(tmpName)
	}()
	if _, err := io.Copy(tmp, src); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", tmpName)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	// downloads table schema: id, target_path, start_time, received_bytes, total_bytes, state
	rows, err := db.Query(`SELECT target_path, start_time, received_bytes, total_bytes, state FROM downloads`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []DownloadEntry
	for rows.Next() {
		var path string
		var startTime int64
		var received, total int64
		var state int
		if err := rows.Scan(&path, &startTime, &received, &total, &state); err != nil {
			continue
		}

		// Get URL from downloads_url_chains table (may be multiple, take first)
		var url string
		db.QueryRow(`SELECT url FROM downloads_url_chains WHERE id=(SELECT id FROM downloads WHERE target_path=? LIMIT 1) LIMIT 1`, path).Scan(&url)

		entries = append(entries, DownloadEntry{
			TargetPath:    path,
			URL:           url,
			StartTime:     chromeTimeToTime(startTime),
			ReceivedBytes: received,
			TotalBytes:    total,
			State:         state,
		})
	}
	return entries, nil
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

///////////////////////////////////////////////////////////
// Windows-specific shared open helper using CreateFile
///////////////////////////////////////////////////////////

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procCreateFileW  = kernel32.NewProc("CreateFileW")
	procCloseHandle  = kernel32.NewProc("CloseHandle")
	FILE_ATTRIBUTE_NORMAL         = uint32(0x80)
	OPEN_EXISTING                 = uint32(3)
	FILE_SHARE_READ   uintptr     = 0x00000001
	FILE_SHARE_WRITE  uintptr     = 0x00000002
	FILE_SHARE_DELETE uintptr     = 0x00000004
	GENERIC_READ      uintptr     = 0x80000000
)

func openFileShared(path string) (*os.File, error) {
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, _, callErr := procCreateFileW.Call(
		uintptr(unsafe.Pointer(pathp)),
		uintptr(GENERIC_READ),
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
		uintptr(0),
		uintptr(OPEN_EXISTING),
		uintptr(FILE_ATTRIBUTE_NORMAL),
		uintptr(0),
	)
	if handle == uintptr(syscall.InvalidHandle) || handle == 0 {
		return nil, callErr
	}
	f := os.NewFile(handle, path)
	if f == nil {
		procCloseHandle.Call(handle)
		return nil, fmt.Errorf("os.NewFile returned nil")
	}
	return f, nil
}
