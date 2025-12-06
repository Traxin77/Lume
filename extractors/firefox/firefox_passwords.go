//go:build windows
// +build windows

package firefox

/*
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>

typedef int PRBool;
typedef int SECStatus;
typedef enum {
    siBuffer = 0
} SECItemType;

typedef struct {
    SECItemType type;
    unsigned char *data;
    unsigned int len;
} SECItem;

typedef struct PK11SlotInfoStr PK11SlotInfo;

#define SECSuccess 0
#define SECFailure -1
#define PR_TRUE 1
#define PR_FALSE 0

// Helper functions implemented in cookies.go
SECStatus my_NSS_Init(const char *configdir);
SECStatus my_NSS_Shutdown(void);
PK11SlotInfo* my_PK11_GetInternalKeySlot(void);
void my_PK11_FreeSlot(PK11SlotInfo *slot);
PRBool my_PK11_NeedLogin(PK11SlotInfo *slot);
SECStatus my_PK11_CheckUserPassword(PK11SlotInfo *slot, const char *password);
SECStatus my_PK11SDR_Decrypt(SECItem *data, SECItem *result, void *cx);
void my_SECITEM_ZfreeItem(SECItem *item, PRBool freeit);
int my_PORT_GetError(void);
*/
import "C"

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

// Global logger for this extractor (also used by cookies.go)
var logger *log.Logger

// PasswordStore holds decrypted credentials
type PasswordStore []map[string]string

// NSSWrapper provides a cleaner interface to NSS operations
type NSSWrapper struct {
	nonFatalDecryption bool
	initialized        bool
	mutex              sync.Mutex
}

// Initializef uses "sql:<profile>" which is recommended for modern Firefox (key4.db)
func (n *NSSWrapper) Initializef(profile string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.initialized {
		return fmt.Errorf("NSS already initialized")
	}

	profilePath := C.CString("sql:" + profile)
	defer C.free(unsafe.Pointer(profilePath))

	logger.Printf("Initializing NSS with profile: %s", profile)

	errStatus := C.my_NSS_Init(profilePath)
	if errStatus != C.SECSuccess {
		return fmt.Errorf("NSS_Init failed with status %d", errStatus)
	}

	n.initialized = true
	logger.Printf("NSS initialized successfully")
	return nil
}

func (n *NSSWrapper) Shutdown() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if !n.initialized {
		return nil
	}

	errStatus := C.my_NSS_Shutdown()
	if errStatus != C.SECSuccess {
		logger.Printf("NSS_Shutdown failed with status %d", errStatus)
	}

	n.initialized = false
	logger.Printf("NSS shutdown completed")
	return nil
}

func (n *NSSWrapper) Authenticatef(profile string, interactive bool) error {
	if !n.initialized {
		return fmt.Errorf("NSS not initialized")
	}

	logger.Printf("Getting internal key slot...")

	keyslot := C.my_PK11_GetInternalKeySlot()
	if keyslot == nil {
		return fmt.Errorf("failed to get internal key slot")
	}
	defer C.my_PK11_FreeSlot(keyslot)

	needLogin := C.my_PK11_NeedLogin(keyslot)
	if needLogin == C.PR_TRUE {
		password := askPassword(profile, interactive)

		logger.Printf("Authenticating with password...")

		cPassword := C.CString(password)
		defer C.free(unsafe.Pointer(cPassword))

		errStatus := C.my_PK11_CheckUserPassword(keyslot, cPassword)
		if errStatus != C.SECSuccess {
			return fmt.Errorf("primary password incorrect")
		}

		logger.Printf("Authentication successful")
	} else {
		logger.Printf("No primary password required")
	}

	return nil
}

func (n *NSSWrapper) Decryptf(base64Data string) (string, error) {
	if !n.initialized {
		return "", fmt.Errorf("NSS not initialized")
	}

	// Decode base64 data
	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	// Create input SECItem
	var inp C.SECItem
	inp._type = C.siBuffer
	inp.data = (*C.uchar)(C.CBytes(data))
	inp.len = C.uint(len(data))
	defer C.free(unsafe.Pointer(inp.data))

	// Create output SECItem
	var out C.SECItem
	out._type = C.siBuffer
	out.data = nil
	out.len = 0

	// Decrypt
	errStatus := C.my_PK11SDR_Decrypt(&inp, &out, nil)
	if errStatus != C.SECSuccess {
		if n.nonFatalDecryption {
			return "", fmt.Errorf("decryption failed")
		}
		errCode := C.my_PORT_GetError()
		return "", fmt.Errorf("decryption failed with status %d, error code %d", errStatus, errCode)
	}

	// Extract result
	result := C.GoStringN((*C.char)(unsafe.Pointer(out.data)), C.int(out.len))

	// Clean up
	C.my_SECITEM_ZfreeItem(&out, C.PR_FALSE)

	return result, nil
}

// FirefoxDecryptor is the main helper struct
type FirefoxDecryptor struct {
	profile string
	nss     *NSSWrapper
}

func NewFirefoxDecryptor(nonFatalDecryption bool) *FirefoxDecryptor {
	return &FirefoxDecryptor{
		nss: NewNSSWrapper(nonFatalDecryption),
	}
}

func (f *FirefoxDecryptor) LoadProfile(profile string) error {
	f.profile = profile
	return f.nss.Initializef(profile)
}

func (f *FirefoxDecryptor) Authenticate(interactive bool) error {
	return f.nss.Authenticatef(f.profile, interactive)
}

func (f *FirefoxDecryptor) Shutdown() error {
	return f.nss.Shutdown()
}

func (f *FirefoxDecryptor) FindCredentials() (PasswordStore, error) {
	logger.Printf("Searching for credentials in profile: %s", f.profile)

	// Candidate in profile root
	jsonPath := filepath.Join(f.profile, "logins.json")
	logger.Printf("Checking: %s", jsonPath)
	if fi, err := os.Stat(jsonPath); err == nil && !fi.IsDir() {
		logger.Printf("Found JSON credentials file: %s", jsonPath)
		return f.parseJSONCredentials(jsonPath)
	} else if err != nil && !os.IsNotExist(err) {
		logger.Printf("Stat error for %s: %v", jsonPath, err)
	}

	// Candidate SQLite (older)
	sqlitePath := filepath.Join(f.profile, "signons.sqlite")
	logger.Printf("Checking: %s", sqlitePath)
	if fi, err := os.Stat(sqlitePath); err == nil && !fi.IsDir() {
		logger.Printf("Found SQLite credentials file: %s", sqlitePath)
		return f.parseSQLiteCredentials(sqlitePath)
	} else if err != nil && !os.IsNotExist(err) {
		logger.Printf("Stat error for %s: %v", sqlitePath, err)
	}

	// If not found in root, do a shallow recursive search (depth limited)
	logger.Printf("Did not find credentials in profile root; walking profile directory (depth 3) to search for logins.json / signons.sqlite")

	var foundJSON, foundSQLite string
	maxDepth := 3
	baseDepth := len(strings.Split(filepath.Clean(f.profile), string(os.PathSeparator)))

	_ = filepath.Walk(f.profile, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// ignore permissions or other errors but log them
			logger.Printf("Walk error: %v (path: %s)", err, path)
			return nil
		}
		if info.IsDir() {
			// check depth
			relDepth := len(strings.Split(filepath.Clean(path), string(os.PathSeparator))) - baseDepth
			if relDepth > maxDepth {
				return filepath.SkipDir
			}
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		if base == "logins.json" && foundJSON == "" {
			foundJSON = path
			logger.Printf("Located logins.json at: %s", path)
			return nil
		}
		if base == "signons.sqlite" && foundSQLite == "" {
			foundSQLite = path
			logger.Printf("Located signons.sqlite at: %s", path)
			return nil
		}
		return nil
	})

	if foundJSON != "" {
		return f.parseJSONCredentials(foundJSON)
	}
	if foundSQLite != "" {
		return f.parseSQLiteCredentials(foundSQLite)
	}

	// Nothing found
	logger.Printf("Directory listing for profile root (%s):", f.profile)
	entries, err := os.ReadDir(f.profile)
	if err == nil {
		for _, e := range entries {
			info, _ := e.Info()
			logger.Printf(" - %s (dir=%v size=%d)", e.Name(), e.IsDir(), info.Size())
		}
	} else {
		logger.Printf(" failed to list profile root: %v", err)
	}

	return nil, fmt.Errorf("no credentials file found (logins.json or signons.sqlite)")
}

func (f *FirefoxDecryptor) parseJSONCredentials(path string) (PasswordStore, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open logins.json: %v", err)
	}
	defer file.Close()

	var data struct {
		Logins []struct {
			Hostname          string `json:"hostname"`
			EncryptedUsername string `json:"encryptedUsername"`
			EncryptedPassword string `json:"encryptedPassword"`
			EncType           int    `json:"encType"`
		} `json:"logins"`
	}

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse logins.json: %v", err)
	}

	var credentials PasswordStore

	for _, login := range data.Logins {
		if login.EncType != 0 {
			// Decrypt username and password
			username, err := f.nss.Decryptf(login.EncryptedUsername)
			if err != nil {
				if f.nss.nonFatalDecryption {
					logger.Printf("Failed to decrypt username for %s: %v", login.Hostname, err)
					continue
				}
				return nil, fmt.Errorf("failed to decrypt username: %v", err)
			}

			password, err := f.nss.Decryptf(login.EncryptedPassword)
			if err != nil {
				if f.nss.nonFatalDecryption {
					logger.Printf("Failed to decrypt password for %s: %v", login.Hostname, err)
					continue
				}
				return nil, fmt.Errorf("failed to decrypt password: %v", err)
			}

			credentials = append(credentials, map[string]string{
				"url":      login.Hostname,
				"user":     username,
				"password": password,
			})
		} else {
			// Not encrypted
			credentials = append(credentials, map[string]string{
				"url":      login.Hostname,
				"user":     login.EncryptedUsername,
				"password": login.EncryptedPassword,
			})
		}
	}

	return credentials, nil
}

func (f *FirefoxDecryptor) parseSQLiteCredentials(path string) (PasswordStore, error) {
	// Not implemented for now
	logger.Printf("SQLite credentials parsing not implemented (path: %s)", path)
	return PasswordStore{}, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func findProfilePath(basepath string, interactive bool, choice string, list bool) (string, error) {
	// If basepath itself already looks like a profile (has logins.json), just use it.
	if fi, err := os.Stat(basepath); err == nil && fi.IsDir() {
		if fileExists(filepath.Join(basepath, "logins.json")) ||
			fileExists(filepath.Join(basepath, "logins.db")) {
			logger.Printf("Treating %s as a direct profile directory", basepath)
			return basepath, nil
		}
	}

	profilesRoot := filepath.Join(basepath, "Profiles")
	fi, err := os.Stat(profilesRoot)
	if err != nil || !fi.IsDir() {
		// Fallback: assume basepath is already a profile directory
		logger.Printf("Profiles directory not found, assuming %s is a profile directory", basepath)
		if _, err := os.Stat(basepath); err != nil {
			return "", fmt.Errorf("profile directory does not exist: %s", basepath)
		}
		return basepath, nil
	}

	type prof struct {
		Name string
		Path string
	}

	entries, err := os.ReadDir(profilesRoot)
	if err != nil {
		return "", fmt.Errorf("failed to read Profiles directory: %v", err)
	}

	var profiles []prof
	for _, e := range entries {
		if e.IsDir() {
			p := prof{
				Name: e.Name(),
				Path: filepath.Join(profilesRoot, e.Name()),
			}
			profiles = append(profiles, p)
		}
	}

	if len(profiles) == 0 {
		return "", fmt.Errorf("no profiles found in %s", profilesRoot)
	}

	// Choose profile based on -choice (index or name)
	var selected *prof
	if choice != "" {
		if idx, err := strconv.Atoi(choice); err == nil {
			// Numeric index (1-based)
			idx--
			if idx >= 0 && idx < len(profiles) {
				selected = &profiles[idx]
			} else {
				return "", fmt.Errorf("no such profile index: %s", choice)
			}
		} else {
			// Match by folder name (case-insensitive)
			for i := range profiles {
				if strings.EqualFold(profiles[i].Name, choice) {
					selected = &profiles[i]
					break
				}
			}
			if selected == nil {
				return "", fmt.Errorf("no such profile name: %s", choice)
			}
		}
	}

	// If still nil, prefer profiles that actually have credential files.
	if selected == nil {
		// 1) Prefer logins.json + key4.db
		for i := range profiles {
			p := profiles[i].Path
			if fileExists(filepath.Join(p, "logins.json")) &&
				fileExists(filepath.Join(p, "key4.db")) {
				selected = &profiles[i]
				break
			}
		}
	}

	if selected == nil {
		// 2) Then prefer logins.db + key4.db
		for i := range profiles {
			p := profiles[i].Path
			if fileExists(filepath.Join(p, "logins.db")) &&
				fileExists(filepath.Join(p, "key4.db")) {
				selected = &profiles[i]
				break
			}
		}
	}

	// 3) Final fallback: first profile
	if selected == nil {
		selected = &profiles[0]
	}

	// Sanity check
	if fi, err := os.Stat(selected.Path); err != nil || !fi.IsDir() {
		return "", fmt.Errorf("profile path is not a directory or missing: %s", selected.Path)
	}

	logger.Printf("Selected profile '%s' at %s", selected.Name, selected.Path)
	return selected.Path, nil
}

func expandPath(path string) (string, error) {
	if strings.HasPrefix(path, "~") {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		return filepath.Join(usr.HomeDir, path[1:]), nil
	}
	return path, nil
}

// RunPasswords is the entry point used by cmd/main.go
func RunPasswords() {
	// Basic logger (stderr)
	logger = log.New(os.Stderr, "", log.LstdFlags)

	logger.Printf("Operating System: %s", runtime.GOOS)
	logger.Printf("Architecture: %s", runtime.GOARCH)

	// Load NSS library (shared implementation in cookies.go)
	logger.Printf("Loading NSS library...")
	if err := LoadNSSLibrary(""); err != nil {
		fmt.Fprintln(os.Stderr, "failed to load NSS library:", err)
		return
	}
	defer UnloadNSSLibrary()
	logger.Printf("NSS library loaded successfully")

	// Determine default Firefox profile base path
	var profileBase string
	switch runtime.GOOS {
	case "windows":
		profileBase = filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox")
	case "darwin":
		profileBase = "~/Library/Application Support/Firefox"
	default:
		profileBase = "~/.mozilla/firefox"
	}

	// Expand profile path
	profilePath, err := expandPath(profileBase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to expand profile path:", err)
		return
	}

	// Find actual profile
	profile, err := findProfilePath(profilePath, true, "", false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to find Firefox profile:", err)
		return
	}

	logger.Printf("Using profile: %s", profile)

	// Initialize decryptor
	decryptor := NewFirefoxDecryptor(false)

	// Load profile
	if err := decryptor.LoadProfile(profile); err != nil {
		fmt.Fprintln(os.Stderr, "failed to load Firefox profile:", err)
		return
	}
	defer decryptor.Shutdown()

	// Authenticate (interactive = true so master password prompt works if needed)
	if err := decryptor.Authenticate(true); err != nil {
		fmt.Fprintln(os.Stderr, "authentication failed:", err)
		return
	}

	// Find and decrypt credentials
	creds, err := decryptor.FindCredentials()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to find credentials:", err)
		return
	}

	if len(creds) == 0 {
		logger.Printf("No passwords found in profile")
		return
	}

	logger.Printf("Found %d password entries", len(creds))

	// Write to JSON file within ./results/firefox/
	outPath := filepath.Join("results", "firefox", "firefox_passwords.json")
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "failed to create results directory:", err)
		return
	}

	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to create output file:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(creds); err != nil {
		fmt.Fprintln(os.Stderr, "failed to encode credentials to JSON:", err)
		return
	}

	fmt.Printf("Successfully extracted %d Firefox credentials\n", len(creds))
	fmt.Println("Saved:", outPath)
}
