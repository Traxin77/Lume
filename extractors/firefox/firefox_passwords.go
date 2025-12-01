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
typedef enum { siBuffer = 0 } SECItemType;

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

static int try_from_dir(const char *base)
{
    char dll_path[MAX_PATH];
    DWORD err;

    snprintf(dll_path, MAX_PATH, "%s\\mozglue.dll", base);
    mozglue_dll = LoadLibraryA(dll_path);
    if (!mozglue_dll) {
        err = GetLastError();
        fprintf(stderr, "LoadLibraryA('%s') failed with error %lu\n", dll_path, err);
        return -1;
    }

    snprintf(dll_path, MAX_PATH, "%s\\nss3.dll", base);
    nss3_dll = LoadLibraryA(dll_path);
    if (!nss3_dll) {
        err = GetLastError();
        fprintf(stderr, "LoadLibraryA('%s') failed with error %lu\n", dll_path, err);
        FreeLibrary(mozglue_dll);
        mozglue_dll = NULL;
        return -1;
    }

    return 0;
}

static int load_nss_library(const char* firefox_path) {
    DWORD err;

    if (firefox_path && firefox_path[0] != '\0') {
        SetDllDirectoryA(firefox_path);
        if (try_from_dir(firefox_path) == 0) {
            goto loaded_ok;
        }
    }

    if (!nss3_dll) {
        if (try_from_dir("C:\\Program Files\\Mozilla Firefox") == 0) {
            goto loaded_ok;
        }
    }

    if (!nss3_dll) {
        if (try_from_dir("C:\\Program Files (x86)\\Mozilla Firefox") == 0) {
            goto loaded_ok;
        }
    }

    if (!mozglue_dll) {
        mozglue_dll = LoadLibraryA("mozglue.dll");
        if (!mozglue_dll) {
            err = GetLastError();
            fprintf(stderr, "LoadLibraryA('mozglue.dll') failed with error %lu\n", err);
        }
    }
    if (!nss3_dll && mozglue_dll) {
        nss3_dll = LoadLibraryA("nss3.dll");
        if (!nss3_dll) {
            err = GetLastError();
            fprintf(stderr, "LoadLibraryA('nss3.dll') failed with error %lu\n", err);
        }
    }

    if (!nss3_dll) {
        return -1;
    }

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

    if (!NSS_Init_ptr || !NSS_Shutdown_ptr || !PK11_GetInternalKeySlot_ptr ||
        !PK11_FreeSlot_ptr || !PK11_NeedLogin_ptr || !PK11_CheckUserPassword_ptr ||
        !PK11SDR_Decrypt_ptr || !SECITEM_ZfreeItem_ptr || !PORT_GetError_ptr) {

        if (nss3_dll) {
            FreeLibrary(nss3_dll);
            nss3_dll = NULL;
        }
        if (mozglue_dll) {
            FreeLibrary(mozglue_dll);
            mozglue_dll = NULL;
        }
        return -2;
    }

    return 0;
}

static void unload_nss_library() {
    if (nss3_dll) {
        FreeLibrary(nss3_dll);
        nss3_dll = NULL;
    }
    if (mozglue_dll) {
        FreeLibrary(mozglue_dll);
        mozglue_dll = NULL;
    }
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
    if (PK11_FreeSlot_ptr) {
        PK11_FreeSlot_ptr(slot);
    }
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
    if (SECITEM_ZfreeItem_ptr) {
        SECITEM_ZfreeItem_ptr(item, freeit);
    }
}

static int my_PORT_GetError() {
    if (!PORT_GetError_ptr) return -1;
    return PORT_GetError_ptr();
}
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

type PasswordStore []map[string]string

var (
	logger  *log.Logger
	verbose = false
)

type NSSWrapper struct {
	nonFatalDecryption bool
	initialized        bool
	slot               *C.PK11SlotInfo // Track the key slot
	mutex              sync.Mutex
}

func (n *NSSWrapper) Shutdown() error {
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if !n.initialized {
		return nil
	}

	// CRITICAL: Free the slot BEFORE shutting down NSS
	// This is the most common cause of NSS_Shutdown failures
	if n.slot != nil {
		logger.Printf("Freeing PK11 slot before shutdown...")
		C.my_PK11_FreeSlot(n.slot)
		n.slot = nil
	}

	// Mark as not initialized BEFORE attempting shutdown
	n.initialized = false

	// Now attempt shutdown - should succeed with proper cleanup
	errStatus := C.my_NSS_Shutdown()
	
	if errStatus == C.SECSuccess {
		logger.Printf("NSS shutdown completed successfully")
		return nil
	}

	// If it still fails, get detailed error
	return nil
}

type FirefoxDecryptor struct {
	profile string
	nss     *NSSWrapper
}

func NewFirefoxDecryptor(nonFatal bool) *FirefoxDecryptor {
	return &FirefoxDecryptor{
		nss: &NSSWrapper{nonFatalDecryption: nonFatal},
	}
}

func (f *FirefoxDecryptor) LoadProfile(profile string) error {
	f.profile = profile
	return f.nss.Initialize(profile)
}

func (f *FirefoxDecryptor) Authenticate() error {
	return f.nss.Authenticate(f.profile, false)
}

func (f *FirefoxDecryptor) Shutdown() error {
	return f.nss.Shutdown()
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
			username, err := f.nss.Decrypt(login.EncryptedUsername)
			if err != nil {
				if f.nss.nonFatalDecryption {
					logger.Printf("Failed to decrypt username for %s: %v", login.Hostname, err)
					continue
				}
				return nil, fmt.Errorf("failed to decrypt username: %v", err)
			}

			password, err := f.nss.Decrypt(login.EncryptedPassword)
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
			credentials = append(credentials, map[string]string{
				"url":      login.Hostname,
				"user":     login.EncryptedUsername,
				"password": login.EncryptedPassword,
			})
		}
	}

	return credentials, nil
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
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

func findProfilePathSimple(basepath string) (string, error) {
	if fi, err := os.Stat(basepath); err == nil && fi.IsDir() {
		if fileExists(filepath.Join(basepath, "logins.json")) ||
			fileExists(filepath.Join(basepath, "logins.db")) {
			logger.Printf("Treating %s as a direct profile directory", basepath)
			return basepath, nil
		}
	}

	profilesRoot := filepath.Join(basepath, "Profiles")
	if fi, err := os.Stat(profilesRoot); err != nil || !fi.IsDir() {
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

	for i := range profiles {
		p := profiles[i].Path
		if fileExists(filepath.Join(p, "logins.json")) &&
			fileExists(filepath.Join(p, "key4.db")) {
			return p, nil
		}
	}

	for i := range profiles {
		p := profiles[i].Path
		if fileExists(filepath.Join(p, "logins.db")) &&
			fileExists(filepath.Join(p, "key4.db")) {
			return p, nil
		}
	}

	return profiles[0].Path, nil
}

func LoadNSSLibraryWrapper(firefoxPath string) error {
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

func UnloadNSSLibraryWrapper() {
	C.unload_nss_library()
}

func RunPasswords() {
	logger = log.New(os.Stderr, "", log.LstdFlags)

	var profileBase string
	switch runtime.GOOS {
	case "windows":
		profileBase = filepath.Join(os.Getenv("APPDATA"), "Mozilla", "Firefox")
	case "darwin":
		profileBase = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", "Firefox")
	default:
		profileBase = filepath.Join(os.Getenv("HOME"), ".mozilla", "firefox")
	}

	logger.Printf("Loading NSS library...")
	if err := LoadNSSLibraryWrapper(""); err != nil {
		fmt.Fprintln(os.Stderr, "failed to load NSS library:", err)
		return
	}
	defer UnloadNSSLibraryWrapper()
	logger.Printf("NSS loaded")

	profilePath, err := expandPath(profileBase)
	if err != nil {
		fmt.Fprintln(os.Stderr, "expand profile path failed:", err)
		return
	}
	profile, err := findProfilePathSimple(profilePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "find profile failed:", err)
		return
	}
	logger.Printf("Using profile: %s", profile)

	decryptor := NewFirefoxDecryptor(false)

	if err := decryptor.LoadProfile(profile); err != nil {
		fmt.Fprintln(os.Stderr, "LoadProfile failed:", err)
		return
	}
	
	// Ensure shutdown is called even if authentication fails
	defer func() {
		if err := decryptor.Shutdown(); err != nil {
			logger.Printf("Shutdown error: %v", err)
		}
	}()

	if err := decryptor.Authenticate(); err != nil {
		fmt.Fprintln(os.Stderr, "Authenticate failed:", err)
		return
	}

	jsonPath := filepath.Join(profile, "logins.json")
	if fileExists(jsonPath) {
		creds, err := decryptor.parseJSONCredentials(jsonPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "parseJSONCredentials failed:", err)
			return
		}
		
		outPath := filepath.Join("results", "firefox_passwords.json")
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir failed:", err)
			return
		}
		f, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create output failed:", err)
			return
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(creds); err != nil {
			fmt.Fprintln(os.Stderr, "encode failed:", err)
			_ = f.Close()
			return
		}
		_ = f.Close()
		fmt.Println("Saved:", outPath)
		return
	}

	fmt.Fprintln(os.Stderr, "logins.json not found; sqlite parsing is not implemented in this extractor")
}