package packager

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	scryptN        = 1 << 15 // 32768
	scryptR        = 8
	scryptP        = 1
	scryptKeyLen   = 32
	aesGCMNonceLen = 12
	saltLen        = 32
)

// FileEntry represents metadata for a single file in the manifest
type FileEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	MTime  string `json:"mtime"`
}

// KDFParams stores key derivation function parameters
type KDFParams struct {
	Name    string `json:"name"`
	N       int    `json:"N"`
	R       int    `json:"r"`
	P       int    `json:"p"`
	SaltHex string `json:"salt_hex"`
}

// Manifest represents the evidence bundle manifest (NO bundle hash inside)
type Manifest struct {
	CaseName            string      `json:"case_name"`
	CaseID              string      `json:"case_id"`
	Investigator        string      `json:"investigator"`
	CreatedUTC          string      `json:"created_utc"`
	CreatedUTCReadable  string      `json:"created_utc_readable"`
	SystemLocal         string      `json:"system_local"`
	SystemLocalReadable string      `json:"system_local_readable"`
	KDF                 KDFParams   `json:"kdf"`
	Files               []FileEntry `json:"files"`
}

// sanitizeBaseName returns a filesystem-safe short base name from user input
func sanitizeBaseName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// replace spaces with underscore, remove path separators and other unsafe chars
	re := regexp.MustCompile(`[^\w\-\.]`)
	s = strings.ReplaceAll(s, " ", "_")
	s = re.ReplaceAllString(s, "")
	// truncate to reasonable length
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

// PackageResults: updated to use user-provided basename and skip encrypted-bundle hash file
// outBase is a short name provided by user (e.g. "case_ACME_001" or "acme_001"), not a full path.
// If outBase is empty, a timestamped name is used (as before).
func PackageResults(resultsDir, outBase, caseName, caseID, investigator, password string, pubKeyPaths []string) error {
	// Validate inputs
	if resultsDir == "" {
		return fmt.Errorf("resultsDir cannot be empty")
	}
	if password == "" {
		return fmt.Errorf("password is required for bundle encryption")
	}

	// Create staging directory
	stagingDir, err := os.MkdirTemp("", "lume-package-*")
	if err != nil {
		return fmt.Errorf("failed to create staging directory: %w", err)
	}
	defer func() {
		// Cleanup on success, leave for debugging on error
		if err == nil {
			os.RemoveAll(stagingDir)
		}
	}()

	if err := os.Chmod(stagingDir, 0700); err != nil {
		return fmt.Errorf("failed to set staging dir permissions: %w", err)
	}

	// Generate timestamps with human-readable format
	now := time.Now()
	createdUTC := now.UTC().Format("2006-01-02 15:04:05 MST")
	systemLocal := now.Format("2006-01-02 15:04:05 MST")

	// Generate KDF salt
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	manifest := Manifest{
		CaseName:            caseName,
		CaseID:              caseID,
		Investigator:        investigator,
		CreatedUTC:          createdUTC,
		SystemLocal:         systemLocal,
		KDF: KDFParams{
			Name:    "scrypt",
			N:       scryptN,
			R:       scryptR,
			P:       scryptP,
			SaltHex: hex.EncodeToString(salt),
		},
		Files: []FileEntry{},
	}

	// Determine base output name
	base := sanitizeBaseName(outBase)
	if base == "" {
		base = fmt.Sprintf("lume_%s", time.Now().Format("20060102_150405"))
	}

	// Output directory
	outDir := "artifacts"
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create artifacts directory: %w", err)
	}

	// Construct output paths using base (short names)
	outEncPath := filepath.Join(outDir, fmt.Sprintf("%s.tar.enc", base))
	plainHashPath := filepath.Join(outDir, fmt.Sprintf("%s.plain.sha256", base))

	// Step 1: Create manifest JSON and save to staging
	fmt.Println("\n[1/5] Creating manifest with file metadata...")
	manifestJSON, err := collectFileMetadata(resultsDir, &manifest)
	if err != nil {
		return fmt.Errorf("failed to collect file metadata: %w", err)
	}

	// Write manifest to staging (will be included in tar)
	manifestPlainPath := filepath.Join(stagingDir, "MANIFEST.json")
	if err := os.WriteFile(manifestPlainPath, manifestJSON, 0600); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Step 2: Encrypt manifest
	fmt.Println("[2/5] Encrypting manifest...")
	manifestEncPath := filepath.Join(stagingDir, "MANIFEST.json.enc")
	manifestKeyPath := filepath.Join(stagingDir, "MANIFEST.key.info")
	if err := encryptManifest(manifestJSON, manifestEncPath, manifestKeyPath); err != nil {
		return fmt.Errorf("failed to encrypt manifest: %w", err)
	}

	// Step 3: Create tar with results/ + MANIFEST.json.enc + key info
	fmt.Println("[3/5] Creating and hashing bundle (plaintext tar)...")
	tarPath := filepath.Join(stagingDir, "bundle.tar.gz")
	plainTarHash, err := createTarBundle(resultsDir, tarPath, manifestEncPath, manifestKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create tar: %w", err)
	}

	// Step 4: Encrypt tar bundle (write final <base>.tar.enc with embedded salt)
	fmt.Println("[4/5] Encrypting evidence bundle...")
	if err := encryptBundle(tarPath, outEncPath, password, salt); err != nil {
		return fmt.Errorf("failed to encrypt bundle: %w", err)
	}

	// Step 5: Create companion plaintext tar hash only (no encrypted-bundle hash)
	fmt.Println("[5/5] Writing plaintext TAR hash (for custody verification)...")

	if err := os.WriteFile(plainHashPath, []byte(plainTarHash+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write plaintext hash: %w", err)
	}

	// Display results (short names)
	fmt.Println("\n=== Evidence Bundle Created ===")
	fmt.Printf("Encrypted Bundle:      %s\n", outEncPath)
	fmt.Printf("Plaintext Bundle Hash: %s (store this securely and sign it externally)\n", plainHashPath)
	fmt.Println("\nBundle Contents:")
	fmt.Println("  - results/ (all extracted files)")
	fmt.Println("  - MANIFEST.json.enc (encrypted manifest)")
	fmt.Println("  - MANIFEST.key.info (manifest decryption key info)")
	fmt.Println("\n⚠️  IMPORTANT: Store the plaintext tar hash in a secure, append-only vault and create a detached signature.")
	fmt.Println("   Example (external):")
	fmt.Printf("   gpg --detach-sign --armor %s\n", plainHashPath)
	fmt.Println("\n✓ Chain of custody preserved")

	return nil
}

// collectFileMetadata walks the results directory and collects file metadata
func collectFileMetadata(resultsDir string, manifest *Manifest) ([]byte, error) {
	err := filepath.Walk(resultsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Compute relative path
		relPath, err := filepath.Rel(resultsDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(filepath.Join("results", relPath))

		// Compute file hash
		fileHash, err := computeFileHash(path)
		if err != nil {
			return err
		}

		// Add file entry to manifest
		manifest.Files = append(manifest.Files, FileEntry{
			Path:   relPath,
			SHA256: fileHash,
			Size:   info.Size(),
			MTime:  info.ModTime().UTC().Format(time.RFC3339),
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Marshal manifest to JSON
	return json.MarshalIndent(manifest, "", "  ")
}

// createTarBundle creates a tar.gz archive containing results/ and encrypted manifest
func createTarBundle(resultsDir, tarPath, manifestEncPath, manifestKeyPath string) (string, error) {
	tarFile, err := os.OpenFile(tarPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", err
	}
	defer tarFile.Close()

	// Create hash writer for plaintext tar
	tarHasher := sha256.New()
	multiWriter := io.MultiWriter(tarFile, tarHasher)

	// Create gzip writer
	gzipWriter := gzip.NewWriter(multiWriter)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	// Add all files from results/
	err = filepath.Walk(resultsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Compute relative path
		relPath, err := filepath.Rel(resultsDir, path)
		if err != nil {
			return err
		}
		relPath = filepath.ToSlash(filepath.Join("results", relPath))

		// Create tar header
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relPath

		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}

		// Copy file content to tar
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		if _, err := io.Copy(tarWriter, file); err != nil {
			return err
		}

		return nil
	})

	if err != nil {
		return "", err
	}

	// Add MANIFEST.json.enc to tar root
	if err := addFileToTar(tarWriter, manifestEncPath, "MANIFEST.json.enc"); err != nil {
		return "", err
	}

	// Add MANIFEST.key.info to tar root
	if err := addFileToTar(tarWriter, manifestKeyPath, "MANIFEST.key.info"); err != nil {
		return "", err
	}

	// Close writers to flush
	if err := tarWriter.Close(); err != nil {
		return "", err
	}
	if err := gzipWriter.Close(); err != nil {
		return "", err
	}

	tarHash := hex.EncodeToString(tarHasher.Sum(nil))

	return tarHash, nil
}

// addFileToTar adds a file to the tar archive with the specified name
func addFileToTar(tarWriter *tar.Writer, filePath, tarName string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = tarName

	if err := tarWriter.WriteHeader(header); err != nil {
		return err
	}

	if _, err := io.Copy(tarWriter, file); err != nil {
		return err
	}

	return nil
}

// encryptManifest encrypts the manifest using AES-256-GCM
func encryptManifest(manifestJSON []byte, encPath, keyPath string) error {
	// Generate random AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return err
	}

	// Encrypt manifest
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, manifestJSON, nil)

	if err := os.WriteFile(encPath, ciphertext, 0600); err != nil {
		return err
	}

	// Save key info (in production, wrap with recipient public keys)
	keyInfo := map[string]string{
		"algorithm": "AES-256-GCM",
		"key_hex":   hex.EncodeToString(aesKey),
		"note":      "In production, wrap this key with recipient OpenPGP public keys",
	}

	keyJSON, err := json.MarshalIndent(keyInfo, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(keyPath, keyJSON, 0600)
}

// encryptBundle encrypts the tar bundle using password-based encryption
// File format: [32 bytes salt][12 bytes nonce][encrypted data]
func encryptBundle(tarPath, outPath, password string, salt []byte) error {
	// Derive key from password
	key, err := scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, scryptKeyLen)
	if err != nil {
		return err
	}

	// Open input tar
	inFile, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer inFile.Close()

	// Create output encrypted file
	outFile, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer outFile.Close()

	// Create AES-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}

	// Write salt first (32 bytes)
	if _, err := outFile.Write(salt); err != nil {
		return err
	}

	// Write nonce (12 bytes)
	if _, err := outFile.Write(nonce); err != nil {
		return err
	}

	// Read entire tar into memory (for smaller files)
	// For very large files, implement chunked AEAD
	plaintext, err := io.ReadAll(inFile)
	if err != nil {
		return err
	}

	// Encrypt
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Write encrypted data
	_, err = outFile.Write(ciphertext)
	return err
}

// computeFileHash computes SHA-256 hash of a file
func computeFileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, bufio.NewReader(file)); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}