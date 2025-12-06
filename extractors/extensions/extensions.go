package extensions

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Extension struct {
	Name string `json:"name"`
}

type Manifest struct {
	Name string `json:"name"`
}

type ExtSetting struct {
	Manifest *Manifest `json:"manifest"`
}

type Preferences struct {
	Extensions struct {
		Settings map[string]ExtSetting `json:"settings"`
	} `json:"extensions"`
}

// list of built-in / system extensions we want to filter out
var systemExts = []string{
	"Web Store",
	"Chrome Web Store Payments",
	"Chrome PDF Viewer",
	"Google Network Speech",
	"Google Hangouts",
	"Google Docs Offline",
	"Microsoft Store",
	"Microsoft Voices",
	"Microsoft Edge PDF Viewer",
	"WebRTC Extension",
	"WebRTC Internals Extension",
	"Microsoft Clipboard Extension",
	"Media Internals Services Extension",
	"Edge relevant text changes",
	"Suppress Consent Prompt",
	"Edge Feedback",
}

func isSystemExtension(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, sys := range systemExts {
		if n == strings.ToLower(sys) {
			return true
		}
	}
	return false
}

func parseExtensions(prefPath string) ([]Extension, error) {
	f, err := os.ReadFile(prefPath)
	if err != nil {
		return nil, err
	}
	var prefs Preferences
	if err := json.Unmarshal(f, &prefs); err != nil {
		return nil, err
	}

	var exts []Extension
	for _, v := range prefs.Extensions.Settings {
		if v.Manifest != nil && v.Manifest.Name != "" {
			if !isSystemExtension(v.Manifest.Name) {
				exts = append(exts, Extension{Name: v.Manifest.Name})
			}
		}
	}
	return exts, nil
}

func scanBrowser3(basePath, browser string, output map[string]map[string][]Extension) {
	output[browser] = make(map[string][]Extension)

	entries, _ := os.ReadDir(basePath)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profile := entry.Name()
		prefPath := filepath.Join(basePath, profile, "Secure Preferences")
		if _, err := os.Stat(prefPath); err == nil {
			exts, err := parseExtensions(prefPath)
			if err == nil && len(exts) > 0 {
				output[browser][profile] = exts
			}
		}
	}
}

func Run() {
	home, _ := os.UserHomeDir()

	// Windows paths (adjust if Linux/macOS)
	chromePath := filepath.Join(home, "AppData", "Local", "Google", "Chrome", "User Data")
	edgePath := filepath.Join(home, "AppData", "Local", "Microsoft", "Edge", "User Data")
	bravePath := filepath.Join(home, "AppData", "Local", "BraveSoftware", "Brave-Browser", "User Data")

	output := make(map[string]map[string][]Extension)

	scanBrowser3(chromePath, "Chrome", output)
	scanBrowser3(edgePath, "Edge", output)
	scanBrowser3(bravePath, "Brave", output)

	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results", "chromium")
	os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, "chromium_extensions.json")

	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		fmt.Println("Error writing JSON:", err)
	}
	fmt.Println("Saved", outputPath)
}
