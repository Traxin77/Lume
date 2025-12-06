package mail

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

type Profile struct {
	Browser     string `json:"browser"`
	ProfileDir  string `json:"profile_dir"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

type InfoCacheEntry struct {
	Name     string `json:"name"`
	UserName string `json:"user_name"`
}

type LocalState struct {
	Profile struct {
		InfoCache map[string]InfoCacheEntry `json:"info_cache"`
	} `json:"profile"`
}

func Run() {
	browser := flag.String("browser", "all", "Browser to scan: chrome, edge, or all")
	output := flag.String("output", "chromium_profiles.json", "Output JSON file name (stored in results/)")
	flag.Parse()

	var profiles []Profile

	switch *browser {
	case "all":
		profiles = append(profiles, scanBrowser2("chrome")...)
		profiles = append(profiles, scanBrowser2("edge")...)
	case "chrome":
		profiles = append(profiles, scanBrowser2("chrome")...)
	case "edge":
		profiles = append(profiles, scanBrowser2("edge")...)
	default:
		log.Fatalf("Unsupported browser: %s. Use chrome, edge, or all.", *browser)
	}

	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Store relative to executable
	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results", "chromium")
	os.MkdirAll(resultsDir, 0755)
	outputPath := filepath.Join(resultsDir, *output)

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}

	fmt.Printf("Extracted %d profiles to %s\n", len(profiles), outputPath)
}


func scanBrowser2(browserName string) []Profile {
	browserPath := getBrowserPath(browserName)
	if browserPath == "" {
		log.Printf("Could not determine path for %s", browserName)
		return nil
	}

	localStatePath := filepath.Join(browserPath, "Local State")
	data, err := os.ReadFile(localStatePath)
	if err != nil {
		log.Printf("Failed to read Local State for %s: %v", browserName, err)
		return nil
	}

	var ls LocalState
	if err := json.Unmarshal(data, &ls); err != nil {
		log.Printf("Failed to unmarshal Local State for %s: %v", browserName, err)
		return nil
	}

	entries, err := os.ReadDir(browserPath)
	if err != nil {
		log.Printf("Failed to read directory %s: %v", browserPath, err)
		return nil
	}

	var profiles []Profile
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		profileDir := entry.Name()
		if !isProfileDir(profileDir) {
			continue
		}

		info, ok := ls.Profile.InfoCache[profileDir]
		if !ok {
			log.Printf("No info_cache entry for profile dir %s in %s", profileDir, browserName)
			continue
		}
		if info.UserName == "" {
			log.Printf("No user_name for profile dir %s (display: %s) in %s", profileDir, info.Name, browserName)
			continue
		}

		profiles = append(profiles, Profile{
			Browser:     browserName,
			ProfileDir:  profileDir,
			DisplayName: info.Name,
			Email:       info.UserName,
		})
	}
	return profiles
}

func isProfileDir(name string) bool {
	return name == "Default" || strings.HasPrefix(name, "Profile ")
}

func getBrowserPath(browserName string) string {
	home := os.Getenv("HOME")
	localAppData := os.Getenv("LOCALAPPDATA")
	switch runtime.GOOS {
	case "windows":
		switch browserName {
		case "chrome":
			return filepath.Join(localAppData, `Google\Chrome\User Data`)
		case "edge":
			return filepath.Join(localAppData, `Microsoft\Edge\User Data`)
		}
	case "darwin":
		switch browserName {
		case "chrome":
			return filepath.Join(home, "Library/Application Support/Google/Chrome")
		case "edge":
			return filepath.Join(home, "Library/Application Support/Microsoft Edge")
		}
	case "linux":
		switch browserName {
		case "chrome":
			return filepath.Join(home, ".config/google-chrome")
		case "edge":
			return filepath.Join(home, ".config/microsoft-edge")
		}
	}
	return ""
}