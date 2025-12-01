package firefox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"
)

// FirefoxExtension represents a single extension/add-on.
type FirefoxExtension struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Type        string  `json:"type"`
	Active      bool    `json:"active"`
	InstalledAt *string `json:"installed_at"`
	UpdatedAt   *string `json:"updated_at"`
}

type ProfileExtensions map[string][]FirefoxExtension

// firefoxBaseDir returns the base firefox directory for the current OS.
func firefoxBaseDir() string {
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

// parseTimestamp returns *time.Time or nil for multiple input kinds.
func parseTimestamp(v interface{}) *time.Time {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case float64:
		return parseNumeric(int64(t))
	case int64:
		return parseNumeric(t)
	case int:
		return parseNumeric(int64(t))
	case string:
		// try RFC3339 first
		if ts, err := time.Parse(time.RFC3339, t); err == nil {
			return &ts
		}
		if ts, err := time.Parse(time.RFC3339Nano, t); err == nil {
			return &ts
		}
		// some common formats
		formats := []string{
			"2006-01-02 15:04:05",
			"2006-01-02T15:04:05",
			"2006/01/02 15:04:05",
			time.ANSIC,
		}
		for _, f := range formats {
			if ts, err := time.Parse(f, t); err == nil {
				return &ts
			}
		}
		// numeric string fallback
		if i, err := strconv.ParseInt(t, 10, 64); err == nil {
			return parseNumeric(i)
		}
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return parseNumeric(i)
		}
	}
	return nil
}

func parseNumeric(v int64) *time.Time {
	if v <= 0 {
		return nil
	}
	// milliseconds vs seconds detection
	if v >= 1_000_000_000_000 {
		sec := v / 1000
		nsec := (v % 1000) * 1_000_000
		t := time.Unix(sec, nsec).Local()
		return &t
	}
	if v >= 1_000_000_000 {
		t := time.Unix(v, 0).Local()
		return &t
	}
	return nil
}

func formatLocal(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Local().Format("2006-01-02 15:04:05")
	return &s
}

// getExtensionsFromProfile reads extensions.json from a profile and parses addons.
func getExtensionsFromProfile(profilePath string) ([]FirefoxExtension, error) {
	data, err := os.ReadFile(filepath.Join(profilePath, "extensions.json"))
	if err != nil {
		return nil, err
	}
	var top interface{}
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, err
	}

	var addons []interface{}
	if m, ok := top.(map[string]interface{}); ok {
		if a, exists := m["addons"]; exists {
			if arr, ok := a.([]interface{}); ok {
				addons = arr
			}
		}
		if len(addons) == 0 {
			if a, exists := m["activeAddons"]; exists {
				if mm, ok := a.(map[string]interface{}); ok {
					for _, v := range mm {
						addons = append(addons, v)
					}
				}
			}
		}
	} else if arr, ok := top.([]interface{}); ok {
		addons = arr
	}

	if len(addons) == 0 {
		return nil, nil
	}

	out := make([]FirefoxExtension, 0, len(addons))
	for i, item := range addons {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		var e FirefoxExtension

		// id
		if s, ok := obj["id"].(string); ok && s != "" {
			e.ID = s
		} else if s, ok := obj["addonID"].(string); ok {
			e.ID = s
		} else if s, ok := obj["addonId"].(string); ok {
			e.ID = s
		}

		// name
		if d, ok := obj["defaultLocale"].(map[string]interface{}); ok {
			if n, ok := d["name"].(string); ok {
				e.Name = n
			}
		}
		if e.Name == "" {
			if n, ok := obj["name"].(string); ok {
				e.Name = n
			}
		}

		// version/type/active
		if v, ok := obj["version"].(string); ok {
			e.Version = v
		}
		if t, ok := obj["type"].(string); ok {
			e.Type = t
		}
		if b, ok := obj["active"].(bool); ok {
			e.Active = b
		}

		candsInstall := []string{"installDate", "install_date", "created", "dateInstalled", "installed", "added", "seen"}
		candsUpdate := []string{"updateDate", "lastUpdated", "modified", "lastModified", "updated", "date", "time"}

		for _, k := range candsInstall {
			if v, ok := obj[k]; ok {
				if ts := parseTimestamp(v); ts != nil {
					e.InstalledAt = formatLocal(ts)
					break
				}
			}
		}
		for _, k := range candsUpdate {
			if v, ok := obj[k]; ok {
				if ts := parseTimestamp(v); ts != nil {
					e.UpdatedAt = formatLocal(ts)
					break
				}
			}
		}

		if (e.InstalledAt == nil) || (e.UpdatedAt == nil) {
			if meta, ok := obj["meta"].(map[string]interface{}); ok {
				for _, k := range candsInstall {
					if v, ok := meta[k]; ok && e.InstalledAt == nil {
						if ts := parseTimestamp(v); ts != nil {
							e.InstalledAt = formatLocal(ts)
						}
					}
				}
				for _, k := range candsUpdate {
					if v, ok := meta[k]; ok && e.UpdatedAt == nil {
						if ts := parseTimestamp(v); ts != nil {
							e.UpdatedAt = formatLocal(ts)
						}
					}
				}
			}
			if props, ok := obj["properties"].(map[string]interface{}); ok {
				if e.InstalledAt == nil {
					if v, ok := props["created"]; ok {
						if ts := parseTimestamp(v); ts != nil {
							e.InstalledAt = formatLocal(ts)
						}
					}
				}
				if e.UpdatedAt == nil {
					if v, ok := props["modified"]; ok {
						if ts := parseTimestamp(v); ts != nil {
							e.UpdatedAt = formatLocal(ts)
						}
					}
				}
			}
		}

		// avoid zero-year weirdness
		if e.InstalledAt != nil {
			if t, err := time.Parse("2006-01-02 15:04:05", *e.InstalledAt); err == nil {
				if t.Year() <= 1 {
					e.InstalledAt = nil
				}
			}
		}
		if e.UpdatedAt != nil {
			if t, err := time.Parse("2006-01-02 15:04:05", *e.UpdatedAt); err == nil {
				if t.Year() <= 1 {
					e.UpdatedAt = nil
				}
			}
		}

		// fallback ID
		if e.ID == "" {
			e.ID = fmt.Sprintf("unknown-%d", i)
		}
		out = append(out, e)
	}

	return out, nil
}

// RunExtensions locates firefox profiles, extracts extensions/add-ons and writes JSON to ./results/firefox_extensions.json
func RunExtensions() {
	outPath := filepath.Join("results", "firefox_extensions.json")

	profiles := findProfiles()
	result := make(ProfileExtensions)
	for _, p := range profiles {
		name := filepath.Base(p)
		fmt.Println("Scanning:", name)
		exts, err := getExtensionsFromProfile(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, " - skip %s: %v\n", name, err)
			continue
		}
		if len(exts) > 0 {
			result[name] = exts
			fmt.Printf(" - %d extensions\n", len(exts))
		}
	}

	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		return
	}
	f, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "create:", err)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return
	}
	fmt.Println("Saved:", outPath)
}
