package firefox

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
)

var (
	prefPatterns = []string{
		`user_pref\("identity.fxaccounts.email",\s*"(.*?)"\)`,
		`user_pref\("services.sync.username",\s*"(.*?)"\)`,
		`user_pref\("services.sync.account",\s*"(.*?)"\)`,
		`user_pref\("mail.identity.*\.useremail",\s*"(.*?)"\)`,
	}
	emailRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$`)
)

// firefoxBaseDirMail returns the base firefox directory for the current OS.
// Named with Mail suffix to avoid symbol collisions with other files.
func firefoxBaseDirMail() string {
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

// findProfilesMail returns a slice of profile directories (Profiles/*) or fallback to base.
func findProfilesMail() []string {
	root := filepath.Join(firefoxBaseDirMail(), "Profiles")

	// Prefer Profiles subfolder
	if fi, err := os.Stat(root); err == nil && fi.IsDir() {
		entries, _ := os.ReadDir(root)
		out := make([]string, 0, len(entries))
		for _, e := range entries {
			if e.IsDir() {
				out = append(out, filepath.Join(root, e.Name()))
			}
		}
		return out
	}

	// Fallback: treat base dir as a single profile
	if fi, err := os.Stat(firefoxBaseDirMail()); err == nil && fi.IsDir() {
		return []string{firefoxBaseDirMail()}
	}

	return nil
}

// extractEmailFromProfile reads prefs.js in profile and returns the first matched email (or nil).
func extractEmailFromProfile(profile string) *string {
	prefs := filepath.Join(profile, "prefs.js")
	data, err := os.ReadFile(prefs)
	if err != nil {
		return nil
	}
	text := string(data)

	for _, pat := range prefPatterns {
		re := regexp.MustCompile(pat)
		m := re.FindStringSubmatch(text)
		if len(m) >= 2 && emailRe.MatchString(m[1]) {
			email := m[1]
			return &email
		}
	}
	return nil
}

// RunMail locates firefox profiles, extracts mail/email related prefs and writes JSON to ./results/firefox_mail.json
func RunMail() {
	outPath := filepath.Join("results", "firefox", "firefox_mail.json")

	profiles := findProfilesMail()
	if len(profiles) == 0 {
		fmt.Fprintln(os.Stderr, "no firefox profiles found")
		return
	}

	results := make(map[string]*string)
	for _, p := range profiles {
		name := filepath.Base(p)
		fmt.Println("Scanning profile:", name)
		email := extractEmailFromProfile(p)
		if email != nil {
			fmt.Printf(" - found email: %s\n", *email)
		} else {
			fmt.Println(" - no email found")
		}
		results[name] = email
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
	if err := enc.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return
	}
	fmt.Println("Saved:", outPath)
}
