package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"project/extractors/autofill"
	"project/extractors/bookmarks"
	cookies "project/extractors/cookie"
	"project/extractors/downloads"
	"project/extractors/extensions"
	"project/extractors/firefox"
	"project/extractors/history"
	"project/extractors/mail"
	credentials "project/extractors/passwords"
	"project/packager"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func main() {
	// Define flags
	historyFlag := flag.Bool("history", false, "Run history extractor (Chrome/Edge/Brave)")
	downloadsFlag := flag.Bool("downloads", false, "Run downloads extractor (Chrome/Edge/Brave)")
	passwordsFlag := flag.Bool("passwords", false, "Run cookies and passwords extractor (Chrome/Edge/Brave)")
	cookieFlag := flag.Bool("cookie", false, "Run cookies and passwords extractor (Chrome/Edge/Brave)")
	extensionsFlag := flag.Bool("extensions", false, "Run extensions extractor (Chrome/Edge/Brave)")
	bookmarksFlag := flag.Bool("bookmarks", false, "Run bookmarks extractor (Chrome/Edge/Brave)")
	mailFlag := flag.Bool("mail", false, "Run mail linked to profile extractor (Chrome/Edge)")
	autofillFlag := flag.Bool("autofill", false, "Run autofill extractor (Chrome/Edge/Brave)")

	// Firefox-specific flags
	firefoxCookiesFlag := flag.Bool("firefox-cookies", false, "Run Firefox cookies extractor")
	firefoxDownloadsFlag := flag.Bool("firefox-downloads", false, "Run Firefox download history extractor")
	firefoxExtensionsFlag := flag.Bool("firefox-extensions", false, "Run Firefox extensions extractor")

	//all
	allFlag := flag.Bool("all", false, "Run all extractors (Chrome/Edge/Brave + Firefox)")
	allChromiumFlag := flag.Bool("all-chromium", false, "Run all Chromium-based browser extractors only")
	allFirefoxFlag := flag.Bool("all-firefox", false, "Run all Firefox extractors only")

	firefoxAutofillFlag := flag.Bool("firefox-autofill", false, "Run firefox autofill extractor")
	firefoxHistoryFlag := flag.Bool("firefox-history", false, "Run Firefox browsing history extractor")
	firefoxMailFlag := flag.Bool("firefox-mail", false, "Run Firefox mail/email extractor")
	firefoxBookmarkFlag := flag.Bool("firefox-bookmark", false, "Run Firefox bookmarks extractor")
	firefoxPasswordsFlag := flag.Bool("firefox-passwords", false, "Run Firefox saved passwords extractor")

	// Packaging flag
	packageFlag := flag.Bool("package", false, "Create encrypted evidence bundle after extraction")

	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println("Browser Forensics Toolkit")
		fmt.Println("========================")
		fmt.Println("\nChromium-based Browsers (Chrome/Edge/Brave):")
		fmt.Println("  --history         Extract browsing history")
		fmt.Println("  --downloads       Extract download history")
		fmt.Println("  --credentials     Extract cookies and passwords")
		fmt.Println("  --bookmarks       Extract bookmarks")
		fmt.Println("  --extensions      Extract installed extensions")
		fmt.Println("  --autofill        Extract autofill data")
		fmt.Println("  --mail            Extract email addresses linked to profiles")
		fmt.Println("\nFirefox:")
		fmt.Println("  --firefox-cookies   Extract Firefox cookies (with decryption support)")
		fmt.Println("  --firefox-downloads Extract Firefox download history")
		fmt.Println("  --firefox-extensions Extract Firefox extensions")
		fmt.Println("  --firefox-autofill Extract Firefox extensions")
		fmt.Println("  --firefox-passwords Extract Firefox extensions")
		fmt.Println("  --firefox-history Extract Firefox extensions")
		fmt.Println("  --firefox-bookmarks Extract Firefox extensions")
		fmt.Println("  --firefox-mails Extract Firefox extensions")
		fmt.Println("\nBatch Operations:")
		fmt.Println("  --all-chromium    Run all Chromium extractors")
		fmt.Println("  --all-firefox     Run all Firefox extractors")
		fmt.Println("  --all             Run all extractors for all browsers")
		fmt.Println("\nEvidence Packaging:")
		fmt.Println("  --package         Create encrypted evidence bundle after extraction")
		fmt.Println("\nExample:")
		fmt.Println("  lume.exe --credentials --firefox-cookies")
		fmt.Println("  lume.exe --firefox-cookies --firefox-downloads")
		fmt.Println("  lume.exe --all --package")
		return
	}

	// Chromium-based browser extractors
	if *allFlag || *allChromiumFlag || *historyFlag {
		fmt.Println("\n=== Running History Extractor (Chromium) ===")
		history.Run()
	}
	if *allFlag || *allChromiumFlag || *downloadsFlag {
		fmt.Println("\n=== Running Downloads Extractor (Chromium) ===")
		downloads.Run()
	}
	if *allFlag || *allChromiumFlag || *passwordsFlag {
		fmt.Println("\n=== Running Credentials Extractor (Chromium) ===")
		credentials.Run()
	}
	if *allFlag || *allChromiumFlag || *bookmarksFlag {
		fmt.Println("\n=== Running Bookmarks Extractor (Chromium) ===")
		bookmarks.Run()
	}
	if *allFlag || *allChromiumFlag || *extensionsFlag {
		fmt.Println("\n=== Running Extensions Extractor (Chromium) ===")
		extensions.Run()
	}
	if *allFlag || *allChromiumFlag || *mailFlag {
		fmt.Println("\n=== Running Mail Extractor (Chromium) ===")
		mail.Run()
	}
	if *allFlag || *allChromiumFlag || *autofillFlag {
		fmt.Println("\n=== Running Autofill Extractor (Chromium) ===")
		autofill.Run()
	}
	if *allFlag || *allFirefoxFlag || *firefoxPasswordsFlag {
		fmt.Println("\n=== Running Firefox Passwords Extractor ===")
		firefox.RunPasswords()
	}
	// Firefox extractors
	if *allFlag || *allFirefoxFlag || *firefoxCookiesFlag {
		fmt.Println("\n=== Running Firefox Cookies Extractor ===")
		firefox.RunCookies()
	}
	if *allFlag || *allFirefoxFlag || *firefoxDownloadsFlag {
		fmt.Println("\n=== Running Firefox Downloads Extractor ===")
		firefox.RunDownloads()
	}
	if *allFlag || *allFirefoxFlag || *firefoxExtensionsFlag {
		fmt.Println("\n=== Running Firefox Extensions Extractor ===")
		firefox.RunExtensions()
	}
	if *allFlag || *allFirefoxFlag || *firefoxHistoryFlag {
		fmt.Println("\n=== Running Firefox History Extractor ===")
		firefox.RunHistory()
	}
	if *allFlag || *allFirefoxFlag || *firefoxMailFlag {
		fmt.Println("\n=== Running Firefox Mail Extractor ===")
		firefox.RunMail()
	}
	if *allFlag || *allFirefoxFlag || *firefoxAutofillFlag {
		fmt.Println("\n=== Running Firefox Autofill Extractor ===")
		firefox.RunAutofill()
	}
	if *allFlag || *allFirefoxFlag || *firefoxBookmarkFlag {
		fmt.Println("\n=== Running Firefox Autofill Extractor ===")
		firefox.RunBookmarks()
	}
	if *allFlag || *allChromiumFlag || *cookieFlag {
		fmt.Println("\n=== Running Cookies Extractor (Chromium) ===")
		cookies.Run()
	}

	fmt.Println("\n=== Extraction Complete ===")
	fmt.Println("Results saved in ./results/ directory")

	// Package results if flag is set
	if *packageFlag {
		promptAndMaybePackage("./results")
	}
}

// promptAndMaybePackage prompts the user for packaging metadata and creates an evidence bundle
func promptAndMaybePackage(resultsDir string) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("\n=== Evidence Bundle Packaging ===")
	fmt.Println("Creating a cryptographically sealed evidence bundle...")
	fmt.Println()

	// Check if results directory exists
	if _, err := os.Stat(resultsDir); os.IsNotExist(err) {
		fmt.Printf("⚠️  Results directory not found: %s\n", resultsDir)
		return
	}

	// Prompt for case metadata
	fmt.Print("Case Name: ")
	caseName, _ := reader.ReadString('\n')
	caseName = strings.TrimSpace(caseName)

	fmt.Print("Case ID: ")
	caseID, _ := reader.ReadString('\n')
	caseID = strings.TrimSpace(caseID)

	fmt.Print("Investigator Name: ")
	investigator, _ := reader.ReadString('\n')
	investigator = strings.TrimSpace(investigator)

	// NEW: ask for a short bundle base name (optional)
	fmt.Print("Bundle base name (short, e.g. ACME_001) [leave empty for auto]: ")
	outBase, _ := reader.ReadString('\n')
	outBase = strings.TrimSpace(outBase)
	// basic sanitize: remove path separators and trim length
	if outBase != "" {
		outBase = strings.ReplaceAll(outBase, string(os.PathSeparator), "_")
		if len(outBase) > 40 {
			outBase = outBase[:40]
		}
	}

	// Read password securely (no echo)
	fmt.Print("Bundle Encryption Password: ")
	pwBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("⚠️  Failed to read password: %v\n", err)
		return
	}
	password := strings.TrimSpace(string(pwBytes))

	if password == "" {
		fmt.Println("⚠️  Password is required for bundle encryption. Skipping packaging.")
		return
	}

	fmt.Print("Confirm Password: ")
	pwConfirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		fmt.Printf("⚠️  Failed to read password confirmation: %v\n", err)
		return
	}
	confirmPassword := strings.TrimSpace(string(pwConfirmBytes))

	if password != confirmPassword {
		fmt.Println("⚠️  Passwords do not match. Skipping packaging.")
		return
	}

	// Optional: prompt for public key paths
	fmt.Print("OpenPGP Public Key Paths (comma-separated, optional): ")
	pubKeyInput, _ := reader.ReadString('\n')
	pubKeyInput = strings.TrimSpace(pubKeyInput)

	var pubKeyPaths []string
	if pubKeyInput != "" {
		pubKeyPaths = strings.Split(pubKeyInput, ",")
		for i := range pubKeyPaths {
			pubKeyPaths[i] = strings.TrimSpace(pubKeyPaths[i])
		}
	}

	fmt.Println()

	// Call the packager using the provided short basename (outBase)
	err = packager.PackageResults(
		resultsDir,
		outBase, // pass the user-provided short base name here
		caseName,
		caseID,
		investigator,
		password,
		pubKeyPaths,
	)

	if err != nil {
		fmt.Printf("❌ Packaging failed: %v\n", err)
		return
	}

	fmt.Println("\n✓ Evidence bundle successfully created!")
}
