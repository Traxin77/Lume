package main

import (
	"flag"
	"fmt"
	"os"

	"project/extractors/autofill"
	"project/extractors/bookmarks"
	"project/extractors/credentials"
	"project/extractors/downloads"
	"project/extractors/extensions"
	"project/extractors/firefox"
	"project/extractors/history"
	"project/extractors/mail"
)

func main() {
    // Define flags
    historyFlag := flag.Bool("history", false, "Run history extractor (Chrome/Edge/Brave)")
    downloadsFlag := flag.Bool("downloads", false, "Run downloads extractor (Chrome/Edge/Brave)")
    credentialsFlag := flag.Bool("credentials", false, "Run cookies and passwords extractor (Chrome/Edge/Brave)")
    extensionsFlag := flag.Bool("extensions", false, "Run extensions extractor (Chrome/Edge/Brave)")
    bookmarksFlag := flag.Bool("bookmarks", false, "Run bookmarks extractor (Chrome/Edge/Brave)")
    mailFlag := flag.Bool("mail", false, "Run mail linked to profile extractor (Chrome/Edge)")
    autofillFlag := flag.Bool("autofill", false, "Run autofill extractor (Chrome/Edge/Brave)")
    
    // Firefox-specific flags
    firefoxCookiesFlag := flag.Bool("firefox-cookies", false, "Run Firefox cookies extractor")
    firefoxDownloadsFlag := flag.Bool("firefox-downloads", false, "Run Firefox download history extractor")
    firefoxExtensionsFlag := flag.Bool("firefox-extensions", false, "Run Firefox extensions extractor")

    allFlag := flag.Bool("all", false, "Run all extractors (Chrome/Edge/Brave + Firefox)")
    allChromiumFlag := flag.Bool("all-chromium", false, "Run all Chromium-based browser extractors only")
    allFirefoxFlag := flag.Bool("all-firefox", false, "Run all Firefox extractors only")
    
    firefoxAutofillFlag := flag.Bool("firefox-autofill", false,"Run firefox autofill extractor")
    firefoxHistoryFlag := flag.Bool("firefox-history", false, "Run Firefox browsing history extractor")
    firefoxMailFlag := flag.Bool("firefox-mail", false, "Run Firefox mail/email extractor")
    firefoxBookmarkFlag := flag.Bool("firefox-bookmark", false, "Run Firefox bookmarks extractor")
    firefoxPasswordsFlag := flag.Bool("firefox-passwords", false, "Run Firefox saved passwords extractor")
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
        fmt.Println("\nExample:")
        fmt.Println("  lume.exe --credentials --firefox-cookies")
        fmt.Println("  lume.exe --firefox-cookies --firefox-downloads")
        fmt.Println("  lume.exe --all")
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
    if *allFlag || *allChromiumFlag || *credentialsFlag {
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
    // If you want to allow custom limit via flag, pass firefoxHistoryLimit
        firefox.RunHistory()
    }
    if *allFlag || *allFirefoxFlag || *firefoxMailFlag {
        fmt.Println("\n=== Running Firefox Mail Extractor ===")
        firefox.RunMail()
    }
    if *allFlag || *allFirefoxFlag || *firefoxPasswordsFlag {
        fmt.Println("\n=== Running Firefox Passwords Extractor ===")
        firefox.RunPasswords()
    }
    if *allFlag || *allFirefoxFlag || *firefoxAutofillFlag {
        fmt.Println("\n=== Running Firefox Autofill Extractor ===")
        firefox.RunAutofill()
    }
    if *allFlag || *allFirefoxFlag || *firefoxBookmarkFlag {
        fmt.Println("\n=== Running Firefox Autofill Extractor ===")
        firefox.RunBookmarks()
    }
    fmt.Println("\n=== Extraction Complete ===")
    fmt.Println("Results saved in ./results/ directory")
}