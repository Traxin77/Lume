package main

import (
    "flag"
    "fmt"
    "os"

    "project/extractors/bookmarks"
    "project/extractors/credentials"
    "project/extractors/downloads"
    "project/extractors/history"
	"project/extractors/autofill"
	"project/extractors/extensions"
	"project/extractors/mail"
)

func main() {
    // Define flags
    historyFlag := flag.Bool("history", false, "Run history extractor")
    downloadsFlag := flag.Bool("downloads", false, "Run downloads extractor")
    credentialsFlag := flag.Bool("credentials", false, "Run cookies and passwords extractor")
	extensionsFlag := flag.Bool("extentions", false, "Run extentions extractor")
    bookmarksFlag := flag.Bool("bookmarks", false, "Run bookmarks extractor")
	mailFlag := flag.Bool("mail", false, "Run mail linked to profile extractor")
	autofillFlag := flag.Bool("autofill", false, "Run autofill extractor")
    allFlag := flag.Bool("all", false, "Run all extractors")
    flag.Parse()

    if len(os.Args) == 1 {
        fmt.Println("Usage: --history --downloads --credentials --bookmarks --all --extenions --autofill --mail")
        return
    }

    // Run extractors
    if *allFlag || *historyFlag {
        history.Run()
    }
    if *allFlag || *downloadsFlag {
        downloads.Run()
    }
    if *allFlag || *credentialsFlag {
        credentials.Run()
    }
    if *allFlag || *bookmarksFlag {
        bookmarks.Run()
    }
	if *allFlag || *extensionsFlag {
        extensions.Run()
    }
	if *allFlag || *mailFlag {
        mail.Run()
    }
	if *allFlag || *autofillFlag {
        autofill.Run()
    }
}
