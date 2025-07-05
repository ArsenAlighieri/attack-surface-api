package services

import (
	"attack-surface-api/internal/models"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

type CrtShResponse struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			Subdomains []string `json:"subdomains"`
		}
	}
}

type ShodanResponse struct {
	Subdomains []string `json:"subdomains"`
}

var (
	virusTotalBaseURL = "https://www.virustotal.com/api/v3"
	shodanBaseURL = "https://api.shodan.io"
)

func fetchSubdomainsFromCrtSh(baseURL, domainName string) []string {
	url := fmt.Sprintf("%s/?q=%%25.%s&output=json", baseURL, domainName)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[!] Error fetching from crt.sh: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	var crtShResponses []CrtShResponse
	if err := json.NewDecoder(resp.Body).Decode(&crtShResponses); err != nil {
		fmt.Printf("[!] Error decoding crt.sh response: %v\n", err)
		return nil
	}

	uniqueSubdomains := make(map[string]struct{})
	for _, entry := range crtShResponses {
		// Split by newline to handle multiple entries in NameValue
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			name = strings.TrimSpace(name)
			if strings.HasSuffix(name, "."+domainName) && !strings.Contains(name, "*") {
				uniqueSubdomains[name] = struct{}{}
			}
		}
	}

	var subdomains []string
	for sub := range uniqueSubdomains {
		subdomains = append(subdomains, sub)
	}
	return subdomains
}

func fetchSubdomainsFromVirusTotal(domainName string) []string {
	apiKey := os.Getenv("VIRUSTOTAL_API_KEY")
	if apiKey == "" {
		fmt.Println("[!] VIRUSTOTAL_API_KEY not set. Skipping VirusTotal scan.")
		return nil
	}

	url := fmt.Sprintf("%s/domains/%s/subdomains", virusTotalBaseURL, domainName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Printf("[!] Error creating VirusTotal request: %v\n", err)
		return nil
	}
	req.Header.Add("x-apikey", apiKey)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] Error fetching from VirusTotal: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[!] VirusTotal API returned status: %d\n", resp.StatusCode)
		return nil
	}

	var vtResponse VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&vtResponse); err != nil {
		fmt.Printf("[!] Error decoding VirusTotal response: %v\n", err)
		return nil
	}

	return vtResponse.Data.Attributes.Subdomains
}

func fetchSubdomainsFromShodan(domainName string) []string {
	apiKey := os.Getenv("SHODAN_API_KEY")
	if apiKey == "" {
		fmt.Println("[!] SHODAN_API_KEY not set. Skipping Shodan scan.")
		return nil
	}

	url := fmt.Sprintf("%s/dns/domain/%s?key=%s", shodanBaseURL, domainName, apiKey)
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("[!] Error fetching from Shodan: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("[!] Shodan API returned status: %d\n", resp.StatusCode)
		return nil
	}

	var shodanResponse ShodanResponse
	if err := json.NewDecoder(resp.Body).Decode(&shodanResponse); err != nil {
		fmt.Printf("[!] Error decoding Shodan response: %v\n", err)
		return nil
	}

	return shodanResponse.Subdomains
}

var wordlist = []string{

	"www", "mail", "ftp", "dev", "test", "api", "admin", "portal",
	"blog", "cdn", "shop", "staging", "secure", "beta", "m", "webmail",
	"ns1", "ns2", "vpn", "support", "help", "dashboard", "static", "media",
	"news", "cloud", "download", "upload", "pay", "billing", "login", "auth",
	"files", "mobile", "docs", "forum", "partners", "cdn1", "cdn2", "cdn3",
	"video", "img", "ads", "track", "api1", "api2", "test1", "test2",
	"prod", "stage", "uat", "dev1", "dev2", "backup", "legacy", "sys",
	"smtp", "pop", "imap", "fileserver", "git", "svn", "gitlab", "jira",
	"confluence", "bitbucket", "kibana", "grafana", "elastic", "search",
}

func isWildcard(domain string) bool {
	testSub := fmt.Sprintf("%s.%s", "thisshouldnotexist12345", domain)
	ips, err := net.LookupHost(testSub)
	if err == nil && len(ips) > 0 {
		fmt.Printf("[!] Wildcard DNS detected for %s\n", domain)
		return true
	}
	return false
}

func ScanSubdomains(domain models.Domain, customWordlist []string) {
	// Combine custom wordlist with crt.sh results
	var combinedWordlist []string
	if len(customWordlist) > 0 {
		combinedWordlist = customWordlist
	} else {
		combinedWordlist = wordlist
	}

	crtShSubdomains := fetchSubdomainsFromCrtSh("https://crt.sh", domain.Name)
	combinedWordlist = append(combinedWordlist, crtShSubdomains...)

	vtSubdomains := fetchSubdomainsFromVirusTotal(domain.Name)
	combinedWordlist = append(combinedWordlist, vtSubdomains...)

	shodanSubdomains := fetchSubdomainsFromShodan(domain.Name)
	combinedWordlist = append(combinedWordlist, shodanSubdomains...)

	// Remove duplicates
	uniqueSubdomains := make(map[string]struct{})
	var finalWordlist []string
	for _, sub := range combinedWordlist {
		if _, ok := uniqueSubdomains[sub]; !ok {
			uniqueSubdomains[sub] = struct{}{}
			finalWordlist = append(finalWordlist, sub)
		}
	}
	
	// Establish a new database connection for the scanner goroutine
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", user, pass, host, port, dbname)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		fmt.Printf("[!] Scanner DB connection error: %v\n", err)
		return
	}

	db.Model(&domain).Update("Status", "scanning")

	if isWildcard(domain.Name) {
		fmt.Printf("[!] Skipping subdomain scan for %s due to wildcard DNS\n", domain.Name)
		db.Model(&domain).Update("Status", "error")
		return
	}

	var wg sync.WaitGroup

		for _, sub := range finalWordlist {
		wg.Add(1)

		go func(sub string) {
			defer wg.Done()

			fqdn := fmt.Sprintf("%s.%s", sub, domain.Name)
			ips, err := net.LookupHost(fqdn)
			if err == nil && len(ips) > 0 {
				fmt.Printf("[+] Found subdomain: %s (%v)\n", fqdn, ips)

				subdomain := models.Subdomain{
					DomainID: domain.ID,
					Name:     fqdn,
				}
				db.Create(&subdomain)
			}
		}(sub)
	}

	wg.Wait()

	db.Model(&domain).Update("Status", "completed")
}
