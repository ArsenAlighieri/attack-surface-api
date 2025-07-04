package services

import (
	"attack-surface-api/internal/database"
	"attack-surface-api/internal/models"
	"fmt"
	"net"
	"sync"
)

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

func ScanSubdomains(domainID uint, domainName string) {
	if isWildcard(domainName) {
		fmt.Printf("[!] Skipping subdomain scan for %s due to wildcard DNS\n", domainName)
		return
	}

	var wg sync.WaitGroup

	for _, sub := range wordlist {
		wg.Add(1)

		go func(sub string) {
			defer wg.Done()

			fqdn := fmt.Sprintf("%s.%s", sub, domainName)
			ips, err := net.LookupHost(fqdn)
			if err == nil && len(ips) > 0 {
				fmt.Printf("[+] Found subdomain: %s (%v)\n", fqdn, ips)

				subdomain := models.Subdomain{
					DomainID: domainID,
					Name:     fqdn,
				}
				database.DB.Create(&subdomain)
			}
		}(sub)
	}

	wg.Wait()
}
