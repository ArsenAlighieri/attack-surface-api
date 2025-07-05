package services

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"attack-surface-api/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	var err error
	db, err := gorm.Open(sqlite.Open("file::memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}

	// Drop existing tables to ensure a clean state for each test
	err = db.Migrator().DropTable(&models.User{}, &models.Domain{}, &models.Subdomain{})
	if err != nil {
		t.Fatalf("failed to drop tables: %v", err)
	}

	err = db.AutoMigrate(&models.User{}, &models.Domain{}, &models.Subdomain{})
	if err != nil {
		t.Fatalf("failed to auto migrate: %v", err)
	}

	return db
}

func TestFetchSubdomainsFromCrtSh(t *testing.T) {
	// Mock crt.sh server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/?q=%25.example.com&output=json", r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"common_name": "example.com", "name_value": "www.example.com\nsub.example.com"},
			{"common_name": "another.com", "name_value": "test.another.com"}
		]`))
	}))
	defer server.Close()

	subdomains := fetchSubdomainsFromCrtSh(server.URL, "example.com")

	assert.Contains(t, subdomains, "www.example.com")
	assert.Contains(t, subdomains, "sub.example.com")
	assert.NotContains(t, subdomains, "test.another.com")
}

func TestFetchSubdomainsFromVirusTotal(t *testing.T) {
	// Mock VirusTotal server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/v3/domains/example.com/subdomains", r.URL.Path)
		assert.Equal(t, "test-virustotal-key", r.Header.Get("x-apikey"))
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"data": {
				"attributes": {
					"subdomains": ["vt1.example.com", "vt2.example.com"]
				}
			}
		}`))
	}))
	defer server.Close()

	os.Setenv("VIRUSTOTAL_API_KEY", "test-virustotal-key")
	defer os.Unsetenv("VIRUSTOTAL_API_KEY")

	// Temporarily override the VirusTotal API URL to point to our mock server
	originalVirusTotalURL := virusTotalBaseURL
	virusTotalBaseURL = server.URL + "/api/v3"
	defer func() { virusTotalBaseURL = originalVirusTotalURL }()

	subdomains := fetchSubdomainsFromVirusTotal("example.com")

	assert.Contains(t, subdomains, "vt1.example.com")
	assert.Contains(t, subdomains, "vt2.example.com")
	assert.Len(t, subdomains, 2)
}

func TestFetchSubdomainsFromShodan(t *testing.T) {
	// Mock Shodan server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/dns/domain/example.com?key=test-shodan-key", r.URL.RequestURI())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"subdomains": ["shodan1.example.com", "shodan2.example.com"]
		}`))
	}))
	defer server.Close()

	os.Setenv("SHODAN_API_KEY", "test-shodan-key")
	defer os.Unsetenv("SHODAN_API_KEY")

	// Temporarily override the Shodan API URL to point to our mock server
	originalShodanURL := shodanBaseURL
	shodanBaseURL = server.URL
	defer func() { shodanBaseURL = originalShodanURL }()

	subdomains := fetchSubdomainsFromShodan("example.com")

	assert.Contains(t, subdomains, "shodan1.example.com")
	assert.Contains(t, subdomains, "shodan2.example.com")
	assert.Len(t, subdomains, 2)
}
