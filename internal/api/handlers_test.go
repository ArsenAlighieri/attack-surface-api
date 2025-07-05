package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"attack-surface-api/internal/models"
	"github.com/glebarez/sqlite"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func init() {
	os.Setenv("JWT_SECRET", "test-super-secret-key")
}

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

	t.Logf("Database setup complete. DB instance: %p", db)
	return db
}

func TestRegisterUser(t *testing.T) {
	db := setupTestDB(t)

	app := fiber.New()
	SetupRoutes(app, db)

	requestBody, _ := json.Marshal(map[string]string{
		"email":    "test@example.com",
		"password": "password123",
	})

	req := httptest.NewRequest("POST", "/api/register", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var responseBody map[string]string
	json.NewDecoder(resp.Body).Decode(&responseBody)

	assert.Equal(t, "Kayıt başarılı", responseBody["message"])
}

func TestLoginUser(t *testing.T) {
	db := setupTestDB(t)

	app := fiber.New()
	SetupRoutes(app, db)

	// First, register a user
	password := "password123"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := models.User{Email: "testlogin@example.com", Password: string(hashedPassword)}
	db.Create(&user)

	// Now, try to log in
	requestBody, _ := json.Marshal(map[string]string{
		"email":    "testlogin@example.com",
		"password": password,
	})

	req := httptest.NewRequest("POST", "/api/login", bytes.NewBuffer(requestBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var responseBody map[string]string
	json.NewDecoder(resp.Body).Decode(&responseBody)

	assert.NotEmpty(t, responseBody["token"], "Token should not be empty")
}

func TestAddAndListDomains(t *testing.T) {
	db := setupTestDB(t)

	app := fiber.New()
	SetupRoutes(app, db)

	// 1. Create a user and a token
	user := models.User{Email: "testdomains@example.com", Password: "password"}
	db.Create(&user)

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(user.ID),
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	assert.NoError(t, err)

	// 2. Add a domain for the user
	addDomainBody, _ := json.Marshal(map[string]interface{}{"name": "example.com", "wordlist": []string{"test1", "test2"}})
	addReq := httptest.NewRequest("POST", "/api/domains", bytes.NewBuffer(addDomainBody))
	addReq.Header.Set("Content-Type", "application/json")
	addReq.Header.Set("Authorization", "Bearer "+tokenString)

	addResp, err := app.Test(addReq)
	assert.NoError(t, err)
	t.Logf("AddDomain Response Status: %d", addResp.StatusCode)
	addRespBody, _ := io.ReadAll(addResp.Body)
	t.Logf("AddDomain Response Body: %s", string(addRespBody))
	assert.Equal(t, fiber.StatusOK, addResp.StatusCode)

	// 3. List domains for the user
	listReq := httptest.NewRequest("GET", "/api/domains", nil)
	listReq.Header.Set("Authorization", "Bearer "+tokenString)

	listResp, err := app.Test(listReq)
	assert.NoError(t, err)
	t.Logf("ListDomains Response Status: %d", listResp.StatusCode)
	listRespBody, _ := io.ReadAll(listResp.Body)
	t.Logf("ListDomains Response Body: %s", string(listRespBody))
	assert.Equal(t, fiber.StatusOK, listResp.StatusCode)

	var domains []models.Domain
	json.NewDecoder(bytes.NewBuffer(listRespBody)).Decode(&domains)

	assert.Len(t, domains, 1, "Should be one domain for this user")
	assert.Equal(t, "example.com", domains[0].Name)
	assert.Equal(t, user.ID, domains[0].UserID)
}

func TestDomainMigration(t *testing.T) {
	db := setupTestDB(t)

	// Check if the domains table exists after auto-migration
	hasTable := db.Migrator().HasTable(&models.Domain{})
	assert.True(t, hasTable, "domains table should exist after auto-migration")
}

func TestGetDomainStatus(t *testing.T) {
	db := setupTestDB(t)

	app := fiber.New()
	SetupRoutes(app, db)

	// 1. Create a user
	user := models.User{Email: "statususer@example.com", Password: "password"}
	db.Create(&user)

	// 2. Create a domain with a specific status
	domain := models.Domain{UserID: user.ID, Name: "teststatus.com", Status: "completed"}
	db.Create(&domain)

	// 3. Generate a token for the user
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(user.ID),
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	assert.NoError(t, err)

	// 4. Make a request to get the domain status
	req := httptest.NewRequest("GET", fmt.Sprintf("/api/domains/%d/status", domain.ID), nil)
	req.Header.Set("Authorization", "Bearer "+tokenString)

	resp, err := app.Test(req)
	assert.NoError(t, err)
	assert.Equal(t, fiber.StatusOK, resp.StatusCode)

	var responseBody map[string]string
	json.NewDecoder(resp.Body).Decode(&responseBody)

	assert.Equal(t, "completed", responseBody["status"], "Expected domain status to be 'completed'")
}
