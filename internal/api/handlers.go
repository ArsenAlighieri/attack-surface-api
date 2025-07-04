package api

import (
	"attack-surface-api/internal/database"
	"attack-surface-api/internal/models"
	"attack-surface-api/internal/services"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"time"
)

var jwtSecret = []byte("supersecretkey") // Daha sonra env dosyasına alacağız

func GetProfile(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(uint)

	var user models.User
	result := database.DB.First(&user, userID)
	if result.Error != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "User not found",
		})
	}

	return c.JSON(fiber.Map{
		"id":         user.ID,
		"email":      user.Email,
		"created_at": user.CreatedAt,
	})
}

func ListSubdomains(c *fiber.Ctx) error {
	domainID := c.Params("id")

	var subdomains []models.Subdomain
	database.DB.Where("domain_id = ?", domainID).Find(&subdomains)

	return c.JSON(subdomains)
}

func RegisterUser(c *fiber.Ctx) error {
	type Request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var body Request
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Geçersiz istek gövdesi",
		})
	}

	// Şifreyi hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), 14)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Şifre hashlenemedi",
		})
	}

	user := models.User{
		Email:    body.Email,
		Password: string(hashedPassword),
	}

	result := database.DB.Create(&user)
	if result.Error != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Bu e-posta zaten kayıtlı",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Kayıt başarılı",
	})
}

func AddDomain(c *fiber.Ctx) error {
	type Request struct {
		Name string `json:"name"`
	}

	var body Request
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Geçersiz istek gövdesi",
		})
	}

	domain := models.Domain{
		Name: body.Name,
	}

	if err := database.DB.Create(&domain).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Bu domain zaten mevcut",
		})
	}

	// Subdomain taramasını arka planda başlat
	go services.ScanSubdomains(domain.ID, domain.Name)

	return c.JSON(domain)
}

func ListDomains(c *fiber.Ctx) error {
	var domains []models.Domain
	if err := database.DB.Preload("Subdomains").Find(&domains).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Domainler alınamadı",
		})
	}

	return c.JSON(domains)
}

func DeleteDomain(c *fiber.Ctx) error {
	id := c.Params("id")

	if err := database.DB.Delete(&models.Domain{}, id).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Silme işlemi başarısız",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Domain silindi",
	})
}

func LoginUser(c *fiber.Ctx) error {
	type Request struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	var body Request
	if err := c.BodyParser(&body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Geçersiz istek gövdesi",
		})
	}

	var user models.User
	result := database.DB.Where("email = ?", body.Email).First(&user)
	if result.Error == gorm.ErrRecordNotFound {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Kullanıcı bulunamadı",
		})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Hatalı şifre",
		})
	}

	// JWT Token oluştur
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 72).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Token oluşturulamadı",
		})
	}

	return c.JSON(fiber.Map{
		"token": tokenString,
	})
}
