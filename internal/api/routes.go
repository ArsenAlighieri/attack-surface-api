package api

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func SetupRoutes(app *fiber.App, db *gorm.DB) {
	handler := &APIHandler{DB: db}

	api := app.Group("/api")

	api.Post("/register", handler.RegisterUser)
	api.Post("/login", handler.LoginUser)

	// Protected routes
	protected := api.Group("", JWTProtected())
	protected.Get("/profile", handler.GetProfile)
	protected.Post("/domains", handler.AddDomain)
	protected.Get("/domains", handler.ListDomains)
	protected.Delete("/domains/:id", handler.DeleteDomain)
	protected.Get("/domains/:id/subdomains", handler.ListSubdomains)
	protected.Get("/domains/:id/status", handler.GetDomainStatus)

}
