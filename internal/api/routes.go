package api

import (
	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	api := app.Group("/api")

	api.Post("/register", RegisterUser)
	api.Post("/login", LoginUser)

	// Protected routes
	protected := api.Group("", JWTProtected())
	protected.Get("/profile", GetProfile)
	protected.Post("/domains", AddDomain)
	protected.Get("/domains", ListDomains)
	protected.Delete("/domains/:id", DeleteDomain)
	protected.Get("/domains/:id/subdomains", ListSubdomains)

}
