package main

import (
	"attack-surface-api/internal/api"
	"attack-surface-api/internal/database"
	"github.com/gofiber/fiber/v2"
	"log"
)

func main() {
	app := fiber.New()

	database.ConnectDB()
	api.SetupRoutes(app)

	if err := app.Listen(":8080"); err != nil {
		log.Fatal(err)
	}
}
