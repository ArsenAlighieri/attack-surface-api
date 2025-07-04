package database

import (
	"attack-surface-api/internal/models"
	"fmt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"os"
	"time"
)

var DB *gorm.DB

func createDatabaseIfNotExists(user, pass, host, port, dbname string) error {
	// Root bağlantısı (env'den farklı root hesabı kullanabilirsin)
	rootDsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/", user, pass, host, port)
	db, err := gorm.Open(mysql.Open(rootDsn), &gorm.Config{})
	if err != nil {
		return err
	}

	// Veritabanını oluştur
	return db.Exec(fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`", dbname)).Error
}

func ConnectDB() {
	user := os.Getenv("DB_USER")
	pass := os.Getenv("DB_PASS")
	host := os.Getenv("DB_HOST")
	port := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local", user, pass, host, port, dbname)

	var db *gorm.DB
	var err error

	for i := 0; i < 10; i++ {
		db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
		if err == nil {
			break
		}
		log.Println("MySQL bağlantı hatası, tekrar deneniyor...:", err)
		time.Sleep(3 * time.Second)
	}

	if err != nil {
		log.Fatal("❌ Veritabanına bağlanılamadı:", err)
	}

	DB = db
	log.Println("✅ MySQL veritabanına başarıyla bağlandı!")

	DB.AutoMigrate(&models.User{}, &models.Domain{}, &models.Subdomain{})
}
