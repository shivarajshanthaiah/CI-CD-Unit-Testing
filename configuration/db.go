package configuration

import (
	"os"

	"github.com/shivarajshanthaiah/unit-testing/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

// ConnectDB to connect database
func ConnectDB() {
	dsn := os.Getenv("DB")
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Failed to connect to the database")
	}
	DB.AutoMigrate(
		&models.User{},
	)
}
