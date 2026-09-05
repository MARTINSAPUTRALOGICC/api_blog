package main

import (
	"app/config"
	"app/handlers"
	"app/models"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Println("WARNING: .env tidak ditemukan, menggunakan environment variable")
	}

	fmt.Println("DB_HOST:", os.Getenv("DB_HOST"))
	fmt.Println("DB_USER:", os.Getenv("DB_USER"))
	fmt.Println("DB_NAME:", os.Getenv("DB_NAME"))

	db, err := config.ConnectDatabase()
	if err != nil {
		log.Fatal("Database connection failed:", err)
	}

	fmt.Println("Database connected!")

	err = db.AutoMigrate(
		&models.User{},
		&models.BlogPost{},
		&models.Comment{},
	)
	if err != nil {
		log.Fatal("Migration failed:", err)
	}

	http.HandleFunc("/register", handlers.Register(db))
	http.HandleFunc("/login", handlers.Login(db))
	http.HandleFunc("/posts", handlers.Posts(db))
	http.HandleFunc("/posts/", handlers.PostByID(db))
	http.HandleFunc("/logout", handlers.Logout)

	fmt.Println("Server running on http://0.0.0.0:8080")

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))

}
