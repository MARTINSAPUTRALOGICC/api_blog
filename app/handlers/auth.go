package handlers

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"
	"fmt"
	"app/models"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

)



type RegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func Register(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request RegisterRequest

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		request.Name = strings.TrimSpace(request.Name)
		request.Email = strings.TrimSpace(strings.ToLower(request.Email))

		if request.Name == "" ||
			request.Email == "" ||
			request.Password == "" {
			http.Error(w, "Name, email and password are required", http.StatusBadRequest)
			return
		}

		// Check email sudah digunakan
		var existingUser models.User

		err = db.Where("email = ?", request.Email).
			First(&existingUser).Error

		if err == nil {
			http.Error(w, "Email already registered", http.StatusConflict)
			return
		}

		if err != gorm.ErrRecordNotFound {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Hash password
		passwordHash, err := bcrypt.GenerateFromPassword(
			[]byte(request.Password),
			bcrypt.DefaultCost,
		)

		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}

		user := models.User{
			Name:         request.Name,
			Email:        request.Email,
			PasswordHash: string(passwordHash),
		}

		if err := db.Create(&user).Error; err != nil {
			http.Error(w, "Failed to create user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Registration successful",
			"user": map[string]interface{}{
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}



type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}


func ClearAuthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // true jika HTTPS
		SameSite: http.SameSiteLaxMode,
	})
}


func Login(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request LoginRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		request.Email = strings.TrimSpace(strings.ToLower(request.Email))

		if request.Email == "" || request.Password == "" {
			http.Error(w, "Email and password are required", http.StatusBadRequest)
			return
		}

		// Cari user
		var user models.User

		err := db.Where("email = ?", request.Email).
			First(&user).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(w, "Invalid email or password", http.StatusUnauthorized)
				return
			}

			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		// Cek password
		err = bcrypt.CompareHashAndPassword(
			[]byte(user.PasswordHash),
			[]byte(request.Password),
		)

		if err != nil {
			http.Error(w, "Invalid email or password", http.StatusUnauthorized)
			return
		}

		// JWT Secret
		jwtSecret := os.Getenv("JWT_SECRET")

		if jwtSecret == "" {
			http.Error(w, "JWT secret is not configured", http.StatusInternalServerError)
			return
		}

		// JWT berlaku 1 jam
		now := time.Now()
		expiration := now.Add(1 * time.Hour)

		claims := jwt.MapClaims{
			"user_id": user.ID,
			"email":   user.Email,
			"iat":     now.Unix(),
			"exp":     expiration.Unix(),
		}

		token := jwt.NewWithClaims(
			jwt.SigningMethodHS256,
			claims,
		)

		tokenString, err := token.SignedString([]byte(jwtSecret))

		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Simpan JWT di HttpOnly Cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    tokenString,
			Path:     "/",
			Expires:  expiration,
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   false, // ubah true jika sudah HTTPS
			SameSite: http.SameSiteLaxMode,
		})

		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Login successful",
			"token":   tokenString,
			"expires": expiration,
			"user": map[string]interface{}{
				"id":    user.ID,
				"name":  user.Name,
				"email": user.Email,
			},
		})
	}
}


func Logout(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// =========================
	// Ambil token dari cookie
	// =========================
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenString := cookie.Value

	// =========================
	// JWT Secret
	// =========================
	jwtSecret := os.Getenv("JWT_SECRET")

	if jwtSecret == "" {
		http.Error(
			w,
			"JWT secret is not configured",
			http.StatusInternalServerError,
		)
		return
	}

	// =========================
	// Validasi JWT
	// =========================
	token, err := jwt.Parse(
		tokenString,
		func(token *jwt.Token) (interface{}, error) {

			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}

			return []byte(jwtSecret), nil
		},
	)

	if err != nil || !token.Valid {
		// Token sudah expired / invalid
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		})

		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// =========================
	// Ambil claims
	// =========================
	claims, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		http.Error(
			w,
			"Invalid token claims",
			http.StatusUnauthorized,
		)
		return
	}

	// =========================
	// Ambil user_id
	// =========================
	userID, ok := claims["user_id"].(float64)

	if !ok {
		http.Error(
			w,
			"Invalid user ID",
			http.StatusUnauthorized,
		)
		return
	}

	// =========================
	// Clear cookie
	// =========================
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // true jika HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// =========================
	// Response
	// =========================
	w.Header().Set("Content-Type", "application/json")

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Logout successful",
		"user_id": uint(userID),
	})
}





