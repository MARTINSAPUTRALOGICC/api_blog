package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"strconv"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"app/models"
)



type CreateCommentRequest struct { 
 	Content string `json:"content"` 
}

type CreatePostRequest struct {
	Title   string `json:"title"`
	Content string `json:"content"`
}


func Posts(db *gorm.DB) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        switch r.Method {
        case http.MethodGet:
            GetAllPosts(db)(w, r)

        case http.MethodPost:
            CreatePost(db)(w, r)

        default:
            http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        }
    }
}


func PostByID(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		path := strings.TrimPrefix(r.URL.Path, "/posts/")
		parts := strings.Split(strings.Trim(path, "/"), "/")

		// =========================
		// /posts/{id}/comments
		// =========================
		if len(parts) == 2 && parts[1] == "comments" {

			switch r.Method {

			case http.MethodGet:
				GetComments(db)(w, r)

			case http.MethodPost:
				CreateComment(db)(w, r)

			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}

			return
		}

		// =========================
		// /posts/{id}
		// =========================
		if len(parts) == 1 {

			switch r.Method {

			case http.MethodGet:
				GetPost(db)(w, r)

			case http.MethodPut:
				UpdatePost(db)(w, r)

			case http.MethodDelete:
				DeletePost(db)(w, r)

			default:
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			}

			return
		}

		http.Error(w, "Invalid post route", http.StatusNotFound)
	}
}




func CreatePost(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// ========================================
		// Hanya POST
		// ========================================

		if r.Method != http.MethodPost {
			http.Error(
				w,
				"Method not allowed",
				http.StatusMethodNotAllowed,
			)
			return
		}

		// ========================================
		// Ambil JWT dari cookie
		// ========================================

		cookie, err := r.Cookie("auth_token")

		if err != nil {
			// Tidak ada cookie JWT
			http.Error(
				w,
				"Unauthorized: JWT token required",
				http.StatusUnauthorized,
			)
			return
		}

		tokenString := cookie.Value

		// Cookie ada tapi kosong
		if tokenString == "" {
			ClearAuthCookie(w)

			http.Error(
				w,
				"Unauthorized: JWT token is empty",
				http.StatusUnauthorized,
			)
			return
		}

		// ========================================
		// Ambil JWT Secret
		// ========================================

		jwtSecret := os.Getenv("JWT_SECRET")

		if jwtSecret == "" {
			http.Error(
				w,
				"JWT secret is not configured",
				http.StatusInternalServerError,
			)
			return
		}

		// ========================================
		// Validasi JWT
		// ========================================

		token, err := jwt.Parse(
			tokenString,
			func(token *jwt.Token) (interface{}, error) {

				// Pastikan algoritma HMAC
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf(
						"unexpected signing method",
					)
				}

				return []byte(jwtSecret), nil
			},
		)

		// ========================================
		// JWT expired / invalid
		// ========================================

		if err != nil || !token.Valid {

			// Hapus cookie JWT
			ClearAuthCookie(w)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "JWT token expired or invalid",
			})

			return
		}

		// ========================================
		// Ambil claims
		// ========================================

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			ClearAuthCookie(w)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid token claims",
			})

			return
		}

		// ========================================
		// Ambil user_id dari JWT
		// ========================================

		userIDFloat, ok := claims["user_id"].(float64)

		if !ok {
			ClearAuthCookie(w)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid user ID",
			})

			return
		}

		userID := uint(userIDFloat)

		// Pastikan user ID tidak 0
		if userID == 0 {
			ClearAuthCookie(w)

			w.Header().Set(
				"Content-Type",
				"application/json",
			)

			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid user ID",
			})

			return
		}

		// ========================================
		// Request body
		// ========================================

		var request CreatePostRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(
				w,
				"Invalid JSON",
				http.StatusBadRequest,
			)
			return
		}

		// ========================================
		// Bersihkan input
		// ========================================

		request.Title = strings.TrimSpace(request.Title)
		request.Content = strings.TrimSpace(request.Content)

		// ========================================
		// Validasi input
		// ========================================

		if request.Title == "" || request.Content == "" {
			http.Error(
				w,
				"Title and content are required",
				http.StatusBadRequest,
			)
			return
		}

		// ========================================
		// Buat post
		// ========================================

		post := models.BlogPost{
			Title:    request.Title,
			Content:  request.Content,
			AuthorID: userID,
		}

		// ========================================
		// Simpan database
		// ========================================

		if err := db.Create(&post).Error; err != nil {
			http.Error(
				w,
				"Failed to create post",
				http.StatusInternalServerError,
			)
			return
		}

		// ========================================
		// Response
		// ========================================

		w.Header().Set(
			"Content-Type",
			"application/json",
		)

		w.WriteHeader(http.StatusCreated)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Post created successfully",
			"data":    post,
		})
	}
}





func GetPost(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
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
			http.Error(
				w,
				"Invalid or expired token",
				http.StatusUnauthorized,
			)
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

		// Pastikan user_id ada
		_, ok = claims["user_id"].(float64)
		if !ok {
			http.Error(
				w,
				"Invalid user ID",
				http.StatusUnauthorized,
			)
			return
		}

		// =========================
		// Ambil ID Post dari URL
		// =========================
		id := strings.TrimPrefix(r.URL.Path, "/posts/")

		if id == "" {
			http.Error(
				w,
				"Post ID is required",
				http.StatusBadRequest,
			)
			return
		}

		// =========================
		// Cari Post + Author
		// =========================
		var post models.BlogPost

		err = db.Preload("Author").
			First(&post, id).Error

		if err != nil {

			if err == gorm.ErrRecordNotFound {
				http.Error(
					w,
					"Post not found",
					http.StatusNotFound,
				)
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Response
		// =========================
		w.Header().Set("Content-Type", "application/json")

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Post found",
			"data": map[string]interface{}{
				"id":          post.ID,
				"title":       post.Title,
				"content":     post.Content,
				"author_id":   post.AuthorID,
				"author_name": post.Author.Name,
				"created_at":  post.CreatedAt,
				"updated_at":  post.UpdatedAt,
			},
		})
	}
}



func GetAllPosts(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Hanya GET
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Ambil token dari cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
			return
		}

		tokenString := cookie.Value

		// Ambil JWT Secret
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			http.Error(
				w,
				"JWT secret is not configured",
				http.StatusInternalServerError,
			)
			return
		}

		// Validasi JWT
		token, err := jwt.Parse(
			tokenString,
			func(token *jwt.Token) (interface{}, error) {

				// Pastikan menggunakan HMAC
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(jwtSecret), nil
			},
		)

		// JWT expired / invalid
		if err != nil || !token.Valid {

			// Hapus cookie JWT
			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Token expired or invalid",
			})
			return
		}

		// Ambil claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid token claims",
			})
			return
		}

		// Ambil user_id dari JWT
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok || userIDFloat <= 0 {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid user ID",
			})
			return
		}

		// User ID dari JWT
		userID := uint(userIDFloat)

		// Ambil semua blog post
		var posts []models.BlogPost

		err = db.
			Preload("Author").
			Order("created_at DESC").
			Find(&posts).Error

		if err != nil {
			http.Error(
				w,
				"Failed to get posts",
				http.StatusInternalServerError,
			)
			return
		}

		// Response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		// Buat response
		data := make([]map[string]interface{}, 0, len(posts))

		for _, post := range posts {

			data = append(data, map[string]interface{}{
				"id":          post.ID,
				"title":       post.Title,
				"content":     post.Content,
				"author_id":   post.AuthorID,
				"author_name": post.Author.Name,
				"created_at":  post.CreatedAt,
				"updated_at":  post.UpdatedAt,
			})
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Posts retrieved successfully",
			"data":    data,
			"count":   len(data),
			"user_id": userID,
		})
	}
}



func UpdatePost(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Hanya PUT
		if r.Method != http.MethodPut {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Ambil token dari cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
			return
		}

		tokenString := cookie.Value

		// Ambil JWT Secret
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			http.Error(
				w,
				"JWT secret is not configured",
				http.StatusInternalServerError,
			)
			return
		}

		// Validasi JWT
		token, err := jwt.Parse(
			tokenString,
			func(token *jwt.Token) (interface{}, error) {

				// Pastikan menggunakan HMAC
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(jwtSecret), nil
			},
		)

		// JWT expired / invalid
		if err != nil || !token.Valid {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Token expired or invalid",
			})
			return
		}

		// Ambil claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid token claims",
			})
			return
		}

		// Ambil user_id dari JWT
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok || userIDFloat <= 0 {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid user ID",
			})
			return
		}

		userID := uint(userIDFloat)

		// Ambil ID blog dari URL
		// Contoh: PUT /posts/5
		id := strings.TrimPrefix(r.URL.Path, "/posts/")

		if id == "" {
			http.Error(
				w,
				"Post ID is required",
				http.StatusBadRequest,
			)
			return
		}

		// Cari blog berdasarkan ID
		var post models.BlogPost

		err = db.First(&post, id).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				http.Error(
					w,
					"Post not found",
					http.StatusNotFound,
				)
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// Pastikan user adalah pemilik blog
		if post.AuthorID != userID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "You are not allowed to update this post",
			})
			return
		}

		// Request body
		var request CreatePostRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(
				w,
				"Invalid JSON",
				http.StatusBadRequest,
			)
			return
		}

		// Bersihkan input
		request.Title = strings.TrimSpace(request.Title)
		request.Content = strings.TrimSpace(request.Content)

		// Validasi
		if request.Title == "" || request.Content == "" {
			http.Error(
				w,
				"Title and content are required",
				http.StatusBadRequest,
			)
			return
		}

		// Update HANYA title dan content
		post.Title = request.Title
		post.Content = request.Content

		if err := db.Save(&post).Error; err != nil {
			http.Error(
				w,
				"Failed to update post",
				http.StatusInternalServerError,
			)
			return
		}

		// Response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Post updated successfully",
			"data": map[string]interface{}{
				"id":         post.ID,
				"title":      post.Title,
				"content":    post.Content,
				"author_id":  post.AuthorID,
				"created_at": post.CreatedAt,
				"updated_at": post.UpdatedAt,
			},
		})
	}
}



func DeletePost(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Hanya DELETE
		if r.Method != http.MethodDelete {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Ambil token dari cookie
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
			return
		}

		tokenString := cookie.Value

		// Ambil JWT Secret
		jwtSecret := os.Getenv("JWT_SECRET")
		if jwtSecret == "" {
			http.Error(
				w,
				"JWT secret is not configured",
				http.StatusInternalServerError,
			)
			return
		}

		// Validasi JWT
		token, err := jwt.Parse(
			tokenString,
			func(token *jwt.Token) (interface{}, error) {

				// Pastikan menggunakan HMAC
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(jwtSecret), nil
			},
		)

		// JWT expired / invalid
		if err != nil || !token.Valid {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Token expired or invalid",
			})
			return
		}

		// Ambil claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid token claims",
			})
			return
		}

		// Ambil user_id dari JWT
		userIDFloat, ok := claims["user_id"].(float64)
		if !ok || userIDFloat <= 0 {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Invalid user ID",
			})
			return
		}

		userID := uint(userIDFloat)

		// Ambil ID blog dari URL
		// Contoh: DELETE /posts/5
		id := strings.TrimPrefix(r.URL.Path, "/posts/")

		if id == "" {
			http.Error(
				w,
				"Post ID is required",
				http.StatusBadRequest,
			)
			return
		}

		// Cari blog berdasarkan ID
		var post models.BlogPost

		err = db.First(&post, id).Error

		if err != nil {
			if err == gorm.ErrRecordNotFound {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)

				json.NewEncoder(w).Encode(map[string]interface{}{
					"message": "Post not found",
				})
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// Pastikan user adalah pemilik blog
		if post.AuthorID != userID {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "You are not allowed to delete this post",
			})
			return
		}

		// Hapus blog
		if err := db.Delete(&post).Error; err != nil {
			http.Error(
				w,
				"Failed to delete post",
				http.StatusInternalServerError,
			)
			return
		}

		// Response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Post deleted successfully",
			"id":      post.ID,
		})
	}
}



func CreateComment(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Hanya POST
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// =========================
		// Ambil token dari cookie
		// =========================
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
			return
		}

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
			cookie.Value,
			func(token *jwt.Token) (interface{}, error) {

				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(jwtSecret), nil
			},
		)

		if err != nil || !token.Valid {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Token expired or invalid",
			})
			return
		}

		// =========================
		// Ambil user_id dari JWT
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

		userIDFloat, ok := claims["user_id"].(float64)

		if !ok {
			http.Error(
				w,
				"Invalid user ID",
				http.StatusUnauthorized,
			)
			return
		}

		userID := uint(userIDFloat)

		// =========================
		// Ambil user dari database
		// =========================
		var user models.User

		if err := db.First(&user, userID).Error; err != nil {

			if err == gorm.ErrRecordNotFound {
				http.Error(
					w,
					"User not found",
					http.StatusUnauthorized,
				)
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Ambil ID post dari URL
		// /posts/5/comments
		// =========================
		path := strings.TrimPrefix(r.URL.Path, "/posts/")
		path = strings.TrimSuffix(path, "/comments")
		path = strings.Trim(path, "/")

		if path == "" {
			http.Error(
				w,
				"Post ID is required",
				http.StatusBadRequest,
			)
			return
		}

		postID, err := strconv.ParseUint(path, 10, 64)

		if err != nil || postID == 0 {
			http.Error(
				w,
				"Invalid post ID",
				http.StatusBadRequest,
			)
			return
		}

		// =========================
		// Pastikan post ada
		// =========================
		var post models.BlogPost

		if err := db.First(&post, uint(postID)).Error; err != nil {

			if err == gorm.ErrRecordNotFound {
				http.Error(
					w,
					"Post not found",
					http.StatusNotFound,
				)
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Decode JSON
		// =========================
		var request CreateCommentRequest

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(
				w,
				"Invalid JSON",
				http.StatusBadRequest,
			)
			return
		}

		// =========================
		// Bersihkan content
		// =========================
		request.Content = strings.TrimSpace(request.Content)

		// =========================
		// Validasi content
		// =========================
		if request.Content == "" {
			http.Error(
				w,
				"Content is required",
				http.StatusBadRequest,
			)
			return
		}

		// =========================
		// Buat comment
		// =========================
		comment := models.Comment{
			PostID:     uint(postID),
			AuthorName: user.Name,
			Content:    request.Content,
		}

		if err := db.Create(&comment).Error; err != nil {
			http.Error(
				w,
				"Failed to create comment",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Response
		// =========================
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Comment created successfully",
			"data": map[string]interface{}{
				"id":          comment.ID,
				"post_id":     comment.PostID,
				"author_name": comment.AuthorName,
				"content":     comment.Content,
				"created_at":  comment.CreatedAt,
			},
		})
	}
}




func GetComments(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		// Hanya GET
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// =========================
		// Ambil token dari cookie
		// =========================
		cookie, err := r.Cookie("auth_token")
		if err != nil || cookie.Value == "" {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Unauthorized",
			})
			return
		}

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
			cookie.Value,
			func(token *jwt.Token) (interface{}, error) {

				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("unexpected signing method")
				}

				return []byte(jwtSecret), nil
			},
		)

		if err != nil || !token.Valid {

			ClearAuthCookie(w)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)

			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Token expired or invalid",
			})
			return
		}

		// =========================
		// Ambil ID post dari URL
		// /posts/5/comments
		// =========================
		path := strings.TrimPrefix(r.URL.Path, "/posts/")
		path = strings.TrimSuffix(path, "/comments")
		path = strings.Trim(path, "/")

		if path == "" {
			http.Error(
				w,
				"Post ID is required",
				http.StatusBadRequest,
			)
			return
		}

		postID, err := strconv.ParseUint(path, 10, 64)

		if err != nil || postID == 0 {
			http.Error(
				w,
				"Invalid post ID",
				http.StatusBadRequest,
			)
			return
		}

		// =========================
		// Pastikan post ada
		// =========================
		var post models.BlogPost

		if err := db.First(&post, uint(postID)).Error; err != nil {

			if err == gorm.ErrRecordNotFound {
				http.Error(
					w,
					"Post not found",
					http.StatusNotFound,
				)
				return
			}

			http.Error(
				w,
				"Database error",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Ambil semua comments
		// =========================
		var comments []models.Comment

		if err := db.
			Where("post_id = ?", uint(postID)).
			Order("created_at ASC").
			Find(&comments).Error; err != nil {

			http.Error(
				w,
				"Failed to get comments",
				http.StatusInternalServerError,
			)
			return
		}

		// =========================
		// Response
		// =========================
		data := make([]map[string]interface{}, 0, len(comments))

		for _, comment := range comments {
			data = append(data, map[string]interface{}{
				"id":          comment.ID,
				"post_id":     comment.PostID,
				"author_name": comment.AuthorName,
				"content":     comment.Content,
				"created_at":  comment.CreatedAt,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "Comments retrieved successfully",
			"data":    data,
			"count":   len(comments),
		})
	}
}
