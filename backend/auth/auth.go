package auth

import (
	"database/sql"
	"errors"
	"time"
	"github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Claims struct {
	Username string `json:"sub"`
	IsAdmin  bool   `json:"is_admin"`
	jwt.StandardClaims
}

func GenerateJWT(username string, isAdmin bool, secretKey string) (string, error) {
	claims := Claims{
		Username: username,
		IsAdmin:  isAdmin,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secretKey))
}

func ValidateJWT(tokenString string, secretKey string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil || !token.Valid {
		return nil, err
	}
	return claims, nil
}

func VerifyPassword(db *sql.DB, username, password string) (*User, error) {
	var user User
	err := db.QueryRow("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &user.PasswordHash, &user.IsAdmin)
	if err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	return &user, nil
}

type User struct {
	ID           int
	Username     string
	PasswordHash string
	IsAdmin      bool
}