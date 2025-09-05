package database

import (
	"strings"
	"database/sql"
	"secure-file-drop/config"
	"golang.org/x/crypto/bcrypt"
	_ "github.com/mattn/go-sqlite3"
)

func InitDB(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			password_hash TEXT,
			is_admin BOOLEAN DEFAULT FALSE
		);
		CREATE TABLE IF NOT EXISTS settings (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			allowed_extensions TEXT,
			blocked_extensions TEXT,
			max_upload_size_mb INTEGER
		);
		CREATE TABLE IF NOT EXISTS upload_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER,
			filename TEXT,
			size REAL,
			content_type TEXT,
			ip_address TEXT,
			status TEXT,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		return nil, err
	}

	// Initialize admin user
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", cfg.AdminUsername).Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.AdminPassword), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		_, err = db.Exec("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)", cfg.AdminUsername, string(hashedPassword), true)
		if err != nil {
			return nil, err
		}
	}

	// Initialize settings
	err = db.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count)
	if err != nil {
		return nil, err
	}
	if count == 0 {
		_, err = db.Exec("INSERT INTO settings (allowed_extensions, blocked_extensions, max_upload_size_mb) VALUES (?, ?, ?)",
			strings.Join(cfg.AllowedExtensions, ","), strings.Join(cfg.BlockedExtensions, ","), cfg.MaxUploadSizeMB)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}