package models

import "time"

type User struct {
	ID           int
	Username     string
	PasswordHash string
	IsAdmin      bool
}

type Settings struct {
	ID                int
	AllowedExtensions string
	BlockedExtensions string
	MaxUploadSizeMB   int
}

type UploadLog struct {
	ID          int
	UserID      int
	Filename    string
	Size        float64
	ContentType string
	IPAddress   string
	Status      string
	Timestamp   time.Time
}