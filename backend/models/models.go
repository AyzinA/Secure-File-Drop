package models

type Settings struct {
	ID                int
	AllowedExtensions string
	BlockedExtensions string
	MaxUploadSizeMB   int
}
