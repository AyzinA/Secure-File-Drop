package config

import (
	"log"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	SecretKey         string
	AdminUsername     string
	AdminPassword     string
	UploadDir         string
	DBDir             string
	CertFile          string
	KeyFile           string
	Host              string
	Port              string
	UseTLS            bool
	AllowedExtensions []string
	BlockedExtensions []string
	MaxUploadSizeMB   int
	DatabaseURL       string
}

func LoadConfig() *Config {
	cfg := &Config{
		SecretKey:         os.Getenv("SECRET_KEY"),
		AdminUsername:     os.Getenv("ADMIN_USERNAME"),
		AdminPassword:     os.Getenv("ADMIN_PASSWORD"),
		UploadDir:         os.Getenv("UPLOAD_DIR"),
		DBDir:             os.Getenv("DB_DIR"),
		CertFile:          os.Getenv("CERT_FILE"),
		KeyFile:           os.Getenv("KEY_FILE"),
		Host:              os.Getenv("HOST"),
		Port:              os.Getenv("PORT"),
		AllowedExtensions: splitNonEmpty(os.Getenv("ALLOWED_EXTENSIONS")),
		BlockedExtensions: splitNonEmpty(os.Getenv("BLOCKED_EXTENSIONS")),
		MaxUploadSizeMB:   10,
		DatabaseURL:       "file:" + os.Getenv("DB_DIR") + "/app.db?cache=shared",
		UseTLS:            strings.ToLower(os.Getenv("USE_TLS")) != "false",
	}

	if cfg.Host == "" {
		cfg.Host = "0.0.0.0"
	}
	if cfg.Port == "" {
		cfg.Port = "8000"
	}
	if size, err := strconv.Atoi(os.Getenv("MAX_UPLOAD_SIZE_MB")); err == nil {
		cfg.MaxUploadSizeMB = size
	}

	log.Printf("Database URL: %s", cfg.DatabaseURL)
	return cfg
}

func splitNonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
