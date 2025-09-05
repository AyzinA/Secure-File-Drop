package main

import (
	"log"
	"net/http"
	"os"
	"github.com/gorilla/mux"
	"secure-file-drop/config"
	"secure-file-drop/database"
	"secure-file-drop/handlers"
)

func main() {
	cfg := config.LoadConfig()
	log.Printf("Config loaded: Host=%s, Port=%s, UseTLS=%t, CertFile=%s, KeyFile=%s",
		cfg.Host, cfg.Port, cfg.UseTLS, cfg.CertFile, cfg.KeyFile)

	// Ensure base dirs exist (fail fast with a clear error)
	if err := os.MkdirAll(cfg.UploadDir, 0o775); err != nil {
		log.Fatalf("Upload base dir init failed for %s: %v", cfg.UploadDir, err)
	}
	if err := os.MkdirAll(cfg.DBDir, 0o775); err != nil {
		log.Fatalf("DB base dir init failed for %s: %v", cfg.DBDir, err)
	}

	db, err := database.InitDB(cfg)
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	defer db.Close()

	r := mux.NewRouter()
	handlers.RegisterHandlers(r, db, cfg)

	addr := cfg.Host + ":" + cfg.Port

	if cfg.UseTLS {
		// Check certs only if TLS is enabled
		if _, err := os.Stat(cfg.CertFile); os.IsNotExist(err) {
			log.Fatalf("Certificate file does not exist: %s", cfg.CertFile)
		}
		if _, err := os.Stat(cfg.KeyFile); os.IsNotExist(err) {
			log.Fatalf("Key file does not exist: %s", cfg.KeyFile)
		}
		log.Printf("Starting TLS server on %s", addr)
		if err := http.ListenAndServeTLS(addr, cfg.CertFile, cfg.KeyFile, r); err != nil {
			log.Fatal("TLS server failed:", err)
		}
	} else {
		log.Printf("Starting HTTP server on %s", addr)
		if err := http.ListenAndServe(addr, r); err != nil {
			log.Fatal("HTTP server failed:", err)
		}
	}
}
