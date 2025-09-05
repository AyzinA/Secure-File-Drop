package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"secure-file-drop/auth"
	"secure-file-drop/config"
	"secure-file-drop/models"
	"golang.org/x/crypto/bcrypt"
)

type Handler struct {
	DB   *sql.DB
	Cfg  *config.Config
	Tmpl *template.Template
}

func RegisterHandlers(r *mux.Router, db *sql.DB, cfg *config.Config) {
	tmpl := template.Must(template.ParseGlob("templates/*.html"))
	h := &Handler{DB: db, Cfg: cfg, Tmpl: tmpl}

	r.HandleFunc("/", h.Index).Methods("GET")
	r.HandleFunc("/login", h.LoginPage).Methods("GET")
	r.HandleFunc("/login", h.Login).Methods("POST")
	r.HandleFunc("/logout", h.Logout).Methods("GET")

	// user area
	r.HandleFunc("/upload", h.AuthMiddleware(h.UploadPage)).Methods("GET")
	r.HandleFunc("/upload", h.AuthMiddleware(h.Upload)).Methods("POST")
	r.HandleFunc("/me", h.AuthMiddleware(h.MyAccountPage)).Methods("GET")
	r.HandleFunc("/me/password", h.AuthMiddleware(h.MyPasswordUpdate)).Methods("POST")

	// admin area
	r.HandleFunc("/admin", h.AuthMiddleware(h.AdminMiddleware(h.AdminPage))).Methods("GET")
	r.HandleFunc("/admin/users", h.AuthMiddleware(h.AdminMiddleware(h.CreateUser))).Methods("POST")
	r.HandleFunc("/admin/users/update", h.AuthMiddleware(h.AdminMiddleware(h.UpdateUser))).Methods("POST")
	r.HandleFunc("/admin/settings", h.AuthMiddleware(h.AdminMiddleware(h.UpdateSettings))).Methods("POST")
	r.HandleFunc("/logs", h.AuthMiddleware(h.AdminMiddleware(h.LogsPage))).Methods("GET")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	r.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}).Methods("GET")
}

func (h *Handler) Index(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("access_token"); err == nil && cookie.Value != "" {
		http.Redirect(w, r, "/upload", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("access_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		token := strings.TrimPrefix(cookie.Value, "Bearer ")
		claims, err := auth.ValidateJWT(token, h.Cfg.SecretKey)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r.Header.Set("X-Username", claims.Username)
		r.Header.Set("X-Is-Admin", fmt.Sprintf("%t", claims.IsAdmin))
		next(w, r)
	}
}

func (h *Handler) AdminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Is-Admin") != "true" {
			http.Error(w, "Admin access required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (h *Handler) LoginPage(w http.ResponseWriter, r *http.Request) {
	_ = h.Tmpl.ExecuteTemplate(w, "login.html", nil)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = h.Tmpl.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": "Bad request",
		})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := auth.VerifyPassword(h.DB, username, password)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_ = h.Tmpl.ExecuteTemplate(w, "login.html", map[string]any{
			"Error":    "Invalid credentials",
			"Username": username,
		})
		return
	}

	token, err := auth.GenerateJWT(user.Username, user.IsAdmin, h.Cfg.SecretKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = h.Tmpl.ExecuteTemplate(w, "login.html", map[string]any{
			"Error": "Failed to generate token",
		})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "Bearer " + token,
		HttpOnly: true,
		Secure:   h.Cfg.UseTLS,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	http.Redirect(w, r, "/upload", http.StatusSeeOther)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    "",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.Cfg.UseTLS,
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (h *Handler) UploadPage(w http.ResponseWriter, r *http.Request) {
	isAdmin := r.Header.Get("X-Is-Admin") == "true"
	_ = h.Tmpl.ExecuteTemplate(w, "upload.html", map[string]any{
		"IsAdmin": isAdmin,
	})
}

type uploadResult struct {
	Filename string `json:"filename"`
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	SizeMB   string `json:"size_mb,omitempty"`
}

func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(int64(h.Cfg.MaxUploadSizeMB) * 1024 * 1024); err != nil {
		http.Error(w, "File too large", http.StatusBadRequest)
		return
	}

	var settings models.Settings
	err := h.DB.QueryRow("SELECT allowed_extensions, blocked_extensions, max_upload_size_mb FROM settings LIMIT 1").
		Scan(&settings.AllowedExtensions, &settings.BlockedExtensions, &settings.MaxUploadSizeMB)
	if err != nil {
		http.Error(w, "Failed to load settings", http.StatusInternalServerError)
		return
	}

	// “*” allow-everything-except-blocked
	allowedIsStar := strings.TrimSpace(strings.ToLower(settings.AllowedExtensions)) == "*"
	allowed := splitNonEmpty(settings.AllowedExtensions)
	for i := range allowed {
		allowed[i] = strings.ToLower(allowed[i])
	}
	blocked := splitNonEmpty(settings.BlockedExtensions)
	for i := range blocked {
		blocked[i] = strings.ToLower(blocked[i])
	}
	maxSize := int64(settings.MaxUploadSizeMB) * 1024 * 1024

	username := r.Header.Get("X-Username")
	if username == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	var userID int
	if err := h.DB.QueryRow("SELECT id FROM users WHERE username = ?", username).Scan(&userID); err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	userUploadDir := path.Join(h.Cfg.UploadDir, username)
	if err := os.MkdirAll(userUploadDir, 0o775); err != nil {
		http.Error(w, "Failed to create upload directory", http.StatusInternalServerError)
		return
	}

	results := []uploadResult{}
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		http.Error(w, "No files received", http.StatusBadRequest)
		return
	}

	for _, fh := range files {
		res := uploadResult{Filename: fh.Filename}
		ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(fh.Filename), "."))

		status := "ok"
		if contains(blocked, ext) {
			status = "blocked-ext"
		} else if !allowedIsStar {
			if len(allowed) == 0 || !contains(allowed, ext) {
				status = "not-allowed"
			}
		}
		if status == "ok" && fh.Size > maxSize {
			status = "too-large"
		}

		ctype := fh.Header.Get("Content-Type")
		sizeMB := float64(fh.Size) / 1024.0 / 1024.0
		_, _ = h.DB.Exec(
			`INSERT INTO upload_logs (user_id, filename, size, content_type, ip_address, status)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			userID, fh.Filename, sizeMB, ctype, r.RemoteAddr, status,
		)

		if status != "ok" {
			res.Status = status
			res.Message = "Rejected by server policy"
			results = append(results, res)
			continue
		}

		src, err := fh.Open()
		if err != nil {
			res.Status = "open-failed"
			res.Message = err.Error()
			results = append(results, res)
			continue
		}
		defer src.Close()

		dstPath := path.Join(userUploadDir, fh.Filename)
		dst, err := os.Create(dstPath)
		if err != nil {
			res.Status = "save-failed"
			res.Message = err.Error()
			results = append(results, res)
			continue
		}
		if _, err := io.Copy(dst, src); err != nil {
			_ = dst.Close()
			res.Status = "write-failed"
			res.Message = err.Error()
			results = append(results, res)
			continue
		}
		_ = dst.Close()

		res.Status = "ok"
		res.SizeMB = fmt.Sprintf("%.2f", sizeMB)
		results = append(results, res)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"results": results})
}

func (h *Handler) AdminPage(w http.ResponseWriter, r *http.Request) {
	type userRow struct {
		ID       int
		Username string
		IsAdmin  bool
	}
	var users []userRow
	rows, err := h.DB.Query(`SELECT id, username, is_admin FROM users ORDER BY username`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var u userRow
			if err := rows.Scan(&u.ID, &u.Username, &u.IsAdmin); err == nil {
				users = append(users, u)
			}
		}
	}

	// Pull current settings for display + form defaults
	var allowedCSV, blockedCSV string
	var maxMB int
	_ = h.DB.QueryRow(`SELECT allowed_extensions, blocked_extensions, max_upload_size_mb FROM settings LIMIT 1`).
		Scan(&allowedCSV, &blockedCSV, &maxMB)

	// Read query parameters and map to human messages
	var okMsg, errMsg string
	switch r.URL.Query().Get("ok") {
	case "user-created":
		okMsg = "User created successfully."
	case "user-updated":
		okMsg = "User updated successfully."
	case "settings-updated":
		okMsg = "Settings saved."
	}
	switch r.URL.Query().Get("err") {
	case "user-exists":
		errMsg = "That username already exists."
	case "db":
		errMsg = "Database error. Please try again."
	case "bad-request":
		errMsg = "Bad request."
	}

	data := map[string]any{
		"Users": users,
		"Settings": map[string]any{
			"Allowed": allowedCSV,
			"Blocked": blockedCSV,
			"MaxMB":   maxMB,
		},
		"IsAdmin": true,
	}
	if okMsg != "" {
		data["OK"] = okMsg
	}
	if errMsg != "" {
		data["Error"] = errMsg
	}

	_ = h.Tmpl.ExecuteTemplate(w, "admin.html", data)
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	isAdmin := false

	var count int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", username).Scan(&count); err != nil {
		http.Error(w, "DB error", http.StatusInternalServerError)
		return
	}
	if count > 0 {
		http.Redirect(w, r, "/admin?err=user-exists", http.StatusSeeOther)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}
	if _, err := h.DB.Exec(
		"INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
		username, string(hashedPassword), isAdmin,
	); err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin?ok=user-created", http.StatusSeeOther)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	idStr := r.FormValue("user_id")
	newPass := r.FormValue("new_password")
	isAdmin := r.FormValue("is_admin") == "on"

	id, _ := strconv.Atoi(idStr)
	if id == 0 {
		http.Error(w, "Invalid user id", http.StatusBadRequest)
		return
	}

	if newPass != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash password", http.StatusInternalServerError)
			return
		}
		if _, err := h.DB.Exec("UPDATE users SET password_hash=?, is_admin=? WHERE id=?", string(hash), isAdmin, id); err != nil {
			http.Error(w, "Update failed", http.StatusInternalServerError)
			return
		}
	} else {
		if _, err := h.DB.Exec("UPDATE users SET is_admin=? WHERE id=?", isAdmin, id); err != nil {
			http.Error(w, "Update failed", http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/admin?ok=user-updated", http.StatusSeeOther)
}

func (h *Handler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	allowed := r.FormValue("allowed_extensions")
	blocked := r.FormValue("blocked_extensions")
	maxSize, err := strconv.Atoi(r.FormValue("max_upload_size_mb"))
	if err != nil {
		http.Error(w, "Invalid max upload size", http.StatusBadRequest)
		return
	}

	var count int
	if err := h.DB.QueryRow("SELECT COUNT(*) FROM settings").Scan(&count); err != nil {
		http.Error(w, "Failed to check settings", http.StatusInternalServerError)
		return
	}
	if count == 0 {
		_, err = h.DB.Exec(
			"INSERT INTO settings (allowed_extensions, blocked_extensions, max_upload_size_mb) VALUES (?, ?, ?)",
			allowed, blocked, maxSize,
		)
	} else {
		_, err = h.DB.Exec(
			"UPDATE settings SET allowed_extensions=?, blocked_extensions=?, max_upload_size_mb=?",
			allowed, blocked, maxSize,
		)
	}
	if err != nil {
		http.Error(w, "Failed to update settings", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin?ok=settings-updated", http.StatusSeeOther)
}

func (h *Handler) LogsPage(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.Query(`
		SELECT u.username, l.filename, l.size, l.content_type, l.ip_address, l.status, l.timestamp
		FROM upload_logs l
		JOIN users u ON u.id = l.user_id
		ORDER BY l.id DESC`)
	if err != nil {
		http.Error(w, "Failed to fetch logs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type row struct {
		Username    string
		Filename    string
		Size        float64
		ContentType string
		IPAddress   string
		Status      string
		Timestamp   string
	}
	var logs []row
	for rows.Next() {
		var rr row
		if err := rows.Scan(&rr.Username, &rr.Filename, &rr.Size, &rr.ContentType, &rr.IPAddress, &rr.Status, &rr.Timestamp); err != nil {
			http.Error(w, "Failed to scan logs", http.StatusInternalServerError)
			return
		}
		logs = append(logs, rr)
	}

	_ = h.Tmpl.ExecuteTemplate(w, "logs.html", map[string]any{
		"Logs":    logs,
		"IsAdmin": true,
	})
}

// ======== Me page helpers & password change with inline banners ========

type ulog struct {
	Filename, ContentType, IPAddress, Status, Timestamp string
	Size                                                float64
}

func (h *Handler) loadUserHistory(username string) ([]ulog, error) {
	rows, err := h.DB.Query(`
		SELECT filename, size, content_type, ip_address, status, timestamp
		FROM upload_logs
		WHERE user_id = (SELECT id FROM users WHERE username=?)
		ORDER BY id DESC`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []ulog
	for rows.Next() {
		var x ulog
		if err := rows.Scan(&x.Filename, &x.Size, &x.ContentType, &x.IPAddress, &x.Status, &x.Timestamp); err == nil {
			history = append(history, x)
		}
	}
	return history, nil
}

func (h *Handler) renderMe(w http.ResponseWriter, r *http.Request, username string, banner map[string]string) {
	isAdmin := r.Header.Get("X-Is-Admin") == "true"
	history, _ := h.loadUserHistory(username)
	data := map[string]any{
		"Username": username,
		"History":  history,
		"IsAdmin":  isAdmin,
	}
	if banner != nil {
		if msg, ok := banner["ok"]; ok {
			data["OK"] = msg
		}
		if msg, ok := banner["err"]; ok {
			data["Error"] = msg
		}
	}
	_ = h.Tmpl.ExecuteTemplate(w, "me.html", data)
}

func (h *Handler) MyAccountPage(w http.ResponseWriter, r *http.Request) {
	h.renderMe(w, r, r.Header.Get("X-Username"), nil)
}

// POST /me/password
// Checks: current_password correct, new_password == confirm_password
// Renders /me with inline success/error message (no raw API strings)
func (h *Handler) MyPasswordUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderMe(w, r, r.Header.Get("X-Username"), map[string]string{"err": "Bad request"})
		return
	}

	username := r.Header.Get("X-Username")
	current := r.FormValue("current_password")
	newPass := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if current == "" || newPass == "" || confirm == "" {
		h.renderMe(w, r, username, map[string]string{"err": "Please fill in all password fields"})
		return
	}
	if newPass != confirm {
		h.renderMe(w, r, username, map[string]string{"err": "New passwords do not match"})
		return
	}

	// Fetch user hash
	var hash string
	if err := h.DB.QueryRow(`SELECT password_hash FROM users WHERE username=?`, username).Scan(&hash); err != nil {
		h.renderMe(w, r, username, map[string]string{"err": "User not found"})
		return
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)); err != nil {
		h.renderMe(w, r, username, map[string]string{"err": "Current password is incorrect"})
		return
	}

	// Set new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		h.renderMe(w, r, username, map[string]string{"err": "Failed to hash new password"})
		return
	}
	if _, err := h.DB.Exec(`UPDATE users SET password_hash=? WHERE username=?`, string(newHash), username); err != nil {
		h.renderMe(w, r, username, map[string]string{"err": "Failed to update password"})
		return
	}

	h.renderMe(w, r, username, map[string]string{"ok": "Password updated successfully"})
}

// ======== helpers ========

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
func splitNonEmpty(csv string) []string {
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
