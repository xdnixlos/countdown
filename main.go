package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// --- DATENSTRUKTUREN ---
type RegisterPayload struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
type Countdown struct {
	ID         int       `json:"id"`
	Title      string    `json:"title"`
	TargetTime time.Time `json:"target_time"`
	ImageURL   string    `json:"image_url"`
}
type CreateCountdownPayload struct {
	Title      string    `json:"title"`
	TargetTime time.Time `json:"target_time"`
	ImageURL   string    `json:"image_url"`
}

// --- HELPER-FUNKTIONEN ---
func generateSessionToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// --- DATENBANK-LOGIK ---
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./countdown.db")
	if err != nil {
		log.Fatal("FATAL: Datenbankverbindung konnte nicht geöffnet werden: ", err)
	}
	userTable := `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL);`
	_, err = db.Exec(userTable)
	if err != nil {
		log.Fatal("FATAL: Tabelle 'users' konnte nicht erstellt werden: ", err)
	}
	sessionTable := `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expiry DATETIME NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id));`
	_, err = db.Exec(sessionTable)
	if err != nil {
		log.Fatal("FATAL: Tabelle 'sessions' konnte nicht erstellt werden: ", err)
	}
	countdownTable := `CREATE TABLE IF NOT EXISTS countdowns (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, title TEXT NOT NULL, target_time DATETIME NOT NULL, image_url TEXT, FOREIGN KEY(user_id) REFERENCES users(id));`
	_, err = db.Exec(countdownTable)
	if err != nil {
		log.Fatal("FATAL: Tabelle 'countdowns' konnte nicht erstellt werden: ", err)
	}
	log.Println("Datenbank erfolgreich initialisiert. Alle Tabellen sind bereit.")
}

// --- MIDDLEWARE ---
func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, `{"error": "Nicht authentifiziert"}`, http.StatusUnauthorized)
			return
		}
		sessionToken := cookie.Value
		var userID int
		var expiry time.Time
		err = db.QueryRow("SELECT user_id, expiry FROM sessions WHERE token = ?", sessionToken).Scan(&userID, &expiry)
		if err != nil || expiry.Before(time.Now()) {
			http.Error(w, `{"error": "Ungültige oder abgelaufene Session"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// --- API-HANDLER ---
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed); return }
	var payload RegisterPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { http.Error(w, `{"error": "Fehlerhafte Anfrage"}`, http.StatusBadRequest); return }
	if payload.Email == "" || payload.Password == "" { http.Error(w, `{"error": "E-Mail und Passwort sind erforderlich"}`, http.StatusBadRequest); return }
	hash, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil { http.Error(w, `{"error": "Interner Serverfehler"}`, http.StatusInternalServerError); log.Println("Fehler beim Hashing des Passworts:", err); return }
	_, err = db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", payload.Email, string(hash))
	if err != nil { if err.Error() == "UNIQUE constraint failed: users.email" { http.Error(w, `{"error": "Diese E-Mail-Adresse ist bereits vergeben"}`, http.StatusConflict) } else { http.Error(w, `{"error": "Interner Serverfehler"}`, http.StatusInternalServerError); log.Println("Fehler beim Einfügen des Benutzers:", err) }; return }
	log.Printf("Neuer Benutzer in DB gespeichert: E-Mail = %s", payload.Email)
	w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusCreated); fmt.Fprint(w, `{"message": "Benutzer erfolgreich registriert!"}`)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" { http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed); return }
	var payload struct { Email string `json:"email"`; Password string `json:"password"` }
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil { http.Error(w, `{"error": "Fehlerhafte Anfrage"}`, http.StatusBadRequest); return }
	var storedHash string; var userID int
	err := db.QueryRow("SELECT id, password_hash FROM users WHERE email = ?", payload.Email).Scan(&userID, &storedHash)
	if err != nil { if err == sql.ErrNoRows { http.Error(w, `{"error": "E-Mail oder Passwort ist ungültig"}`, http.StatusUnauthorized) } else { http.Error(w, `{"error": "Interner Serverfehler"}`, http.StatusInternalServerError); log.Println("Fehler bei der DB-Abfrage:", err) }; return }
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(payload.Password))
	if err != nil { http.Error(w, `{"error": "E-Mail oder Passwort ist ungültig"}`, http.StatusUnauthorized); return }
	token, err := generateSessionToken(); if err != nil { http.Error(w, `{"error": "Interner Serverfehler"}`, http.StatusInternalServerError); log.Println("Konnte Session-Token nicht erstellen:", err); return }
	expiry := time.Now().Add(24 * time.Hour)
	_, err = db.Exec("INSERT INTO sessions (token, user_id, expiry) VALUES (?, ?, ?)", token, userID, expiry); if err != nil { http.Error(w, `{"error": "Interner Serverfehler"}`, http.StatusInternalServerError); log.Println("Konnte Session nicht in DB speichern:", err); return }
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: token, Expires: expiry, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
	log.Printf("Benutzer (ID: %d) erfolgreich eingeloggt, Session-Cookie gesetzt.", userID)
	w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusOK); fmt.Fprint(w, `{"message": "Login erfolgreich!"}`)
}

func handleCheckAuth(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token"); if err != nil { if err == http.ErrNoCookie { http.Error(w, `{"error": "Nicht authentifiziert"}`, http.StatusUnauthorized) } else { http.Error(w, `{"error": "Fehlerhafte Anfrage"}`, http.StatusBadRequest) }; return }
	sessionToken := cookie.Value; var userID int; var expiry time.Time
	err = db.QueryRow("SELECT user_id, expiry FROM sessions WHERE token = ?", sessionToken).Scan(&userID, &expiry); if err != nil { http.Error(w, `{"error": "Ungültige Session"}`, http.StatusUnauthorized); return }
	if expiry.Before(time.Now()) { db.Exec("DELETE FROM sessions WHERE token = ?", sessionToken); http.Error(w, `{"error": "Session abgelaufen"}`, http.StatusUnauthorized); return }
	log.Printf("Gültige Session für Benutzer-ID %d gefunden.", userID)
	w.Header().Set("Content-Type", "application/json"); w.WriteHeader(http.StatusOK); fmt.Fprint(w, `{"authenticated": true}`)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_token")
	if err != nil { w.WriteHeader(http.StatusOK); return }
	_, _ = db.Exec("DELETE FROM sessions WHERE token = ?", cookie.Value)
	http.SetCookie(w, &http.Cookie{Name: "session_token", Value: "", Expires: time.Unix(0, 0), Path: "/"})
	log.Println("Benutzer ausgeloggt, Session und Cookie gelöscht.")
	w.WriteHeader(http.StatusOK)
}

func handleCountdowns(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("session_token")
	var userID int
	_ = db.QueryRow("SELECT user_id FROM sessions WHERE token = ?", cookie.Value).Scan(&userID)

	switch r.Method {
	case http.MethodGet:
		rows, _ := db.Query("SELECT id, title, target_time, image_url FROM countdowns WHERE user_id = ?", userID)
		defer rows.Close()
		var countdowns []Countdown
		for rows.Next() {
			var c Countdown
			_ = rows.Scan(&c.ID, &c.Title, &c.TargetTime, &c.ImageURL)
			countdowns = append(countdowns, c)
		}
		_ = json.NewEncoder(w).Encode(countdowns)
	case http.MethodPost:
		var payload CreateCountdownPayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		_, _ = db.Exec("INSERT INTO countdowns (user_id, title, target_time, image_url) VALUES (?, ?, ?, ?)", userID, payload.Title, payload.TargetTime, payload.ImageURL)
		w.WriteHeader(http.StatusCreated)
	case http.MethodDelete:
		parts := strings.Split(r.URL.Path, "/")
		idStr := parts[len(parts)-1]
		id, _ := strconv.Atoi(idStr)
		res, _ := db.Exec("DELETE FROM countdowns WHERE id = ? AND user_id = ?", id, userID)
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 0 { http.Error(w, `{"error": "Nicht gefunden"}`, http.StatusNotFound); return }
		log.Printf("Benutzer (ID: %d) hat Countdown (ID: %d) gelöscht.", userID, id)
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Methode nicht erlaubt", http.StatusMethodNotAllowed)
	}
}

// --- HAUPTFUNKTION (main) ---
func main() {
	initDB()
	defer db.Close()

	fileServer := http.FileServer(http.Dir("./static"))
	http.Handle("/", fileServer)

	http.HandleFunc("/api/register", handleRegister)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/check-auth", handleCheckAuth)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/countdowns/", authMiddleware(handleCountdowns))

	port := ":8080"
	log.Printf("Server startet auf Port %s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
