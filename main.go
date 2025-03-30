package main

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"server/config"
	"time"
    "strings"
	// "github.com/lib/pq"
)

// i need to store these values in a db so make a connection with a db called sql-converter and insert into it and fetch data from it
type Login struct {
	HashedPassword string
	SessionToken   string
	CSRFToken      string
}

type App struct {
    DB *sql.DB
}

// Database schema for the `sql-converter` database
/*
CREATE TABLE users (
	id SERIAL PRIMARY KEY,
	username VARCHAR(255) UNIQUE NOT NULL,
	hashed_password TEXT NOT NULL,
	session_token TEXT,
	csrf_token TEXT
);
*/


// Insert user data into the database
func insertUser(db *sql.DB, username string, login Login) error {
	query := `INSERT INTO users (username, hashed_password, session_token, csrf_token) VALUES ($1, $2, $3, $4)`
	_, err := db.Exec(query, username, login.HashedPassword, login.SessionToken, login.CSRFToken)
	return err
}

// Fetch user data from the database
func fetchUser(db *sql.DB, username string) (Login, error) {
	query := `SELECT hashed_password, session_token, csrf_token FROM users WHERE username = $1`
	row := db.QueryRow(query, username)

	var login Login
	err := row.Scan(&login.HashedPassword, &login.SessionToken, &login.CSRFToken)
	if err != nil {
		return Login{}, err
	}

	return login, nil
}

func main() {

    // Load the database configuration
    dbConfig := config.LoadDB()
    dbInstance, err := config.InitDB(dbConfig)
    if err != nil {
        log.Fatalf("Failed to connect to the database: %v", err)
    }
    defer dbInstance.Close()

    fmt.Println("Database connection successful!")
	defer dbInstance.Close()
	 
    app := &App{DB: dbInstance}

	if err!=nil {
		fmt.Printf("Database connection unsucessfull")
	}
	// Start the server
	fmt.Println("Server is running on port 8080...")


	fmt.Print("starting server....")
	// http.HandleFunc("/register", app.register)
	// http.HandleFunc("/login", app.login)
	// http.HandleFunc("/logout", app.logout)
	// http.HandleFunc("/protected", app.protected)
    http.HandleFunc("/query", app.query)
	http.ListenAndServe(":8080", nil)
}

func (app *App) query(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
        return
    }

    query := r.FormValue("query")
    if query == "" {
        http.Error(w, "Query parameter is required", http.StatusBadRequest)
        return
    }

    // Send POST request to the Flask app
    client := &http.Client{Timeout: 10 * time.Second}
    requestBody := fmt.Sprintf(`{"query": "%s"}`, query) // JSON body
    req, err := http.NewRequest("POST", "http://127.0.0.1:5000/query", strings.NewReader(requestBody))
    if err != nil {
        http.Error(w, "Failed to create request", http.StatusInternalServerError)
        return
    }
    req.Header.Set("Content-Type", "application/json") // Set JSON content type

    resp, err := client.Do(req)
    if err != nil {
        http.Error(w, "Failed to send request to external service", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        http.Error(w, "Failed to execute query on external service", resp.StatusCode)
        return
    }

    // Read response from the external service
    responseBody, err := io.ReadAll(resp.Body)
    if err != nil {
        http.Error(w, "Failed to read response from external service", http.StatusInternalServerError)
        return
    }

    // Send the response back to the client
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    w.Write(responseBody)
}

func (app *App) register(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    if len(username) < 8 || len(password) < 8 {
        http.Error(w, "Invalid username or password", http.StatusNotAcceptable)
        return
    }

    hashedPassword, _ := hashedPassword(password)
    login := Login{
        HashedPassword: hashedPassword,
    }

    // Insert user into the database
    err := insertUser(app.DB, username, login)
    if err != nil {
        http.Error(w, "Failed to register user", http.StatusInternalServerError)
        return
    }

    fmt.Fprint(w, "User registered successfully!")
}

func (app *App) login(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        er := http.StatusMethodNotAllowed
        http.Error(w, "Invalid request method", er)
        return
    }

    username := r.FormValue("username")
    password := r.FormValue("password")

    user, err := fetchUser(app.DB, username)
    if err != nil {
        er := http.StatusUnauthorized
        http.Error(w, "User doesn't exist", er)
        return
    }
    if !checkPassword(password, user.HashedPassword) {
        er := http.StatusUnauthorized
        http.Error(w, "Invalid username or password", er)
        return
    }

    sessionToken := generateToken(32)
    csrfToken := generateToken(32)

    // Set CSRF token in a cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_token",
        Value:    sessionToken,
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: true,
    })

    // Set CSRF token in a cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "csrf_token",
        Value:    csrfToken,
        Expires:  time.Now().Add(24 * time.Hour),
        HttpOnly: false, // Needs to be accessible to the client side
    })

    // Update tokens in the database
    user.SessionToken = sessionToken
    user.CSRFToken = csrfToken
    err = insertUser(app.DB, username, user)
    if err != nil {
        http.Error(w, "Failed to update tokens", http.StatusInternalServerError)
        return
    }

    fmt.Fprint(w, "Login successful!")
}

func (app *App) protected(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        er := http.StatusMethodNotAllowed
        http.Error(w, "Invalid request method", er)
        return
    }

    if err := Authorize(app.DB,r); err != nil {
        er := http.StatusUnauthorized
        http.Error(w, "Unauthorized", er)
        return
    }

    username := r.FormValue("username")
    fmt.Fprintf(w, "CSRF validation successful! Welcome, %s", username)
}

func (app *App) logout(w http.ResponseWriter, r *http.Request) {
    if err := Authorize(app.DB,r); err != nil {
        er := http.StatusUnauthorized
        http.Error(w, "Unauthorized", er)
        return
    }

    // Clear cookie
    http.SetCookie(w, &http.Cookie{
        Name:     "session_token",
        Value:    "",
        Expires:  time.Now().Add(-1 * time.Hour),
        HttpOnly: true,
    })

    http.SetCookie(w, &http.Cookie{
        Name:     "csrf_token",
        Value:    "",
        Expires:  time.Now().Add(-1 * time.Hour),
        HttpOnly: false, // Needs to be accessible to the client side
    })

    // Clear the tokens from the database
    username := r.FormValue("username")
    user, err := fetchUser(app.DB, username)
    if err != nil {
        http.Error(w, "Failed to fetch user", http.StatusInternalServerError)
        return
    }
    user.SessionToken = ""
    user.CSRFToken = ""
    err = insertUser(app.DB, username, user)
    if err != nil {
        http.Error(w, "Failed to clear tokens", http.StatusInternalServerError)
        return
    }

    fmt.Fprintln(w, "Logged out successfully!")
}
