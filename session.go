package main

import (
    "database/sql"
    "errors"
    "fmt"
    "net/http"

    _ "github.com/lib/pq" // Example for PostgreSQL, replace with your DB driver
)

var ErrUnauthorized = errors.New("unauthorized")

type User struct {
    Username      string
    SessionToken  string
    CSRFToken     string
}

func getUserFromDB(db *sql.DB, username string) (*User, error) {
    query := "SELECT username, session_token, csrf_token FROM users WHERE username = $1"
    row := db.QueryRow(query, username)

    var user User
    err := row.Scan(&user.Username, &user.SessionToken, &user.CSRFToken)
    if err != nil {
        if err == sql.ErrNoRows {
            return nil, ErrUnauthorized
        }
        return nil, err
    }

    return &user, nil
}

func Authorize(db *sql.DB, r *http.Request) error {
    username := r.FormValue("username")
    user, err := getUserFromDB(db, username)
    if err != nil {
        fmt.Printf("Error fetching user: %v\n", err)
        return ErrUnauthorized
    }

    // Get the session token from the request cookie
    st, err := r.Cookie("session_token")
    if err != nil || st.Value == "" || st.Value != user.SessionToken {
        fmt.Printf("Session token invalid\n")
        return ErrUnauthorized
    }

    // Get the CSRF token from the request header
    csrf := r.Header.Get("X-CSRF-Token")
    if csrf != user.CSRFToken {
        fmt.Printf("CSRF token mismatch: expected %s, got %s\n", user.CSRFToken, csrf)
        return ErrUnauthorized
    }

    if csrf == "" {
        fmt.Printf("CSRF token is empty\n")
        return ErrUnauthorized
    }

    return nil
}
