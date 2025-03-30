package config

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"log"

	_ "github.com/lib/pq" // PostgreSQL driver
)

type DatabaseConfig struct {
	Host         string
	Port         int
	User         string
	Password     string
	DatabaseName string
	SSLMode      string
}

type Credentials struct {
	DatabasePassword string
}

var creds = Credentials{
	DatabasePassword: getEnv("DB_PASSWORD", "idkaboutum"),
}

func LoadDB() *DatabaseConfig {
	dbConfig := DatabaseConfig{
		Host:         getEnv("DB_HOST", "localhost"),
		Port:         getInt("DB_PORT", 5432),
		DatabaseName: getEnv("DB_NAME", "sql_converter"),
		User:         getEnv("DB_USER", "postgres"),
		Password:     creds.DatabasePassword,
		SSLMode:      getEnv("DB_SSL_MODE","require"),
	}

	return &dbConfig
}

// Initialize the database connection
func InitDB(dbConfig *DatabaseConfig) (*sql.DB, error) {
    connStr := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
        dbConfig.Host, dbConfig.Port, dbConfig.User, dbConfig.Password, dbConfig.DatabaseName, dbConfig.SSLMode)

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        return nil, fmt.Errorf("failed to open database connection: %w", err)
    }

    if err := db.Ping(); err != nil {
        if dbConfig.SSLMode == "require" && err.Error() == "pq: SSL is not enabled on the server" {
            log.Println("SSL is not enabled on the server. Retrying with sslmode=disable...")
            dbConfig.SSLMode = "disable"
            return InitDB(dbConfig) // Retry with sslmode=disable
        }
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }

    log.Println("Connected to the database successfully!")
    return db, nil
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func getInt(key string, defaultValue int) int {
	if value, exists := os.LookupEnv(key); exists {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// now i want to load this db and pass it all the handler fucntion
