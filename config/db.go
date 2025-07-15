// Package db provides application configuration utilities.
//
// It includes database connection management using sqlx with PostgreSQL.
// The ConnectDB function initializes a global sqlx.DB instance that is used
// throughout the application to interact with the database.
//
// Note: Update the PostgreSQL connection string in ConnectDB() with your
// actual database credentials and settings.
package db

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

// DB is the global database connection pool.
var DB *sqlx.DB

// ConnectDB initializes the connection to the PostgreSQL database
// using sqlx and assigns it to the global DB variable.
//
// It will terminate the application with log.Fatal if the connection fails.
func ConnectDB() {
	var err error

	DB, err = sqlx.Open("postgres", "user=postgres password=password dbname=adhamOsman sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}
