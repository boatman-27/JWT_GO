// Package config provides application configuration utilities.
//
// It includes database connection management using sqlx with PostgreSQL.
// The ConnectDB function initializes a global sqlx.DB instance that is used
// throughout the application to interact with the database.
//
// Example usage:
//
//    //     err := config.DB.Get(&user, "SELECT * FROM users WHERE id=$1", 1)
//     if err != nil {
//         log.Fatal(err)
//     }
//
// Note: Update the PostgreSQL connection string in ConnectDB() with your
// actual database credentials and settings.

package db

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DB *sqlx.DB

func ConnectDB() {
	var err error

	DB, err = sqlx.Open("postgres", "user=postgres password=password dbname=adhamOsman sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}
