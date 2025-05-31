package db

import (
	"log"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

var DB *sqlx.DB

func ConnectDB() {
	var err error

	DB, err = sqlx.Open("postgres", "user=postgres password=Ao260221_@ dbname=adhamOsman sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}
