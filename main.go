/*
Package main is the entry point for the JWT_GO application.

This application sets up a RESTful HTTP server using the Gin web framework,
connects to a PostgreSQL database, and mounts all account-related routes for
authentication, registration, user management, and token handling.

Main responsibilities:
  - Connect to the database using the config package.
  - Register account routes via the accountRouter package.
  - Start the HTTP server on port 8000.

Example usage:

	go run main.go

Dependencies:
  - Gin for HTTP routing.
  - sqlx for database connectivity.
  - Internal packages for configuration and route management.
*/
package main

import (
	DB "github.com/boatman-27/JWT_GO/config"

	"github.com/gin-gonic/gin"

	accountRouter "github.com/boatman-27/JWT_GO/routes"
)

// main initializes the database connection, sets up routes, and starts the HTTP server.
//
// This function should be the only entry point for running the application.
func main() {
	router := gin.Default()
	DB.ConnectDB()
	accountRouter.AccountRouter(router)

	router.Run(":8000")
}
