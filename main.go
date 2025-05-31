package main

import (
	DB "jwt/config"

	"github.com/gin-gonic/gin"

	accountRouter "jwt/routes"
)

func main() {
	router := gin.Default()
	DB.ConnectDB()
	accountRouter.AccountRouter(router)

	router.Run(":8000")
}
