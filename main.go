package main

import (
	DB "github.com/boatman-27/config"

	"github.com/gin-gonic/gin"

	accountRouter "github.com/boatman-27/routes"
)

func main() {
	router := gin.Default()
	DB.ConnectDB()
	accountRouter.AccountRouter(router)

	router.Run(":8000")
}
