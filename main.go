package main

import (
	DB "github.com/boatman-27/JWT_GO/config"

	"github.com/gin-gonic/gin"

	accountRouter "github.com/boatman-27/JWT_GO/routes"
)

func main() {
	router := gin.Default()
	DB.ConnectDB()
	accountRouter.AccountRouter(router)

	router.Run(":8000")
}
