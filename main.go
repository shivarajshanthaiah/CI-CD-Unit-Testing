package main

import (
	"github.com/gin-gonic/gin"
	"github.com/shivarajshanthaiah/unit-testing/configuration"
	"github.com/shivarajshanthaiah/unit-testing/routes"
)



func main() {
	configuration.Loadenv()
	configuration.InitRedis()
	r:=gin.Default()
	configuration.ConnectDB()
	routes.ConfigRoutes(r)

	r.Run("localhost:8080")
}