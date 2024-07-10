package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/shivarajshanthaiah/unit-testing/middleware"
)

func ConfigRoutes(r *gin.Engine){

	r.Use(middleware.ClearCache())

	userRoutes(r)

}

