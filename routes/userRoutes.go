package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/shivarajshanthaiah/unit-testing/controllers"
)

func userRoutes(r *gin.Engine) {
	controllers.RegisterUserRoutes(r)

}
