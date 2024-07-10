package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/shivarajshanthaiah/unit-testing/middleware"
)


func RegisterUserRoutes(r *gin.Engine) {
	// r.GET("/",IndexPage)
	r.POST("/login", UserLogin)
	r.POST("/signup", UserSignup)
	r.POST("/verifyotp", VerifyOTP)

	userGroup := r.Group("/user")
	userGroup.Use(middleware.Authorization("user"))
	{
		userGroup.GET("/home", HomePage)

	}
}