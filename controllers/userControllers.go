package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"
	"github.com/shivarajshanthaiah/unit-testing/auth"
	"github.com/shivarajshanthaiah/unit-testing/configuration"
	"github.com/shivarajshanthaiah/unit-testing/models"
)

// Global variables for validation, Redis operations, and user model
var validate = validator.New() // Validator instance for input validation
var globalUser models.User     // Global user variable for user operations

var (
	setRedis      = configuration.SetRedis // Redis set operation function
	getRedis      = configuration.GetRedis
	getOtp        = auth.GenerateOTP
	sendOtp       = auth.SendOTPByEmail
	verifyOtp     = auth.ValidateOTP
	create        = globalUser.CreateUser
	getUser       = globalUser.FetchUser
	hashPassword  = globalUser.HashPassword
	checkPassword = globalUser.CheckPassword
	generateToken = auth.GenerateToken
)

// UserLogin handles login and create jwt token
func UserLogin(c *gin.Context) {
	type login struct {
		Email    string `json:"email" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	var temp login

	if err := c.ShouldBindJSON(&temp); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "Failed",
			"message": "Binding error",
			"data":    err.Error(),
		})
	}

	if err := validate.Struct(temp); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "Failed",
			"message": "Please fill all fields",
		})
		return
	}

	// var user models.User
	// var err error
	user, err := getUser(temp.Email, configuration.DB)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "Failed",
			"message": "User not found",
		})
		return
	}
	// globalUser = *user

	if err := checkPassword(user, temp.Password); err == nil {
		token, err := generateToken(user.UserID, user.Email, user.Role)
		if err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"status": "Failed",
				"message": "Failed to generate token",
			})
			return
		}
		c.JSON(200, gin.H{"status": "Success",
			"message": "Login successful",
			"data":    token,
		})

		c.Header("Authorization", "Bearer "+token)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "Failed",
			"message": "Invalid password",
		})
	}

}

// UserSignup handles post signup form and validation
func UserSignup(c *gin.Context) {
	var user models.User

	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "Failed",
			"message": "Binding error",
			"data":    err.Error(),
		})
		return
	}

	if err := validate.Struct(user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "validation error",
		})
		return
	}

	if _, err := getUser(user.Email, configuration.DB); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already in use"})
		return
	}

	if err := hashPassword(&user, user.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "Failed",
			"message": "Failed to hash password",
		})
		return
	}
	// user.Password=string(hashedPassword)
	user.UserName = user.FirstName + " " + user.LastName

	otp := getOtp(6)
	if err := sendOtp(otp, user.Email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "Failed",
			"message": "Failed to send otp",
			"data":    err.Error(),
		})
		return
	}

	jsonData, err := json.Marshal(user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": "Failed",
			"message": "Failed to marshal json data",
			"data":    err.Error(),
		})
		return
	}

	if err := setRedis("otp"+user.Email, otp, 30*time.Second); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "Failed",
			"message": "Redis error",
		})
		return
	}

	if err := setRedis("user"+user.Email, jsonData, 120*time.Second); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": "Failed",
			"message": "Redis error",
			"data":    err.Error(),
		})
		return
	}

	fmt.Println(otp)

	c.JSON(http.StatusOK, gin.H{"message": "Go to user/signup-verification", "status": "true"})

}

// VerifyOTP handles verifying otp and saving user data in database
func VerifyOTP(c *gin.Context) {
	var userData models.User
	type OTPString struct {
		Email string `json:"email"`
		Otp   string `json:"otp"`
	}
	var user OTPString
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"status": "Failed",
			"message": "Binding error",
			"data":    err.Error(),
		})
		return
	}
	if user.Otp == "" {
		c.JSON(http.StatusNotFound, gin.H{"status": "Failed",
			"message": "OTP not entered",
		})
		return
	}

	otp, err := getRedis("otp" + user.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": "Failed",
			"message": "otp not found",
		})
		return
	}
	if verifyOtp(otp, user.Otp) {
		user, err := getRedis("user" + user.Email)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "Failed",
				"message": "User details missing",
				"data":    err.Error(),
			})
			return
		}
		err = json.Unmarshal([]byte(user), &userData)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"status": "Failed",
				"message": "Error in unmarshaling json data",
				"data":    err.Error(),
			})
			return
		}
		create(&userData, configuration.DB)
		c.JSON(http.StatusOK, gin.H{"status": "Success",
			"message": "Signup successful",
		})
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"status": "Failed",
			"message": "Otp mismatch",
		})
	}
}

// HomePage handles get homepage
func HomePage(c *gin.Context) {
	data, _ := c.Get("email")
	email := data.(string)

	c.JSON(http.StatusOK, gin.H{"status": "Success",
		"message": "Welcome to homepage",
		"data":    email,
	})
}

func LogOut(c *gin.Context) {
}
