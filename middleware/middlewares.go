package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
)


func ClearCache() gin.HandlerFunc{
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")

		c.Next()
	}
}


//Authorization to handle  authorization through middleware
func Authorization(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString:= c.GetHeader("Authorization")

		if tokenString==""{
			
			c.JSON(http.StatusUnauthorized,gin.H{"error":"Token is missing"})
			c.Abort()
			return
		}

		tokenString=strings.Replace(tokenString,"Bearer ","",1)

		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return []byte("101101"),nil
		})
		if err !=nil || !token.Valid {
			c.JSON(http.StatusUnauthorized,gin.H{"Error":"Invalid token"})
			c.Abort()
			return
		}

		claims,ok :=token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized,gin.H{"error":"Invalid token claims"})
			c.Abort()
			return
		}

		email,ok:=claims["email"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized,gin.H{"error": "Email missing in claims"})
			c.Abort()
			return
		}
		
		userIDf,ok:=claims["userid"].(float64)
		if !ok {
			c.JSON(http.StatusUnauthorized,gin.H{"error": "User ID missing in claims"})
			c.Abort()
			return
		}
		ClaimRole,ok:=claims["role"].(string)
		if !ok {
			c.JSON(http.StatusUnauthorized,gin.H{"error": "Role missing in claims"})
			c.Abort()
			return
		}
		if role!=ClaimRole{
			c.JSON(http.StatusUnauthorized,gin.H{"error":"Don't have permissions to access"})
			c.Abort()
			return
		}

		userID:=uint64(userIDf)

		c.Set("email",email)
		c.Set("user_id",userID)
		c.Next()
	}
}