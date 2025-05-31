package middlewares

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequireAuth(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header required"})
		c.Abort()
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header format must be Bearer {token}"})
		c.Abort()
		return
	}

	tokenStr := parts[1]
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid or malformed token",
			"error":   err.Error(),
		})
		c.Abort()
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		exp, ok := claims["exp"].(float64)

		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid expiration in token"})
			c.Abort()
			return
		}

		fmt.Println(exp, float64(time.Now().Unix()))

		if float64(time.Now().Unix()) > exp {
			c.JSON(http.StatusUnauthorized, gin.H{
				"message": "Access Token has expired",
			})
			c.Abort()
			return
		}

		email, emailOk := claims["Email"].(string)
		userId, userIdOk := claims["UserId"].(string)

		if !emailOk || !userIdOk {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Missing or invalid token claims"})
			c.Abort()
			return
		}

		c.Set("Email", email)
		c.Set("UserId", userId)

		c.Next()
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid Token claims",
		})
		c.Abort()
		return
	}
}
