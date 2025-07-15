// Package middlewares provides reusable middleware functions for securing routes
// and managing request authentication in your Gin web application.
//
// It includes helpers for verifying JWT access tokens, extracting user claims,
// and ensuring that only authenticated requests can access protected endpoints.
//
// Typical usage:
//
//	router := gin.Default()
//	router.Use(middlewares.RequireAuth)
//
// The RequireAuth middleware validates incoming JWT tokens, extracts user information,
// and attaches it to the request context for downstream handlers.
//
// All JWT secrets must be configured in environment variables for security.
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

// RequireAuth is a Gin middleware that ensures a valid JWT access token is provided
// in the Authorization header for protected routes.
//
// It expects the header in the format:
//
//	Authorization: Bearer <access_token>
//
// The middleware will:
//   - Verify that the header is present and correctly formatted.
//   - Parse the token using HMAC SHA-256 with the secret from ACCESS_SECRET.
//   - Validate the token's signature, expiration, and required claims.
//   - Abort the request with HTTP 401 if the token is invalid or expired.
//   - On success, attach the user's Email and UserId claims to the request context,
//     allowing downstream handlers to access them via c.Get("Email") and c.Get("UserId").
//
// Example:
//
//	router := gin.Default()
//	router.Use(middlewares.RequireAuth)
//
//	router.GET("/protected", func(c *gin.Context) {
//	    email := c.GetString("Email")
//	    userId := c.GetString("UserId")
//	    c.JSON(200, gin.H{"email": email, "userId": userId})
//	})
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
