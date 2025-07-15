// Package tokens provides helper functions for generating and validating
// JSON Web Tokens (JWTs) for user authentication and session management.
//
// This package supports generating short-lived access tokens and long-lived
// refresh tokens. It uses HMAC SHA-256 signing, with secret keys loaded
// from environment variables.
//
// Typical usage:
//   - GenerateAccessToken: create a JWT with a short expiration for authenticated routes.
//   - GenerateRefreshToken: create a longer-lived JWT for refreshing access tokens.
//   - ParseAndValidateToken: parse and verify a token's signature and claims.
//
// All secrets must be configured via the ACCESS_SECRET and REFRESH_SECRET
// environment variables for security. Tokens store basic claims such as
// UserId, Email, and exp (expiration time) for validating session state.
//
// Example:
//
//	accessToken, err := tokens.GenerateAccessToken(userID, email)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	refreshToken, err := tokens.GenerateRefreshToken(userID, email)
//
//	token, err := tokens.ParseAndValidateToken(refreshToken)
//	if err != nil || !token.Valid {
//	    // handle invalid token
//	}
package tokens

import (
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateAccessToken creates a signed JWT access token containing the user's ID and email.
//
// The token is signed with HMAC SHA-256 and expires after 15 minutes.
// The secret key is loaded from the ACCESS_SECRET environment variable.
//
// Parameters:
//   - userID: The unique ID of the user.
//   - email:  The email address of the user.
//
// Returns:
//   - string: The signed JWT token string.
//   - error:  An error if signing fails or the secret is missing.
func GenerateAccessToken(userID, email string) (string, error) {
	claims := jwt.MapClaims{
		"UserId": userID,
		"Email":  email,
		"exp":    time.Now().Add(15 * time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
}

// GenerateRefreshToken creates a signed JWT refresh token containing the user's ID and email.
//
// The refresh token is signed with HMAC SHA-256 and is valid for 7 days.
// The secret key is loaded from the REFRESH_SECRET environment variable.
//
// Use refresh tokens to issue new access tokens without requiring the user to log in again.
//
// Parameters:
//   - userID: The unique ID of the user.
//   - email:  The email address of the user.
//
// Returns:
//   - string: The signed JWT refresh token string.
//   - error:  An error if signing fails or the secret is missing.
func GenerateRefreshToken(userID, email string) (string, error) {
	claims := jwt.MapClaims{
		"UserId": userID,
		"Email":  email,
		"exp":    time.Now().Add(7 * 24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
}

// ParseAndValidateToken parses a JWT string and validates its signature and claims.
//
// It verifies that the token is signed with HMAC SHA-256 and checks its validity.
// By default, this function uses the REFRESH_SECRET for verification,
// but you can adapt it for access tokens as needed.
//
// Parameters:
//   - tokenStr: The JWT string to parse and validate.
//
// Returns:
//   - *jwt.Token: The parsed token if valid.
//   - error: An error if parsing or validation fails.
func ParseAndValidateToken(tokenStr string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		// Optional: Ensure the token's algorithm is what you expect
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
}
