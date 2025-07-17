/*
Package accountRouter provides HTTP route handlers for user account management
in a Gin-based web application.

It includes routes and handlers for:
  - User registration and login
  - JWT-based authentication with access and refresh tokens
  - Token refresh and logout functionality
  - Fetching and updating authenticated user profile data
  - Password change operations
  - Retrieving all users (for administrative or demo purposes)
  - User authentication validation endpoint

The package integrates with middlewares (e.g., RequireAuth) to protect sensitive routes,
uses bcrypt for password hashing and comparison, and interacts with the database
via helper functions to manage user data.

Typical usage involves mounting the AccountRouter on a Gin Engine instance to expose
RESTful endpoints under the "/account" route group.

Example:

	router := gin.Default()
	accountRouter.AccountRouter(router)
	router.Run()

This package depends on:
  - github.com/gin-gonic/gin for HTTP routing and middleware
  - github.com/golang-jwt/jwt/v5 for JWT token creation and validation
  - golang.org/x/crypto/bcrypt for secure password hashing
  - Internal packages for database configuration, account helpers, and token helpers
*/
package accountRouter

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/boatman-27/JWT_GO/middlewares"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	DB "github.com/boatman-27/JWT_GO/config"
	accountHelpers "github.com/boatman-27/JWT_GO/helpers/account"
	tokenHelpers "github.com/boatman-27/JWT_GO/helpers/tokens"

	accountModels "github.com/boatman-27/JWT_GO/models"

	"golang.org/x/crypto/bcrypt"
)

/*
GetAllUsers is a Gin handler that retrieves all users from the database
and returns them in the HTTP response.

It performs a SELECT query on the `users` table to fetch basic user data,
including ID, first name, last name, email, user ID, role, coins, XP, and level.
For each row, it scans the result into an accountModels.User struct,
collects them into a slice, and sends them as JSON.

On success, it responds with HTTP 200 and an array of user objects.
If the database query or row scan fails, it responds with HTTP 500
and includes the error message in the response body.

Example:

router.GET("/users", accountRouter.GetAllUsers)

Response:

HTTP/1.1 200 OK
[

	{
	  "id": 1,
	  "fname": "John",
	  "lname": "Doe",
	  "email": "john@example.com",
	  "userid": "abc123",
	  "role": "user",
	  "coins": 100,
	  "xp": 50,
	  "level": 2
	},
	...

]
*/
func GetAllUsers(c *gin.Context) {
	var users []accountModels.User
	rows, err := DB.DB.Query("SELECT id, fname, lname, email, userid, role, coins, xp, level from users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	for rows.Next() {
		var user accountModels.User
		err := rows.Scan(&user.ID,
			&user.Fname,
			&user.Lname,
			&user.Email,
			&user.UserId,
			&user.UserRole,
			&user.Coins,
			&user.Level,
			&user.Xp,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		users = append(users, user)
	}
	c.JSON(http.StatusOK, users)
}

/*
Login handles user login requests by validating credentials and returning JWT tokens.

It expects a JSON body with "email" and "password" fields.
The handler workflow:
 1. Parses and validates the input JSON.
 2. Retrieves user data from the database by email.
 3. Compares the provided password with the stored hashed password.
 4. If valid, generates a short-lived access token and a long-lived refresh token.
 5. Sets the refresh token as an HTTP-only cookie with a 7-day expiry.
 6. Returns the sanitized user data and the access token in the JSON response.

Possible responses:
  - 400 Bad Request: If input JSON is invalid.
  - 401 Unauthorized: If email does not exist or password is incorrect.
  - 500 Internal Server Error: If token generation fails.

Example request body:

	{
	  "email": "user@example.com",
	  "password": "userpassword"
	}

Example success response:

HTTP/1.1 200 OK

	{
	  "user": { ...sanitized user data... },
	  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	}
*/
func Login(c *gin.Context) {
	var loginData accountModels.LoginData
	if err := c.ShouldBindJSON(&loginData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request data",
			"error":   err.Error(),
		})
		return
	}

	// get user data from DB :)
	user, err := accountHelpers.GetUserData(loginData.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Email does not exist",
			"error":   err.Error(),
		})
		return
	}

	// Check if passwords match
	if !accountHelpers.ComparePasswords(loginData.Password, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Incorrect Password",
		})
		return
	}

	// generating access and refresh tokens
	accessToken, err := tokenHelpers.GenerateAccessToken(user.UserId, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error generating Access Token",
			"error":   err.Error(),
		})
		return
	}

	refreshToken, err := tokenHelpers.GenerateRefreshToken(user.UserId, user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error generating Refresh Token",
			"error":   err.Error(),
		})
		return
	}

	c.SetCookie(
		"refreshToken", // cookie name
		refreshToken,   // value
		7*24*60*60,     // maxAge in seconds (7 days)
		"/",            // path
		"",             // domain (empty = current domain)
		false,          // secure (set true in production with HTTPS)
		true,           // httpOnly (can't be accessed by JS)
	)
	c.JSON(http.StatusOK, gin.H{
		"user":        accountHelpers.SanitizeUser(user),
		"accessToken": accessToken,
	})
}

/*
Register handles user registration by creating a new user account.

It expects a JSON body with user details including first name, last name,
email, password, and user ID.

The function workflow:
 1. Parses and validates the input JSON.
 2. Checks if the email or user ID already exists in the database.
 3. Hashes the provided password securely using bcrypt.
 4. Creates a new user record with the hashed password.
 5. Generates JWT access and refresh tokens for the new user.
 6. Sets the refresh token as an HTTP-only cookie with a 7-day expiration.
 7. Returns the sanitized user data and access token in the JSON response.

Possible responses:
  - 400 Bad Request: Invalid input data or duplicate email/userID, or password hashing failure.
  - 500 Internal Server Error: Token generation failure.

Example request body:

	{
	  "fname": "Jane",
	  "lname": "Doe",
	  "email": "jane@example.com",
	  "password": "securepassword",
	  "userid": "janedoe123"
	}

Example success response:

HTTP/1.1 200 OK

	{
	  "user": { ...sanitized user data... },
	  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	}
*/
func Register(c *gin.Context) {
	var newUser accountModels.NewUser

	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request data",
			"error":   err.Error(),
		})
		return
	}

	// check if email was used before
	if accountHelpers.CheckIfEmailExists(newUser.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email already exists",
		})
		return
	}

	// check if userid was used before
	if accountHelpers.CheckIfUserIdExists(newUser.UserId) {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "UserId already exists",
		})
		return
	}

	// Hash Password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Can't Hash Password",
			"error":   err.Error(),
		})
		return
	}

	// create and return Sanitized User
	sanitizedUser, err := accountHelpers.CreateNewUser(&newUser, string(hashedPassword))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Failed to create new User",
			"error":   err.Error(),
		})
		return
	}

	// create access and refresh tokens
	accessToken, err := tokenHelpers.GenerateAccessToken(sanitizedUser.UserId, sanitizedUser.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error generating Access Token",
			"error":   err.Error(),
		})
		return
	}

	refreshToken, err := tokenHelpers.GenerateRefreshToken(sanitizedUser.UserId, sanitizedUser.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error generating Refresh Token",
			"error":   err.Error(),
		})
		return
	}

	c.SetCookie(
		"refreshToken", // cookie name
		refreshToken,   // value
		7*24*60*60,     // maxAge in seconds (7 days)
		"/",            // path
		"",             // domain (empty = current domain)
		false,          // secure (set true in production with HTTPS)
		true,           // httpOnly (can't be accessed by JS)
	)

	c.JSON(http.StatusOK, gin.H{
		"user":        sanitizedUser,
		"accessToken": accessToken,
	})
}

/*
RefreshAccessToken handles the issuance of a new access token using a valid refresh token.

It expects the refresh token to be sent as an HTTP-only cookie named "refreshToken".

The function workflow:
 1. Retrieves the refresh token cookie from the request.
 2. Parses and validates the refresh token JWT.
 3. Extracts the UserId and Email claims from the token payload.
 4. Generates a new short-lived access token using these claims.
 5. Retrieves the user's latest data from the database.
 6. Responds with HTTP 200 including the sanitized user data and the new access token.

Possible responses:
  - 401 Unauthorized: If the refresh token is missing, invalid, or missing required claims.
  - 500 Internal Server Error: If generating the new access token fails.

Example usage:

Client sends a request with the "refreshToken" cookie set.
Server responds with a new access token and user info in JSON.

Example success response:

HTTP/1.1 200 OK

	{
	  "user": { ...sanitized user data... },
	  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	}
*/
func RefreshAccessToken(c *gin.Context) {
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Refresh Token not provided",
		})
		return
	}

	token, err := tokenHelpers.ParseAndValidateToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Invalid Refresh Token",
		})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Could not parse token claims"})
		return
	}

	// Destructring Claims
	userIDRaw, ok := claims["UserId"]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "UserId missing in token"})
		return
	}
	emailRaw, ok := claims["Email"]
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Email missing in token"})
		return
	}

	UserID, ok := userIDRaw.(string)
	Email, ok2 := emailRaw.(string)
	if !ok || !ok2 {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token payload"})
		return
	}

	// New Access Token
	newAccessToken, err := tokenHelpers.GenerateAccessToken(UserID, Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Could not generate access token"})
		return
	}

	fmt.Println(claims) // map[Email:adham4603@gmail.com exp:1.74893217e+09 UserId:Boatman]

	// get user data from DB :)
	user, err := accountHelpers.GetUserData(Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Email does not exist",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"user":        accountHelpers.SanitizeUser(user),
		"accessToken": newAccessToken,
	})
}

/*
Logout clears the user's refresh token cookie to effectively log the user out.

It sets the "refreshToken" cookie with an empty value and a negative max age,
instructing the browser to delete the cookie.

On success, it responds with HTTP 200 and a confirmation message.

Example usage:

Client sends a logout request.
Server clears the refresh token cookie and returns confirmation
*/
func Logout(c *gin.Context) {
	c.SetCookie("refreshToken", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

/*
Validate verifies the authenticated user's identity by retrieving and returning their sanitized data.

This handler expects the "Email" key to be set in the Gin context, typically by authentication middleware.

Workflow:
 1. Extracts the email from the context.
 2. Queries the database for the user's full data using the email.
 3. Handles errors such as missing email in context or user not found.
 4. Returns HTTP 200 with the sanitized user data upon successful validation.

Possible responses:
  - 401 Unauthorized: If the email is not found in the context (user not authenticated).
  - 404 Not Found: If no user exists with the provided email.
  - 500 Internal Server Error: If a database query error occurs.

Example usage:

Middleware sets "Email" in context after token validation.
Client calls /validate endpoint to confirm current user info.

Example success response:

HTTP/1.1 200 OK

	{
	  "message": "Validated",
	  "user": { ...sanitized user data... }
	}
*/
func Validate(c *gin.Context) {
	email, ok := c.Get("Email")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Email is not set",
		})
		return
	}

	userData, err := accountHelpers.GetUserData(email.(string))
	if err != nil {
		// Example: if GetUserData returns sql.ErrNoRows for missing user
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"message": "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to get user data",
		})
		return
	}

	user := accountHelpers.SanitizeUser(userData)
	c.JSON(http.StatusOK, gin.H{
		"message": "Validated",
		"user":    user,
	})
}

/*
GetCurrentUserData fetches and returns the authenticated user's sanitized data.

This handler expects the "Email" key to be set in the Gin context by authentication middleware.

Workflow:
 1. Retrieves the email from the context.
 2. Queries the database for the user's complete data using the email.
 3. Handles cases where the email is missing, user is not found, or a query error occurs.
 4. Returns HTTP 200 with the sanitized user data upon success.

Possible responses:
  - 401 Unauthorized: If the email is not present in the context (user not authenticated).
  - 404 Not Found: If no user exists with the provided email.
  - 500 Internal Server Error: If a database error occurs.

Example usage:

Middleware sets "Email" in context after verifying authentication.
Client calls /current-user endpoint to retrieve current user's info.

Example success response:

HTTP/1.1 200 OK

	{
	  "message": "User data fetched",
	  "user": { ...sanitized user data... }
	}
*/
func GetCurrentUserData(c *gin.Context) {
	email, ok := c.Get("Email")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Email is not set",
		})
		return
	}

	userData, err := accountHelpers.GetUserData(email.(string))
	if err != nil {
		// Example: if GetUserData returns sql.ErrNoRows for missing user
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{
				"message": "User not found",
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to get user data",
		})
		return
	}
	user := accountHelpers.SanitizeUser(userData)
	c.JSON(http.StatusOK, gin.H{
		"message": "User data fetched",
		"user":    user,
	})
}

/*
UpdateUser processes updates to the authenticated user's profile information.

It expects a JSON body containing updated user fields: first name, last name, and email.

Workflow:
 1. Parses and validates the input JSON.
 2. Retrieves the current user's email and user ID from the Gin context (set by middleware).
 3. If the email is changed, checks if the new email is already used by another user.
 4. Updates the user's information in the database.
 5. If the email was changed:
    - Clears the existing refresh token cookie.
    - Generates new access and refresh tokens with updated email claims.
    - Sets the new refresh token cookie.
    - Updates the Gin context values for email and user ID.
    - Returns the updated user data and new access token.
 6. Otherwise, returns the updated user data only.

Possible responses:
  - 400 Bad Request: Invalid input, missing context values, or new email already taken.
  - 500 Internal Server Error: Failure generating tokens.

Example request body:

	{
	  "fname": "Jane",
	  "lname": "Doe",
	  "email": "jane.new@example.com"
	}

Example success response (email changed):

HTTP/1.1 200 OK

	{
	  "user": { ...updated user data... },
	  "accessToken": "newAccessTokenHere"
	}

Example success response (email unchanged):

HTTP/1.1 200 OK

	{
	  "user": { ...updated user data... }
	}
*/
func UpdateUser(c *gin.Context) {
	var updatedUser accountModels.UpdatedUser

	if err := c.ShouldBindJSON(&updatedUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request data",
			"error":   err.Error(),
		})
		return

	}

	currentEmail, ok := c.Get("Email")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email is not set",
		})
		return
	}

	currentUserId, ok := c.Get("UserId")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "UserId is not set",
		})
		return
	}

	if updatedUser.Email != currentEmail {
		if accountHelpers.CheckEmailExistsForUpdate(updatedUser.Email, currentUserId.(string)) {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "The new email belongs to another user.",
			})
			return
		}
	}

	updatedUserData, err := accountHelpers.ModifyUser(&updatedUser, currentEmail.(string), currentUserId.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error Updating User data",
			"error":   err.Error(),
		})
		return
	}

	if updatedUser.Email != currentEmail {
		c.SetCookie("refreshToken", "", -1, "/", "", true, true)
		// generating access and refresh tokens
		accessToken, err := tokenHelpers.GenerateAccessToken(currentUserId.(string), updatedUserData.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error generating Access Token",
				"error":   err.Error(),
			})
			return
		}

		refreshToken, err := tokenHelpers.GenerateRefreshToken(currentUserId.(string), updatedUserData.Email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": "Error generating Refresh Token",
				"error":   err.Error(),
			})
			return
		}

		c.SetCookie(
			"refreshToken", // cookie name
			refreshToken,   // value
			7*24*60*60,     // maxAge in seconds (7 days)
			"/",            // path
			"",             // domain (empty = current domain)
			false,          // secure (set true in production with HTTPS)
			true,           // httpOnly (can't be accessed by JS)
		)

		c.Set("Email", updatedUser.Email)
		c.Set("UserId", currentUserId.(string))

		c.JSON(http.StatusOK, gin.H{
			"user":        updatedUserData,
			"accessToken": accessToken,
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"user": updatedUserData,
		})
	}
}

/*
ChangePassword handles the process of updating a user's password.

It expects a JSON payload containing the old password, the new password,
and a confirmation of the new password.

Workflow:
 1. Parses and validates the incoming JSON data.
 2. Checks that the new password and confirmation match.
 3. Retrieves the current user's email from the Gin context (set by authentication middleware).
 4. Fetches the user's current password hash from the database.
 5. Verifies the provided old password against the stored hashed password.
 6. Hashes the new password and updates it in the database.
 7. Returns a success message upon completion.

Possible responses:
  - 400 Bad Request: If request data is invalid or new passwords do not match.
  - 401 Unauthorized: If the old password is incorrect or email is not set.
  - 500 Internal Server Error: If password hashing or database update fails.

Example request body:

	{
	  "oldPassword": "oldPass123",
	  "newPassword": "newPass456",
	  "confirmNewP": "newPass456"
	}

Example success response:

HTTP/1.1 200 OK

	{
	  "message": "Password updated successfully"
	}
*/
func ChangePassword(c *gin.Context) {
	var changePasswordData accountModels.ChangePasswordData
	if err := c.ShouldBindJSON(&changePasswordData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request data",
			"error":   err.Error(),
		})
		return
	}

	if changePasswordData.NewPassword != changePasswordData.ConfirmNewP {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "New password and confirm password do not match",
		})
		return
	}

	currentEmail, ok := c.Get("Email")
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Email is not set",
		})
		return
	}

	// get user data from DB :)
	user, err := accountHelpers.GetUserData(currentEmail.(string))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Email does not exist",
			"error":   err.Error(),
		})
		return
	}

	// Check if old passwords match
	if !accountHelpers.ComparePasswords(changePasswordData.OldPassword, user.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Incorrect Password",
		})
		return
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(changePasswordData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Can't Hash Password",
			"error":   err.Error(),
		})
		return
	}

	err = accountHelpers.ModifyPassword(string(hashedPassword), currentEmail.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Could not update password",
			"error":   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Password updated successfully",
	})
}

/*
AccountRouter registers all account-related API routes on the provided Gin router.

Routes include:
  - GET    /account/users          : Retrieves all users.
  - POST   /account/login          : Authenticates a user and returns tokens.
  - POST   /account/refreshtoken  : Refreshes access token using a refresh token.
  - POST   /account/register       : Registers a new user.
  - POST   /account/logout         : Logs out a user by clearing the refresh token cookie.
  - GET    /account/validate       : Validates the current user's authentication status.
  - GET    /account/me             : Returns the authenticated user's data.
  - PUT    /account/update         : Updates the authenticated user's profile.
  - PUT    /account/changepassword : Changes the authenticated user's password.

Protected routes require a valid JWT access token via the `RequireAuth` middleware.
*/
func AccountRouter(router *gin.Engine) {
	accountRoutes := router.Group("/account")
	{
		accountRoutes.GET("/users", GetAllUsers)
		accountRoutes.POST("/login", Login)
		accountRoutes.POST("/refreshtoken", RefreshAccessToken)
		accountRoutes.POST("/register", Register)
		accountRoutes.POST("/logout", Logout)
		accountRoutes.GET("/validate", middlewares.RequireAuth, Validate)
		accountRoutes.GET("/me", middlewares.RequireAuth, GetCurrentUserData)
		accountRoutes.PUT("/update", middlewares.RequireAuth, UpdateUser)
		accountRoutes.PUT("/changepassword", middlewares.RequireAuth, ChangePassword)
	}
}
