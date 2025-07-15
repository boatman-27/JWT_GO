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
	accountHelpers "github.com/boatman-27/helpers/account"
	tokenHelpers "github.com/boatman-27/helpers/tokens"

	accountModels "github.com/boatman-27/models"

	"golang.org/x/crypto/bcrypt"
)

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
	sanitizedUser, err := accountHelpers.CreateNewUser(newUser, string(hashedPassword))
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

func Logout(c *gin.Context) {
	c.SetCookie("refreshToken", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

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

	updatedUserData, err := accountHelpers.ModifyUser(updatedUser, currentEmail.(string), currentUserId.(string))
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

func ChangePassword(c *gin.Context) {
	var changePasswordData accountModels.ChangePasswordData
	if err := c.ShouldBindJSON(&changePasswordData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request data",
			"error":   err.Error(),
		})
		return
	}
	fmt.Println(changePasswordData.NewPassword, changePasswordData.ConfirmNewP)

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
		accountRoutes.PUT("changepassword", middlewares.RequireAuth, ChangePassword)
	}
}
