package accountRouter

import (
	"fmt"
	"jwt/middlewares"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	DB "jwt/config"
	accountHelpers "jwt/helpers/account"
	tokenHelpers "jwt/helpers/tokens"

	accountModels "jwt/models"

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
	c.JSON(http.StatusOK, gin.H{
		"message": "Validated",
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
	}
}
