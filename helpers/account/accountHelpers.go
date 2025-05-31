package accountHelpers

import (
	//"net/http"
	"fmt"
	"time"

	// "github.com/gin-gonic/gin"
	DB "jwt/config"
	accountModels "jwt/models"

	"golang.org/x/crypto/bcrypt"
)

func GetUserData(email string) (accountModels.User, error) {
	var user accountModels.User

	err := DB.DB.QueryRow("SELECT id, fname, lname, email, userid, role, coins, xp, password from users WHERE email = $1", email).
		Scan(&user.ID, &user.Fname, &user.Lname, &user.Email, &user.UserId, &user.UserRole, &user.Coins, &user.Xp, &user.Password)
	if err != nil {
		return accountModels.User{}, err
	}

	return user, nil
}

func ComparePasswords(enteredPassword, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	return err == nil
}

func SanitizeUser(user accountModels.User) accountModels.SanitizedUser {
	sanitized := accountModels.SanitizedUser{
		Fname:    user.Fname,
		Lname:    user.Lname,
		Email:    user.Email,
		UserId:   user.UserId,
		UserRole: user.UserRole,
		Coins:    user.Coins,
		Xp:       user.Xp,
		Level:    user.Level,
		Streak:   user.Streak,
	}

	return sanitized
}

func CheckIfEmailExists(email string) bool {
	var emailCount int
	err := DB.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&emailCount)
	if err != nil {
		return false
	}
	return emailCount > 0
}

func CheckIfUserIdExists(userid string) bool {
	var useridCount int
	fmt.Println(userid)
	err := DB.DB.QueryRow("SELECT COUNT(*) FROM users WHERE userid = $1", userid).Scan(&useridCount)
	if err != nil {
		return false
	}
	return useridCount > 0
}

func CreateNewUser(newUser accountModels.NewUser, hashedPassword string) (accountModels.SanitizedUser, error) {
	var createdUser accountModels.User

	err := DB.DB.QueryRow(`
		INSERT INTO users (fname, lname, email, password, userid, role, coins, xp, level, streak, last_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING fname, lname, email, password, userid, role, coins, xp, level, streak, last_active
	`, newUser.Fname, newUser.Lname, newUser.Email, hashedPassword, newUser.UserId, "user", 0, 0, 1, 0, time.Now()).
		Scan(&createdUser.Fname, &createdUser.Lname, &createdUser.Email, &createdUser.Password,
			&createdUser.UserId, &createdUser.UserRole, &createdUser.Coins, &createdUser.Xp,
			&createdUser.Level, &createdUser.Streak, &createdUser.LastActive)

	return SanitizeUser(createdUser), err
}
