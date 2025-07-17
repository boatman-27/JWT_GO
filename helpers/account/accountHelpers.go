// Package accountHelpers provides helper functions for managing user accounts.
//
// It includes reusable utilities for common account-related operations such as:
//   - Retrieving user data from the database
//   - Creating new user accounts
//   - Checking for existing emails or user IDs
//   - Updating user profile details and passwords
//   - Comparing plaintext and hashed passwords securely
//   - Sanitizing user data before sending it to clients
//
// This package interacts directly with the configured database connection (DB)
// and works alongside the accountModels package for defining user data structures.
//
// Typical use cases:
//   - Authenticating and validating user login credentials
//   - Enforcing uniqueness of user data (e.g., email, user ID)
//   - Safely returning user data without exposing sensitive fields like passwords
//
// Example:
//
//	user, err := accountHelpers.GetUserData("someone@example.com")
//	if err != nil {
//	    // handle error
//	}
//	if accountHelpers.ComparePasswords(inputPassword, user.Password) {
//	    sanitized := accountHelpers.SanitizeUser(user)
//	    // Return sanitized user data in response
//	}
//
// All functions assume a working global DB connection via the db package.
package accountHelpers

import (
	//"net/http"

	"time"

	// "github.com/gin-gonic/gin"
	accountModels "github.com/boatman-27/JWT_GO/models"

	DB "github.com/boatman-27/JWT_GO/config"

	"golang.org/x/crypto/bcrypt"
)

// GetUserData queries the database for a user by their email address.
//
// It performs a SELECT query on the `users` table to retrieve the user's
// ID, first name, last name, email, user ID, role, coins, XP, and hashed password.
//
// Parameters:
//   - email: The email address of the user to find.
//
// Returns:
//   - *accountModels.User: A pointer to the complete user data including sensitive fields like the password.
//     Returns nil if the user is not found or an error occurs.
//   - error: An error if the query fails or no user matches the provided email.func GetUserData(email string) (*accountModels.User, error) {
func GetUserData(email string) (*accountModels.User, error) {
	var user accountModels.User
	err := DB.DB.QueryRow("SELECT id, fname, lname, email, userid, role, coins, xp, password from users WHERE email = $1", email).
		Scan(&user.ID, &user.Fname, &user.Lname, &user.Email, &user.UserId, &user.UserRole, &user.Coins, &user.Xp, &user.Password)
	if err != nil {
		return nil, err // user not found
	}

	return &user, nil
}

// ComparePasswords compares a plaintext password with its hashed version
// using bcrypt's CompareHashAndPassword function.
//
// This is used to validate login attempts.
//
// Parameters:
//   - enteredPassword: The plaintext password entered by the user.
//   - hashedPassword: The hashed password stored in the database.
//
// Returns:
//   - bool: true if the passwords match, false otherwise.
func ComparePasswords(enteredPassword, hashedPassword string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(enteredPassword))
	return err == nil
}

// SanitizeUser removes sensitive fields from a User object,
// returning a SanitizedUser struct that can be safely sent
// back to the client in API responses.
//
// Parameters:
//   - user: A pointer to the User object to be sanitized.
//
// Returns:
//   - *accountModels.SanitizedUser: A pointer to the sanitized version of the created user.
//     Returns nil if the operation fails.
func SanitizeUser(user *accountModels.User) *accountModels.SanitizedUser {
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

	return &sanitized
}

// CheckIfEmailExists checks if there is any user in the database with the given email.
//
// It performs a COUNT query on the `users` table.
//
// Parameters:
//   - email: The email address to check.
//
// Returns:
//   - bool: true if at least one user with the email exists, false otherwise.
func CheckIfEmailExists(email string) bool {
	var emailCount int
	err := DB.DB.QueryRow("SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&emailCount)
	if err != nil {
		return false
	}
	return emailCount > 0
}

// CheckIfUserIdExists checks whether a user ID already exists in the database.
//
// Useful for ensuring user ID uniqueness during registration.
//
// Parameters:
//   - userid: The user ID to check.
//
// Returns:
//   - bool: true if the user ID exists, false otherwise.
func CheckIfUserIdExists(userid string) bool {
	var useridCount int
	err := DB.DB.QueryRow("SELECT COUNT(*) FROM users WHERE userid = $1", userid).Scan(&useridCount)
	if err != nil {
		return false
	}
	return useridCount > 0
}

// CreateNewUser inserts a new user record into the database and returns a sanitized pointer.
//
// It uses parameterized SQL to prevent SQL injection. The user is assigned a default
// role of "user", starts with zero coins and XP, level 1, and a zero streak.
//
// Parameters:
//   - newUser: A pointer to the NewUser struct containing user input data.
//   - hashedPassword: The bcrypt-hashed password to store securely.
//
// Returns:
//   - *accountModels.SanitizedUser: A pointer to the sanitized version of the created user.
//     Returns nil if the operation fails.
//   - error: An error if the insert or scan fails.
func CreateNewUser(newUser *accountModels.NewUser, hashedPassword string) (*accountModels.SanitizedUser, error) {
	var createdUser accountModels.User

	err := DB.DB.QueryRow(`
		INSERT INTO users (fname, lname, email, password, userid, role, coins, xp, level, streak, last_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING fname, lname, email, password, userid, role, coins, xp, level, streak, last_active
	`, newUser.Fname,
		newUser.Lname,
		newUser.Email,
		hashedPassword,
		newUser.UserId,
		"user",     // default role
		0,          // coins
		0,          // xp
		1,          // level
		0,          // streak
		time.Now(), // last_active timestamp
	).Scan(
		&createdUser.Fname, &createdUser.Lname, &createdUser.Email, &createdUser.Password,
		&createdUser.UserId, &createdUser.UserRole, &createdUser.Coins, &createdUser.Xp,
		&createdUser.Level, &createdUser.Streak, &createdUser.LastActive,
	)

	sanitized := SanitizeUser(&createdUser)
	return sanitized, err
}

// CheckEmailExistsForUpdate checks if another user (excluding the current user)
// already uses the specified email address.
//
// This is used to ensure email uniqueness during profile updates.
//
// Parameters:
//   - email: The new email to check.
//   - currentUserId: The user ID of the user making the update (excluded from the check).
//
// Returns:
//   - bool: true if another user uses the email, false otherwise.
func CheckEmailExistsForUpdate(email, currentUserId string) bool {
	var count int
	err := DB.DB.QueryRow(
		`SELECT COUNT(*) FROM users WHERE email = $1 AND userid != $2`,
		email, currentUserId,
	).Scan(&count)
	if err != nil {
		return false
	}

	return count > 0
}

// ModifyUser updates a user's profile details (first name, last name, and email)
// and returns the updated sanitized user.
//
// It ensures that only the user with the matching current email and user ID is updated.
// The update is performed using a parameterized SQL query to prevent SQL injection.
//
// Parameters:
//   - updatedUser: A pointer to the UpdatedUser struct containing the new values.
//   - currentEmail: The user's current email address used for matching.
//   - currentUserId: The user's unique ID used for matching.
//
// Returns:
//   - *accountModels.SanitizedUser: A pointer to the sanitized version of the updated user.
//     Returns nil if the update fails.
//   - error: An error if the update or scan operation fails.
func ModifyUser(updatedUser *accountModels.UpdatedUser, currentEmail, currentUserId string) (*accountModels.SanitizedUser, error) {
	var ModifiedUser accountModels.User

	err := DB.DB.QueryRow(
		`UPDATE users 
		SET fname = $1, lname = $2, email = $3
		WHERE email = $4 And userid = $5
		RETURNING fname, lname, email, password, userid, role, coins, xp, level, streak, last_active
		`, updatedUser.Fname, updatedUser.Lname, updatedUser.Email, currentEmail, currentUserId).
		Scan(&ModifiedUser.Fname, &ModifiedUser.Lname, &ModifiedUser.Email, &ModifiedUser.Password,
			&ModifiedUser.UserId, &ModifiedUser.UserRole, &ModifiedUser.Coins, &ModifiedUser.Xp,
			&ModifiedUser.Level, &ModifiedUser.Streak, &ModifiedUser.LastActive)

	sanitized := SanitizeUser(&ModifiedUser)
	return sanitized, err
}

// ModifyPassword updates a user's password hash in the database.
//
// It only updates the password for the user with the specified email.
// This function does not return the user object, only an error if the query fails.
//
// Parameters:
//   - hashedPassword: The new bcrypt-hashed password.
//   - email: The email of the user whose password should be updated.
//
// Returns:
//   - error: An error if the update fails.
func ModifyPassword(hashedPassword, email string) error {
	_, err := DB.DB.Exec(
		`UPDATE users
		SET password = $1
		WHERE email = $2
		`, hashedPassword, email)
	return err
}
