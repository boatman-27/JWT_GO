// Package accountModels defines the data models for user accounts and related operations.
//
// It includes structs for representing user data stored in the database (`User`),
// input data for authentication (`LoginData`), sanitized user output (`SanitizedUser`),
// and payloads for creating new users, updating profiles, and changing passwords.
//
// These models use struct tags to map database fields (with sqlx) and JSON fields (for API responses).
//
// Example usage:
//
//	user := accountModels.User{}
//	err := config.DB.Get(&user, "SELECT * FROM users WHERE id=$1", 1)
//
//	newUser := accountModels.NewUser{
//	    Fname: "John",
//	    Lname: "Doe",
//	    Email: "john@example.com",
//	    Password: "SomePassword123",
//	    UserId: "penguin123",
//	}
//
// Note: The `Password` field should always be hashed before storing it in the database.
// The `SanitizedUser` struct can be used to safely return user info without exposing sensitive data.
package accountModels

// User represents a user account in the application.
//
// It contains personal details, account information, and gamification
// metrics such as coins, XP, level, and streaks.
type User struct {
	ID           int    `db:"id" json:"id"`                       // ID is the unique database identifier for the user.
	Fname        string `db:"fname" json:"fname"`                 // Fname is the user's first name.
	Lname        string `db:"lname" json:"lname"`                 // Lname is the user's last name.
	Email        string `db:"email" json:"email"`                 // Email is the user's email address.
	Password     string `db:"password" json:"password"`           // Password is the hashed user password.
	CreatedAt    string `db:"created_at" json:"created_at"`       // CreatedAt is the timestamp when the user account was created.
	UserId       string `db:"userid" json:"userid"`               // UserId is an optional custom user identifier.
	UserRole     string `db:"role" json:"role"`                   // UserRole defines the role or permissions for the user.
	Coins        int    `db:"coins" json:"coins"`                 // Coins represents the number of coins the user has earned.
	Xp           int    `db:"xp" json:"xp"`                       // Xp represents the user's experience points.
	Level        int    `db:"level" json:"level"`                 // Level indicates the user's current level.
	Streak       int    `db:"streak" json:"streak"`               // Streak shows how many days in a row the user has been active.
	FriendsCount int    `db:"friends_count" json:"friends_count"` // FriendsCount is the number of friends the user has.
	LastActive   string `db:"last_active" json:"last_active"`     // LastActive is the timestamp of the user's last activity.
}

// LoginData represents the credentials required for a user to log in.
type LoginData struct {
	Email    string // Email is the user's email address.
	Password string // Password is the user's plaintext password input.
}

// SanitizedUser represents a user object with sensitive fields removed.
//
// It is typically used for returning safe user data in API responses.
type SanitizedUser struct {
	Fname    string // Fname is the user's first name.
	Lname    string // Lname is the user's last name.
	Email    string // Email is the user's email address.
	UserId   string // UserId is the user's unique identifier.
	UserRole string // UserRole defines the user's role or permissions.
	Coins    int    // Coins represents the number of coins the user has.
	Xp       int    // Xp is the user's experience points.
	Level    int    // Level is the user's current level.
	Streak   int    // Streak is the user's current activity streak.
}

// NewUser represents the data required to create a new user account.
type NewUser struct {
	Fname    string `json:"fname"`    // Fname is the user's first name.
	Lname    string `json:"lname"`    // Lname is the user's last name.
	Email    string `json:"email"`    // Email is the user's email address.
	Password string `json:"password"` // Password is the user's plaintext password input.
	UserId   string `json:"userid"`   // UserId is a custom unique identifier for the user.
}

// UpdatedUser represents user profile data that can be updated.
type UpdatedUser struct {
	Fname string `db:"fname" json:"fname"` // Fname is the updated first name.
	Lname string `db:"lname" json:"lname"` // Lname is the updated last name.
	Email string `db:"email" json:"email"` // Email is the updated email address.
}

// ChangePasswordData represents the payload for changing a user's password.
type ChangePasswordData struct {
	OldPassword string `json:"oldPassword"` // OldPassword is the user's current password.
	NewPassword string `json:"newPassword"` // NewPassword is the user's new password.
	ConfirmNewP string `json:"confirmNewP"` // ConfirmNewP is the confirmation of the new password.
}
