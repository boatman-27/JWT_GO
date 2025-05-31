package accountModels

type User struct {
	ID           int    `db:"id" json:"id"`
	Fname        string `db:"fname" json:"fname"`
	Lname        string `db:"lname" json:"lname"`
	Email        string `db:"email" json:"email"`
	Password     string `db:"password" json:"password"`
	CreatedAt    string `db:"created_at" json:"created_at"`
	UserId       string `db:"userid" json:"userid"`
	UserRole     string `db:"role" json:"role"`
	Coins        int    `db:"coins" json:"coins"`
	Xp           int    `db:"xp" json:"xp"`
	Level        int    `db:"level" json:"level"`
	Streak       int    `db:"streak" json:"streak"`
	FriendsCount int    `db:"friends_count" json:"friends_count"`
	LastActive   string `db:"last_active" json:"last_active"`
}

type LoginData struct {
	Email    string
	Password string
}

type SanitizedUser struct {
	Fname    string
	Lname    string
	Email    string
	UserId   string
	UserRole string
	Coins    int
	Xp       int
	Level    int
	Streak   int
}

type NewUser struct {
	Fname    string `json:"fname"`
	Lname    string `json:"lname"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UserId   string `json:"userid"`
}
