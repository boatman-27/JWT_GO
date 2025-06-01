# JWT Authentication API with Go + Gin

This is a simple and secure user authentication and authorization API built with **Go** using the **Gin** web framework. It supports registration, login, access and refresh token generation, protected routes, and logout functionality using **JWT**.

## Features

- User Registration & Login
- Access Token (short-lived) & Refresh Token (long-lived)
- HttpOnly Cookies for secure refresh tokens
- Access Token Refresh Endpoint
- Middleware to protect routes (`RequireAuth`)
- User sanitization (no passwords in responses)
- Bcrypt password hashing
- PostgreSQL integration

---

## Users table SQL

```SQL
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    fname VARCHAR(255) NOT NULL,
    lname VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    userId VARCHAR(10) NOT NULL UNIQUE,
    role VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user'))

    -- Gamification fields
    coins INT DEFAULT 0 CHECK (coins >= 0), -- Users earn/spend coins through tasks & shop
    xp INT DEFAULT 0 CHECK (xp >= 0), -- Experience points for leveling up
    level INT DEFAULT 1 CHECK (level >= 1), -- Users rank up based on XP
    streak INT DEFAULT 0 CHECK (streak >= 0), -- Daily task completion streak

    -- Social features
    friends_count INT DEFAULT 0 CHECK (friends_count >= 0), -- Number of friends added
    leaderboard_rank INT DEFAULT NULL, -- Rank in global leaderboard
    last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP -- For activity tracking
);
```

---

## Quick start

### 1. Clone the repository

```bash
git clone https://github.com/boatman-27/JWT_GO
cd JWT_GO
```

### 2. Setup environment variables

Create a `.env` file and add your secrets and DB config:

```env
ACCESS_SECRET=your_access_secret
REFRESH_SECRET=your_refresh_secret
```

### 3. Install CompileDaemon (Optional)

Once installed, you can use `CompileDaemon` to watch your project files and recompile/run your Go application automatically on changes.

```Bash
go install github.com/githubnemo/CompileDaemon@latest
```

Add `export PATH="$HOME/go/bin:$PATH"` to your `shell` file (`.zshrc` or `.bashrc`)

### 4. Add an alias in your `shell` file (Optional)

```bash
alias gomon="CompileDaemon -build='go build -o myapp main.go' -command='./myapp'"
```

### 5. Run the application

If CompileDaemon is installed

```bash
gomon
```

OR if CompileDaemon is not installed

```
go run .
```

## API Endpoints

| Method | Endpoint                | Description               |
| ------ | ----------------------- | ------------------------- |
| POST   | `/account/register`     | Register a new user       |
| POST   | `/account/login`        | Login user and get tokens |
| POST   | `/account/refreshtoken` | Refresh access token      |
| GET    | `/account/validate`     | Validate access token     |
| GET    | `/account/users`        | Get all users             |
| POST   | `/account/logout`       | Logout (clear cookie)     |

#### Example JSON for Register

```JSON
{
	"fname": "John",
	"lname": "Doe",
	"email": "someemail@example.com",
	"password": "SomePassword",
	"userid": "penguin"
}
```

#### Example JSON for Register

```JSON
{
	"email": "someemail@example.com",
	"password": "SomePassword"
}
```

## How Authentication Works

1. **Login/Register**: Returns:
   - `accessToken` (JWT)
   - Sets `refreshToken` in `HttpOnly` cookie
2. **Access Token**: Used in `Authorization` header for protected routes
3. **Refresh Token**: Used to get a new access token when expired
4. **Logout**: Clears refresh token cookie

## Notes

- `accessToken` is short-lived (e.g. 15 mins)
- `refreshToken` is long-lived (e.g. 7 days) and stored in a secure cookie
- Tokens are signed with HMAC SHA256 using secrets from `.env`
