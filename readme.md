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

### 4. Add an alias in your `shell` file

```bash
alias gomon="CompileDaemon -build='go build -o myapp main.go' -command='./myapp'"
```

### 5. Run the application

```bash
gomon
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
