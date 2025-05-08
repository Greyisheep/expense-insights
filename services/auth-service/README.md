# Auth Service

## Overview
The Auth Service provides JWT-based authentication for the Expense Insights platform. It supports user registration, login, logout, token refresh, and retrieval of user information. The service is written in Go and is designed for secure, scalable authentication with support for access and refresh token rotation.

---

## Low-Level Design

### Flow Diagram
```mermaid
flowchart TD
    subgraph Client
        A1[Register]
        A2[Login]
        A3[Logout]
        A4[Refresh Token]
        A5[Get Me (Protected)]
    end
    subgraph AuthService
        B1[Validate Input]
        B2[User Repo]
        B3[Token Service]
        B4[Token Repo]
        B5[JWT Generation]
        B6[Set/Clear Cookie]
        B7[Return User Info]
    end
    subgraph Middleware
        M1[JWT Validation]
        M2[Context Injection]
    end

    %% Registration
    A1 -->|POST /register| B1 --> B2 -->|Create| B3 -->|Generate Tokens| B4 --> B5 --> B6 --> B7
    B7 -->|Access Token + Cookie| Client

    %% Login
    A2 -->|POST /login| B1 --> B2 -->|Find| B3 -->|Check Password| B4 -->|Generate Tokens| B5 --> B6 --> B7
    B7 -->|Access Token + Cookie| Client

    %% Logout
    A3 -->|POST /logout| B1 --> B3 -->|Revoke Refresh| B4 --> B6
    B6 -->|Clear Cookie| Client

    %% Refresh Token
    A4 -->|POST /refresh-token| B1 --> B3 -->|Validate/Rotate| B4 --> B5 --> B6
    B6 -->|Set New Cookie| Client

    %% Protected Route
    A5 -->|GET /me| M1 -->|Validate JWT| M2 --> B2 -->|Get User| B7 -->|User Info| Client
```

---

## API Endpoints

| Method | Path                   | Description                | Auth Required |
|--------|------------------------|----------------------------|---------------|
| POST   | /api/v1/auth/register  | Register new user          | No            |
| POST   | /api/v1/auth/login     | Login user                 | No            |
| POST   | /api/v1/auth/logout    | Logout (revoke refresh)    | No (cookie)   |
| POST   | /api/v1/auth/refresh-token | Refresh tokens         | No (cookie)   |
| GET    | /api/v1/auth/me        | Get current user info      | Yes (JWT)     |

---

## Token Handling
- **Access Token**: Short-lived JWT, sent in Authorization header (Bearer).
- **Refresh Token**: Long-lived, stored in HttpOnly cookie, rotated on use.
- **Rotation**: On refresh, old token is revoked and replaced. Reuse detection is enforced.
- **Revocation**: On logout or refresh, refresh tokens are revoked in DB.

---

## Middleware & Security
- **JWT Validation**: All protected routes require a valid access token.
- **Context Injection**: User ID and role are injected into request context after validation.
- **Error Handling**: Consistent error responses for invalid/missing tokens.
- **Password Policy**: Enforced minimum length and entropy.

---

## Configuration
- `AUTH_SERVICE_PORT`: Service port (default: 8080)
- `AUTH_DB_CONNECTION_STRING`: Database connection string
- `JWT_SECRET`: Secret for signing access tokens
- `REFRESH_SECRET`: Secret for signing refresh tokens
- `AUTH_ACCESS_TOKEN_TTL_MINUTES`: Access token TTL (default: 15)
- `AUTH_REFRESH_TOKEN_TTL_HOURS`: Refresh token TTL (default: 168)
- `AUTH_JWT_ISSUER`: JWT issuer (default: expense-insights-auth)

---

## Example Usage

### Register
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"StrongPass123!","first_name":"John","last_name":"Doe"}'
```

### Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"StrongPass123!"}'
```

### Logout
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  --cookie "refresh_token=..."
```

### Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh-token \
  --cookie "refresh_token=..."
```

### Get Current User
```bash
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

---

## Notes
- All responses are JSON.
- Refresh token is managed via HttpOnly cookie for security.
- Access token must be sent in the Authorization header for protected endpoints. 