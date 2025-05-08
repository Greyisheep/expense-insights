module github.com/Greyisheep/expense-insights/auth-service

go 1.23.0 // Or your target Go version

toolchain go1.23.2

require (
	github.com/google/uuid v1.6.0 // Add UUID library
	github.com/jackc/pgx/v5 v5.5.5 // Add pgx driver
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/wagslane/go-password-validator v0.3.0
	golang.org/x/crypto v0.38.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/text v0.25.0 // indirect
)
