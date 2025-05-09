package auth

import (
	"context"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/Greyisheep/expense-insights/auth-service/internal/token"
	"github.com/Greyisheep/expense-insights/auth-service/internal/user"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// MockUserRepository is a mock type for the user.Repository type
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(ctx context.Context, usr *user.User) (*user.User, error) {
	args := m.Called(ctx, usr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*user.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserRepository) FindByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

func (m *MockUserRepository) Update(ctx context.Context, usr *user.User) (*user.User, error) {
	args := m.Called(ctx, usr)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*user.User), args.Error(1)
}

// MockTokenRepository is a mock type for the token.Repository type
type MockTokenRepository struct {
	mock.Mock
}

func (m *MockTokenRepository) Create(ctx context.Context, tkn *token.RefreshToken) (*token.RefreshToken, error) {
	args := m.Called(ctx, tkn)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.RefreshToken), args.Error(1)
}

func (m *MockTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*token.RefreshToken, error) {
	args := m.Called(ctx, tokenHash)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.RefreshToken), args.Error(1)
}

func (m *MockTokenRepository) MarkRevoked(ctx context.Context, tokenID uuid.UUID) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockTokenRepository) MarkReplaced(ctx context.Context, oldTokenID, newTokenID uuid.UUID) error {
	args := m.Called(ctx, oldTokenID, newTokenID)
	return args.Error(0)
}

// SetReplacedBy implements token.Repository
func (m *MockTokenRepository) SetReplacedBy(ctx context.Context, tokenID uuid.UUID, replacedBy uuid.UUID) error {
	args := m.Called(ctx, tokenID, replacedBy)
	return args.Error(0)
}

// CleanupExpired implements token.Repository
func (m *MockTokenRepository) CleanupExpired(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

// DeleteByUserID implements token.Repository
func (m *MockTokenRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	var count int64
	if arg0 := args.Get(0); arg0 != nil {
		count = arg0.(int64)
	}
	return count, args.Error(1)
}

// FindByID implements token.Repository
func (m *MockTokenRepository) FindByID(ctx context.Context, id uuid.UUID) (*token.RefreshToken, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*token.RefreshToken), args.Error(1)
}

// MockTokenService is a mock type for the token.Service type
type MockTokenService struct {
	mock.Mock
}

func (m *MockTokenService) GenerateAccessToken(ctx context.Context, userID uuid.UUID, userRole string) (string, error) {
	args := m.Called(ctx, userID, userRole)
	return args.String(0), args.Error(1)
}

func (m *MockTokenService) GenerateRefreshToken(ctx context.Context, userID uuid.UUID) (*token.RefreshToken, string, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, "", args.Error(2)
	}
	return args.Get(0).(*token.RefreshToken), args.String(1), args.Error(2)
}

func (m *MockTokenService) ValidateAccessToken(ctx context.Context, tokenString string) (*token.Claims, error) {
	args := m.Called(ctx, tokenString)
	var claims *token.Claims
	if arg0 := args.Get(0); arg0 != nil {
		claims = arg0.(*token.Claims)
	}
	return claims, args.Error(1)
}

func (m *MockTokenService) HashToken(tokenString string) string {
	args := m.Called(tokenString)
	return args.String(0)
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
}

func TestRegister_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository) // We don't expect this to be called in Register
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	password := "StrongPassword123!"
	firstName := "Test"
	lastName := "User"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	expectedUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		FirstName:    firstName,
		LastName:     lastName,
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}
	expectedAccessToken := "test_access_token"
	expectedRefreshTokenString := "test_refresh_token_string"
	expectedRefreshToken := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    expectedUser.ID,
		TokenHash: "hashed_refresh_token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(nil, user.ErrUserNotFound)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Run(func(args mock.Arguments) {
		argUser := args.Get(1).(*user.User)
		assert.Equal(t, email, argUser.Email)
		assert.NotEmpty(t, argUser.PasswordHash)
		assert.Equal(t, firstName, argUser.FirstName)
		assert.Equal(t, lastName, argUser.LastName)
		assert.Equal(t, user.StatusActive, argUser.Status)
		assert.Equal(t, user.RoleUser, argUser.Role)
	}).Return(expectedUser, nil)

	mockTokenSvc.On("GenerateAccessToken", ctx, expectedUser.ID, string(expectedUser.Role)).Return(expectedAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, expectedUser.ID).Return(expectedRefreshToken, expectedRefreshTokenString, nil)

	createdUser, accessToken, refreshToken, expiresAt, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.NoError(t, err)
	assert.NotNil(t, createdUser)
	assert.Equal(t, expectedUser.ID, createdUser.ID)
	assert.Equal(t, email, createdUser.Email)
	assert.Equal(t, accessToken, expectedAccessToken)
	assert.Equal(t, refreshToken, expectedRefreshTokenString)
	assert.Equal(t, expiresAt, expectedRefreshToken.ExpiresAt)

	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertExpectations(t)
}

func TestRegister_UserAlreadyExists(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "exists@example.com"
	password := "StrongPassword123!"
	firstName := "Existing"
	lastName := "User"

	mockUserRepo.On("FindByEmail", ctx, email).Return(&user.User{}, nil) // User found

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	assert.Equal(t, ErrUserAlreadyExists, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRegister_PasswordTooShort(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	password := "short"
	firstName := "Test"
	lastName := "User"

	// No repo calls expected

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	assert.Equal(t, ErrPasswordTooShort, err)
	mockUserRepo.AssertNotCalled(t, "FindByEmail")
	mockUserRepo.AssertNotCalled(t, "Create")
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRegister_PasswordNotStrongEnough(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	password := "weakpassword"
	firstName := "Test"
	lastName := "User"

	// No repo calls expected beyond FindByEmail if password check is first (which it is)

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	assert.Equal(t, ErrPasswordNotStrongEnough, err)
	mockUserRepo.AssertNotCalled(t, "FindByEmail")
	mockUserRepo.AssertNotCalled(t, "Create")
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRegister_CreateUserError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "createerror@example.com"
	password := "StrongPassword123!"
	firstName := "Create"
	lastName := "Error"

	mockUserRepo.On("FindByEmail", ctx, email).Return(nil, user.ErrUserNotFound)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(nil, assert.AnError) // Simulate DB error

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	assert.NotEqual(t, ErrUserAlreadyExists, err) // Ensure it's not a specific known error
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRegister_GenerateAccessTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "tokenerror@example.com"
	password := "StrongPassword123!"
	firstName := "Access"
	lastName := "TokenError"

	expectedUser := &user.User{ID: uuid.New(), Email: email, Role: user.RoleUser, Status: user.StatusActive}

	mockUserRepo.On("FindByEmail", ctx, email).Return(nil, user.ErrUserNotFound)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(expectedUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, expectedUser.ID, string(expectedUser.Role)).Return("", assert.AnError)

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertCalled(t, "GenerateAccessToken", ctx, expectedUser.ID, string(expectedUser.Role))
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRegister_GenerateRefreshTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "refreshtokenerror@example.com"
	password := "StrongPassword123!"
	firstName := "Refresh"
	lastName := "TokenError"

	expectedUser := &user.User{ID: uuid.New(), Email: email, Role: user.RoleUser, Status: user.StatusActive}
	expectedAccessToken := "test_access_token"

	mockUserRepo.On("FindByEmail", ctx, email).Return(nil, user.ErrUserNotFound)
	mockUserRepo.On("Create", ctx, mock.AnythingOfType("*user.User")).Return(expectedUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, expectedUser.ID, string(expectedUser.Role)).Return(expectedAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, expectedUser.ID).Return(nil, "", assert.AnError)

	_, _, _, _, err := authService.Register(ctx, email, password, firstName, lastName)

	assert.Error(t, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertCalled(t, "GenerateAccessToken", ctx, expectedUser.ID, string(expectedUser.Role))
	mockTokenSvc.AssertCalled(t, "GenerateRefreshToken", ctx, expectedUser.ID)
}

func TestLogin_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository) // Not directly used in login success path, but service requires it
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	password := "StrongPassword123!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userUUID := uuid.New()
	existingUser := &user.User{
		ID:           userUUID,
		Email:        email,
		PasswordHash: string(hashedPassword),
		FirstName:    "Test",
		LastName:     "User",
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	expectedAccessToken := "test_access_token"
	expectedRefreshTokenString := "test_refresh_token_string"
	expectedRefreshToken := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userUUID,
		TokenHash: "hashed_refresh_token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*user.User")).Run(func(args mock.Arguments) {
		updatedUser := args.Get(1).(*user.User)
		assert.Equal(t, userUUID, updatedUser.ID)
		assert.True(t, updatedUser.LastLoginAt.Valid)
		assert.WithinDuration(t, time.Now(), updatedUser.LastLoginAt.Time, 5*time.Second) // Check if LastLoginAt is recent
	}).Return(existingUser, nil) // Return the user, or a modified one if needed
	mockTokenSvc.On("GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role)).Return(expectedAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, existingUser.ID).Return(expectedRefreshToken, expectedRefreshTokenString, nil)

	loggedInUser, accessToken, refreshTokenStr, expiresAt, err := authService.Login(ctx, email, password)

	assert.NoError(t, err)
	assert.NotNil(t, loggedInUser)
	assert.Equal(t, existingUser.ID, loggedInUser.ID)
	assert.Equal(t, email, loggedInUser.Email)
	assert.Equal(t, accessToken, expectedAccessToken)
	assert.Equal(t, refreshTokenStr, expectedRefreshTokenString)
	assert.Equal(t, expiresAt, expectedRefreshToken.ExpiresAt)
	assert.True(t, loggedInUser.LastLoginAt.Valid)

	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertExpectations(t)
}

func TestLogin_UserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "nonexistent@example.com"
	password := "password123"

	mockUserRepo.On("FindByEmail", ctx, email).Return(nil, user.ErrUserNotFound)

	_, _, _, _, err := authService.Login(ctx, email, password)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestLogin_InvalidPassword(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	correctPassword := "StrongPassword123!"
	wrongPassword := "WrongPassword!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)

	_, _, _, _, err := authService.Login(ctx, email, wrongPassword)

	assert.Error(t, err)
	assert.Equal(t, ErrInvalidCredentials, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestLogin_AccountInactive(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "inactive@example.com"
	password := "StrongPassword123!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Status:       user.StatusInactive, // Key difference
		Role:         user.RoleUser,
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)

	_, _, _, _, err := authService.Login(ctx, email, password)

	assert.Error(t, err)
	assert.Equal(t, ErrAccountInactive, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestLogin_AccountPending(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "pending@example.com"
	password := "StrongPassword123!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Status:       user.StatusPending, // Key difference
		Role:         user.RoleUser,
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)

	_, _, _, _, err := authService.Login(ctx, email, password)

	assert.Error(t, err)
	assert.Equal(t, ErrAccountPending, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestLogin_GenerateAccessTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "accesstokenerror@example.com"
	password := "StrongPassword123!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role)).Return("", assert.AnError)

	_, _, _, _, err := authService.Login(ctx, email, password)

	assert.Error(t, err)
	assert.NotEqual(t, ErrInvalidCredentials, err) // Ensure it's not a credential error
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertCalled(t, "GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role))
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
	mockUserRepo.AssertNotCalled(t, "Update") // Should not attempt to update if token gen fails first
}

func TestLogin_GenerateRefreshTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "refreshtokenerror@example.com"
	password := "StrongPassword123!"
	expectedAccessToken := "test_access_token"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	existingUser := &user.User{
		ID:           uuid.New(),
		Email:        email,
		PasswordHash: string(hashedPassword),
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role)).Return(expectedAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, existingUser.ID).Return(nil, "", assert.AnError)

	_, _, _, _, err := authService.Login(ctx, email, password)

	assert.Error(t, err)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertCalled(t, "GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role))
	mockTokenSvc.AssertCalled(t, "GenerateRefreshToken", ctx, existingUser.ID)
	mockUserRepo.AssertNotCalled(t, "Update") // Should not attempt to update if token gen fails
}

func TestLogin_UpdateLastLoginError_StillSucceeds(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger() // In a real scenario, you might capture logs to verify the error was logged

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	email := "test@example.com"
	password := "StrongPassword123!"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	userUUID := uuid.New()
	existingUser := &user.User{
		ID:           userUUID,
		Email:        email,
		PasswordHash: string(hashedPassword),
		FirstName:    "Test",
		LastName:     "User",
		Status:       user.StatusActive,
		Role:         user.RoleUser,
	}

	expectedAccessToken := "test_access_token"
	expectedRefreshTokenString := "test_refresh_token_string"
	expectedRefreshToken := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userUUID,
		TokenHash: "hashed_refresh_token",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	mockUserRepo.On("FindByEmail", ctx, email).Return(existingUser, nil)
	mockUserRepo.On("Update", ctx, mock.AnythingOfType("*user.User")).Return(nil, assert.AnError) // Simulate error on update
	mockTokenSvc.On("GenerateAccessToken", ctx, existingUser.ID, string(existingUser.Role)).Return(expectedAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, existingUser.ID).Return(expectedRefreshToken, expectedRefreshTokenString, nil)

	loggedInUser, accessToken, refreshTokenStr, expiresAt, err := authService.Login(ctx, email, password)

	assert.NoError(t, err) // Login should still succeed
	assert.NotNil(t, loggedInUser)
	assert.Equal(t, existingUser.ID, loggedInUser.ID)
	assert.Equal(t, accessToken, expectedAccessToken)
	assert.Equal(t, refreshTokenStr, expectedRefreshTokenString)
	assert.Equal(t, expiresAt, expectedRefreshToken.ExpiresAt)
	// LastLoginAt on the returned user might not be updated if the DB call failed before user object modification in service layer.
	// The service code updates usr.LastLoginAt *before* calling s.userRepo.Update().
	// So, loggedInUser.LastLoginAt will be set, even if the DB update fails.
	assert.True(t, loggedInUser.LastLoginAt.Valid)

	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertExpectations(t)
}

func TestLogout_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository) // Not used directly in Logout
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "valid_refresh_token"
	hashedToken := "hashed_valid_refresh_token"
	tokenID := uuid.New()
	userID := uuid.New()

	existingToken := &token.RefreshToken{
		ID:        tokenID,
		UserID:    userID,
		TokenHash: hashedToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
	}

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(existingToken, nil)
	mockTokenRepo.On("MarkRevoked", ctx, tokenID).Return(nil)

	err := authService.Logout(ctx, refreshTokenString)

	assert.NoError(t, err)
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

func TestLogout_TokenNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "nonexistent_token"
	hashedToken := "hashed_nonexistent_token"

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(nil, token.ErrTokenNotFound)

	err := authService.Logout(ctx, refreshTokenString)

	assert.Error(t, err)
	assert.Equal(t, ErrTokenInvalid, err)
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenRepo.AssertNotCalled(t, "MarkRevoked")
}

func TestLogout_TokenAlreadyRevoked(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "revoked_token"
	hashedToken := "hashed_revoked_token"
	tokenID := uuid.New()

	existingToken := &token.RefreshToken{
		ID:        tokenID,
		TokenHash: hashedToken,
		Revoked:   true, // Key difference
	}

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(existingToken, nil)

	err := authService.Logout(ctx, refreshTokenString)

	assert.NoError(t, err) // Logging out an already revoked token is not an error
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenRepo.AssertNotCalled(t, "MarkRevoked") // Should not be called again
}

func TestLogout_TokenReused(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "reused_token"
	hashedToken := "hashed_reused_token"
	tokenID := uuid.New()

	existingToken := &token.RefreshToken{
		ID:         tokenID,
		TokenHash:  hashedToken,
		Revoked:    false,
		ReplacedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}, // Key difference
	}

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(existingToken, nil)

	err := authService.Logout(ctx, refreshTokenString)

	assert.NoError(t, err) // Logging out a reused (rotated) token is not an error by itself for logout
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenRepo.AssertNotCalled(t, "MarkRevoked")
}

func TestLogout_FindByTokenHashError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "error_token"
	hashedToken := "hashed_error_token"

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(nil, assert.AnError) // Simulate DB error

	err := authService.Logout(ctx, refreshTokenString)

	assert.Error(t, err)
	assert.NotEqual(t, ErrTokenInvalid, err)
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockTokenRepo.AssertNotCalled(t, "MarkRevoked")
}

func TestLogout_MarkRevokedError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	refreshTokenString := "mark_error_token"
	hashedToken := "hashed_mark_error_token"
	tokenID := uuid.New()

	existingToken := &token.RefreshToken{
		ID:        tokenID,
		TokenHash: hashedToken,
		Revoked:   false,
	}

	mockTokenSvc.On("HashToken", refreshTokenString).Return(hashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedToken).Return(existingToken, nil)
	mockTokenRepo.On("MarkRevoked", ctx, tokenID).Return(assert.AnError) // Simulate DB error

	err := authService.Logout(ctx, refreshTokenString)

	assert.Error(t, err)
	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
}

func TestRefreshToken_Success(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()

	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)

	ctx := context.Background()
	oldRefreshTokenString := "old_refresh_token"
	oldHashedToken := "hashed_old_refresh_token"
	userID := uuid.New()
	oldTokenID := uuid.New()

	existingUser := &user.User{ID: userID, Email: "test@example.com", Role: user.RoleUser, Status: user.StatusActive}
	oldTokenData := &token.RefreshToken{
		ID:        oldTokenID,
		UserID:    userID,
		TokenHash: oldHashedToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
	}

	newAccessToken := "new_access_token"
	newRefreshTokenString := "new_refresh_token_string"
	newRefreshTokenData := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: "hashed_new_refresh_token",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(oldHashedToken)
	mockTokenRepo.On("FindByTokenHash", ctx, oldHashedToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, userID, string(existingUser.Role)).Return(newAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, userID).Return(newRefreshTokenData, newRefreshTokenString, nil)
	mockTokenRepo.On("MarkReplaced", ctx, oldTokenID, newRefreshTokenData.ID).Return(nil)

	accessToken, refreshTokenStr, expiresAt, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.NoError(t, err)
	assert.Equal(t, newAccessToken, accessToken)
	assert.Equal(t, newRefreshTokenString, refreshTokenStr)
	assert.Equal(t, newRefreshTokenData.ExpiresAt, expiresAt)

	mockTokenSvc.AssertExpectations(t)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestRefreshToken_OldTokenNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	oldRefreshTokenString := "nonexistent_token"
	hashedOldToken := "hashed_nonexistent_token"

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(nil, token.ErrTokenNotFound)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.ErrorIs(t, err, ErrTokenInvalid)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertNotCalled(t, "FindByID")
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
	mockTokenRepo.AssertNotCalled(t, "MarkReplaced")
}

func TestRefreshToken_OldTokenRevoked(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	oldRefreshTokenString := "revoked_token"
	hashedOldToken := "hashed_revoked_token"
	userID := uuid.New()

	oldTokenData := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hashedOldToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   true, // Key difference
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.ErrorIs(t, err, ErrTokenRevoked)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertNotCalled(t, "FindByID")
}

func TestRefreshToken_OldTokenReused(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	oldRefreshTokenString := "reused_token"
	hashedOldToken := "hashed_reused_token"
	userID := uuid.New()
	replacedByTokenID := uuid.New()

	oldTokenData := &token.RefreshToken{
		ID:         uuid.New(),
		UserID:     userID,
		TokenHash:  hashedOldToken,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Revoked:    false,
		ReplacedBy: uuid.NullUUID{UUID: replacedByTokenID, Valid: true}, // Key difference
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockTokenRepo.On("MarkRevoked", ctx, replacedByTokenID).Return(nil) // Expect subsequent token to be revoked

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.ErrorIs(t, err, ErrTokenReused)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertNotCalled(t, "FindByID")
}

func TestRefreshToken_OldTokenExpired(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	oldRefreshTokenString := "expired_token"
	hashedOldToken := "hashed_expired_token"
	userID := uuid.New()

	oldTokenData := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hashedOldToken,
		ExpiresAt: time.Now().Add(-24 * time.Hour), // Key difference: expired
		Revoked:   false,
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.ErrorIs(t, err, ErrTokenInvalid)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertNotCalled(t, "FindByID")
}

func TestRefreshToken_UserNotFound(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	userID := uuid.New()
	oldRefreshTokenString := "user_not_found_token"
	hashedOldToken := "hashed_user_not_found_token"

	oldTokenData := &token.RefreshToken{
		ID:        uuid.New(),
		UserID:    userID,
		TokenHash: hashedOldToken,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Revoked:   false,
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(nil, user.ErrUserNotFound)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.ErrorIs(t, err, ErrUserNotFound)
	mockTokenRepo.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
	mockTokenSvc.AssertNotCalled(t, "GenerateAccessToken")
}

// Add tests for other error scenarios: FindByTokenHash error, FindByID error, GenerateAccessToken error, GenerateRefreshToken error, MarkReplaced error

func TestRefreshToken_FindByTokenHashError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	oldRefreshTokenString := "db_error_token"
	hashedOldToken := "hashed_db_error_token"

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(nil, assert.AnError) // Simulate DB error

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrTokenInvalid)
	mockTokenRepo.AssertExpectations(t)
}

func TestRefreshToken_FindUserByIDError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	userID := uuid.New()
	oldRefreshTokenString := "user_db_error_token"
	hashedOldToken := "hashed_user_db_error_token"

	oldTokenData := &token.RefreshToken{
		ID: uuid.New(), UserID: userID, TokenHash: hashedOldToken, ExpiresAt: time.Now().Add(time.Hour), Revoked: false,
	}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(nil, assert.AnError) // Simulate DB error

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrUserNotFound)
	mockUserRepo.AssertExpectations(t)
}

func TestRefreshToken_GenerateAccessTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	userID := uuid.New()
	existingUser := &user.User{ID: userID, Role: user.RoleUser}
	oldRefreshTokenString := "gen_access_token_error"
	hashedOldToken := "hashed_gen_access_token_error"
	oldTokenData := &token.RefreshToken{ID: uuid.New(), UserID: userID, TokenHash: hashedOldToken, ExpiresAt: time.Now().Add(time.Hour)}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, userID, string(existingUser.Role)).Return("", assert.AnError)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.Error(t, err)
	mockTokenSvc.AssertCalled(t, "GenerateAccessToken", ctx, userID, string(existingUser.Role))
	mockTokenSvc.AssertNotCalled(t, "GenerateRefreshToken")
}

func TestRefreshToken_GenerateRefreshTokenError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	userID := uuid.New()
	existingUser := &user.User{ID: userID, Role: user.RoleUser}
	oldRefreshTokenString := "gen_refresh_token_error"
	hashedOldToken := "hashed_gen_refresh_token_error"
	newAccessToken := "new_valid_access_token"
	oldTokenData := &token.RefreshToken{ID: uuid.New(), UserID: userID, TokenHash: hashedOldToken, ExpiresAt: time.Now().Add(time.Hour)}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, userID, string(existingUser.Role)).Return(newAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, userID).Return(nil, "", assert.AnError)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.Error(t, err)
	mockTokenSvc.AssertCalled(t, "GenerateRefreshToken", ctx, userID)
	mockTokenRepo.AssertNotCalled(t, "MarkReplaced")
}

func TestRefreshToken_MarkReplacedError(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockTokenRepo := new(MockTokenRepository)
	mockTokenSvc := new(MockTokenService)
	logger := newTestLogger()
	authService := NewService(mockUserRepo, mockTokenRepo, mockTokenSvc, logger)
	ctx := context.Background()
	userID := uuid.New()
	oldTokenID := uuid.New()
	existingUser := &user.User{ID: userID, Role: user.RoleUser}
	oldRefreshTokenString := "mark_replaced_error_token"
	hashedOldToken := "hashed_mark_replaced_error_token"
	oldTokenData := &token.RefreshToken{ID: oldTokenID, UserID: userID, TokenHash: hashedOldToken, ExpiresAt: time.Now().Add(time.Hour)}
	newAccessToken := "new_access_token"
	newRefreshTokenString := "new_refresh_token_string"
	newRefreshTokenData := &token.RefreshToken{ID: uuid.New(), UserID: userID, ExpiresAt: time.Now().Add(7 * 24 * time.Hour)}

	mockTokenSvc.On("HashToken", oldRefreshTokenString).Return(hashedOldToken)
	mockTokenRepo.On("FindByTokenHash", ctx, hashedOldToken).Return(oldTokenData, nil)
	mockUserRepo.On("FindByID", ctx, userID).Return(existingUser, nil)
	mockTokenSvc.On("GenerateAccessToken", ctx, userID, string(existingUser.Role)).Return(newAccessToken, nil)
	mockTokenSvc.On("GenerateRefreshToken", ctx, userID).Return(newRefreshTokenData, newRefreshTokenString, nil)
	mockTokenRepo.On("MarkReplaced", ctx, oldTokenID, newRefreshTokenData.ID).Return(assert.AnError)

	_, _, _, err := authService.RefreshToken(ctx, oldRefreshTokenString)

	assert.Error(t, err) // The error from MarkReplaced should be propagated
	mockTokenRepo.AssertCalled(t, "MarkReplaced", ctx, oldTokenID, newRefreshTokenData.ID)
}
