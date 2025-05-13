package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
	// Used by sqlc generated types
)

// StatementRepository defines the interface for statement data operations.
type StatementRepository interface {
	CreateStatement(ctx context.Context, arg sqlc.CreateStatementParams) (sqlc.Statement, error)
	GetStatementByIDAndUser(ctx context.Context, arg sqlc.GetStatementByIDAndUserParams) (sqlc.Statement, error)
	GetStatementStatusByIDAndUser(ctx context.Context, arg sqlc.GetStatementStatusByIDAndUserParams) (sqlc.GetStatementStatusByIDAndUserRow, error)
	ListStatementsByUser(ctx context.Context, arg sqlc.ListStatementsByUserParams) ([]sqlc.ListStatementsByUserRow, error)
	UpdateStatementMetadataByIDAndUser(ctx context.Context, arg sqlc.UpdateStatementMetadataByIDAndUserParams) (sqlc.Statement, error)
	UpdateStatementStatusAndProgress(ctx context.Context, arg sqlc.UpdateStatementStatusAndProgressParams) (sqlc.Statement, error)
	DeleteStatementByIDAndUser(ctx context.Context, arg sqlc.DeleteStatementByIDAndUserParams) error
}
