package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
	"github.com/google/uuid" // Used by sqlc generated types
)

// StatementTagRepository defines the interface for statement tag data operations.
type StatementTagRepository interface {
	AddTagToStatement(ctx context.Context, arg sqlc.AddTagToStatementParams) (sqlc.StatementTag, error)
	GetTagsForStatement(ctx context.Context, statementID uuid.UUID) ([]string, error)
	RemoveTagFromStatement(ctx context.Context, arg sqlc.RemoveTagFromStatementParams) error
	RemoveAllTagsFromStatement(ctx context.Context, statementID uuid.UUID) error
	ListStatementsByTagAndUser(ctx context.Context, arg sqlc.ListStatementsByTagAndUserParams) ([]sqlc.ListStatementsByTagAndUserRow, error)
}
