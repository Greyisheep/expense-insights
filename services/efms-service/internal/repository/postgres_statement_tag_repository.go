package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
	"github.com/google/uuid"
)

// NewPostgresStatementTagRepository creates a new instance of StatementTagRepository.
func NewPostgresStatementTagRepository(queries *sqlc.Queries) StatementTagRepository {
	return &postgresStatementTagRepository{queries: queries}
}

type postgresStatementTagRepository struct {
	queries *sqlc.Queries
}

func (r *postgresStatementTagRepository) AddTagToStatement(ctx context.Context, arg sqlc.AddTagToStatementParams) (sqlc.StatementTag, error) {
	return r.queries.AddTagToStatement(ctx, arg)
}

func (r *postgresStatementTagRepository) GetTagsForStatement(ctx context.Context, statementID uuid.UUID) ([]string, error) {
	return r.queries.GetTagsForStatement(ctx, statementID)
}

func (r *postgresStatementTagRepository) RemoveTagFromStatement(ctx context.Context, arg sqlc.RemoveTagFromStatementParams) error {
	return r.queries.RemoveTagFromStatement(ctx, arg)
}

func (r *postgresStatementTagRepository) RemoveAllTagsFromStatement(ctx context.Context, statementID uuid.UUID) error {
	return r.queries.RemoveAllTagsFromStatement(ctx, statementID)
}

func (r *postgresStatementTagRepository) ListStatementsByTagAndUser(ctx context.Context, arg sqlc.ListStatementsByTagAndUserParams) ([]sqlc.ListStatementsByTagAndUserRow, error) {
	return r.queries.ListStatementsByTagAndUser(ctx, arg)
}
