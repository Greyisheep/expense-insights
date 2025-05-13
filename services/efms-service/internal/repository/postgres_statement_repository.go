package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
)

// NewPostgresStatementRepository creates a new instance of StatementRepository.
func NewPostgresStatementRepository(queries *sqlc.Queries) StatementRepository {
	return &postgresStatementRepository{queries: queries}
}

type postgresStatementRepository struct {
	queries *sqlc.Queries
}

func (r *postgresStatementRepository) CreateStatement(ctx context.Context, arg sqlc.CreateStatementParams) (sqlc.Statement, error) {
	return r.queries.CreateStatement(ctx, arg)
}

func (r *postgresStatementRepository) GetStatementByIDAndUser(ctx context.Context, arg sqlc.GetStatementByIDAndUserParams) (sqlc.Statement, error) {
	return r.queries.GetStatementByIDAndUser(ctx, arg)
}

func (r *postgresStatementRepository) GetStatementStatusByIDAndUser(ctx context.Context, arg sqlc.GetStatementStatusByIDAndUserParams) (sqlc.GetStatementStatusByIDAndUserRow, error) {
	return r.queries.GetStatementStatusByIDAndUser(ctx, arg)
}

func (r *postgresStatementRepository) ListStatementsByUser(ctx context.Context, arg sqlc.ListStatementsByUserParams) ([]sqlc.ListStatementsByUserRow, error) {
	return r.queries.ListStatementsByUser(ctx, arg)
}

func (r *postgresStatementRepository) UpdateStatementMetadataByIDAndUser(ctx context.Context, arg sqlc.UpdateStatementMetadataByIDAndUserParams) (sqlc.Statement, error) {
	return r.queries.UpdateStatementMetadataByIDAndUser(ctx, arg)
}

func (r *postgresStatementRepository) UpdateStatementStatusAndProgress(ctx context.Context, arg sqlc.UpdateStatementStatusAndProgressParams) (sqlc.Statement, error) {
	return r.queries.UpdateStatementStatusAndProgress(ctx, arg)
}

func (r *postgresStatementRepository) DeleteStatementByIDAndUser(ctx context.Context, arg sqlc.DeleteStatementByIDAndUserParams) error {
	return r.queries.DeleteStatementByIDAndUser(ctx, arg)
}
