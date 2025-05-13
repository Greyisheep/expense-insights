package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
)

// NewPostgresUploadRepository creates a new instance of UploadRepository using sqlc.Queries.
func NewPostgresUploadRepository(queries *sqlc.Queries) UploadRepository {
	return &postgresUploadRepository{queries: queries}
}

type postgresUploadRepository struct {
	queries *sqlc.Queries
}

func (r *postgresUploadRepository) CreateUpload(ctx context.Context, arg sqlc.CreateUploadParams) (sqlc.Upload, error) {
	return r.queries.CreateUpload(ctx, arg)
}

func (r *postgresUploadRepository) GetUpload(ctx context.Context, arg sqlc.GetUploadParams) (sqlc.Upload, error) {
	return r.queries.GetUpload(ctx, arg)
}

func (r *postgresUploadRepository) GetUploadByFileNameAndUser(ctx context.Context, arg sqlc.GetUploadByFileNameAndUserParams) (sqlc.Upload, error) {
	return r.queries.GetUploadByFileNameAndUser(ctx, arg)
}

func (r *postgresUploadRepository) UpdateUploadStatus(ctx context.Context, arg sqlc.UpdateUploadStatusParams) (sqlc.Upload, error) {
	return r.queries.UpdateUploadStatus(ctx, arg)
}

func (r *postgresUploadRepository) DeleteUpload(ctx context.Context, arg sqlc.DeleteUploadParams) error {
	return r.queries.DeleteUpload(ctx, arg)
}
