package repository

import (
	"context"

	"github.com/Greyisheep/expense-insights/efms-service/internal/repository/sqlc"
)

// UploadRepository defines the interface for upload data operations.
// It will typically be a subset of the sqlc.Querier interface methods related to uploads.
type UploadRepository interface {
	CreateUpload(ctx context.Context, arg sqlc.CreateUploadParams) (sqlc.Upload, error)
	GetUpload(ctx context.Context, arg sqlc.GetUploadParams) (sqlc.Upload, error)
	GetUploadByFileNameAndUser(ctx context.Context, arg sqlc.GetUploadByFileNameAndUserParams) (sqlc.Upload, error)
	UpdateUploadStatus(ctx context.Context, arg sqlc.UpdateUploadStatusParams) (sqlc.Upload, error)
	DeleteUpload(ctx context.Context, arg sqlc.DeleteUploadParams) error
}
