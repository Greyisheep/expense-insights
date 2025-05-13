package domain

import (
	"time"

	"github.com/google/uuid"
)

// UploadStatus defines the possible statuses for an upload.
// Example: pending, uploaded, processing_initiated, processing_failed, completed
type UploadStatus string

const (
	UploadStatusPending             UploadStatus = "pending"              // Initial status after presign, before client uploads to S3
	UploadStatusUploaded            UploadStatus = "uploaded"             // Client has successfully uploaded to S3, EFMS confirmed via event
	UploadStatusStatementRegistered UploadStatus = "statement_registered" // /statements POST call made, linked to a statement
	UploadStatusError               UploadStatus = "error"                // An error occurred during any part of the upload or initial processing
)

// Upload represents a file uploaded by a user.
// This record is created when a presigned URL is requested.
// Its status is updated as the file moves through the initial stages.	ype Upload struct {
	ID            uuid.UUID    `json:"id" db:"id"`                                       // Primary Key
	UserID        uuid.UUID    `json:"user_id" db:"user_id"`                             // FK to users table
	FileName      string       `json:"file_name" db:"file_name"`                         // Original file name
	ContentType   string       `json:"content_type" db:"content_type"`                   // MIME type
	Status        UploadStatus `json:"status" db:"status"`                               // Current status of the upload
	StoragePath   string       `json:"storage_path,omitempty" db:"storage_path"`         // Path in S3/MinIO (e.g., user_id/upload_id/file_name)
	SizeBytes     *int64       `json:"size_bytes,omitempty" db:"size_bytes"`             // Size of the uploaded file, nullable
	ErrorMessage  *string      `json:"error_message,omitempty" db:"error_message"`      // Error message if status is 'error', nullable
	PresignExpiry *time.Time   `json:"presign_expiry,omitempty" db:"presign_expiry"`      // When the presigned URL expires, nullable
	CreatedAt     time.Time    `json:"created_at" db:"created_at"`                       // Timestamp of creation (presign request)
	UpdatedAt     time.Time    `json:"updated_at" db:"updated_at"`                       // Timestamp of last update
	// UpdatedBy is not directly in the table schema provided, user_id implies ownership.
	// If needed, add UpdatedBy uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
}

// PresignRequestMetadata contains metadata provided by the client during presign request.
// This might be stored in the `uploads` table or passed through to `statements` later.
// For now, keeping it separate from the core Upload struct fields that map directly to db columns.
// The API spec shows statement_date, bank_name, tags in metadata for POST /uploads/presign
// These fields align more with the `Statement` entity.
// So, EFMS might create an Upload record, and when POST /statements is called,
// it uses the upload_id and then these metadata fields to create the Statement record.

// PresignResponseData is the data part of the presign URL response.
type PresignResponseData struct {
	UploadID string      `json:"upload_id"`
	URL      string      `json:"url"`
	Method   string      `json:"method"`         // e.g., "PUT"
	Fields   interface{} `json:"fields,omitempty"` // For S3 POST policy fields, usually null for PUT
} 