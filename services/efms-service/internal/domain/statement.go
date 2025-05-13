package domain

import (
	"time"

	"github.com/google/uuid"
)

// StatementStatus defines the possible statuses for a statement.
type StatementStatus string

const (
	StatementStatusPendingFile StatementStatus = "pending_file_confirmation" // Initial: /statements called, but file not yet confirmed by S3 event
	StatementStatusProcessing  StatementStatus = "processing"                // File confirmed, processing (e.g., by ETL) has been initiated
	StatementStatusCompleted   StatementStatus = "completed"                 // Processing finished successfully, insights might be available
	StatementStatusFailed      StatementStatus = "failed"                    // Processing failed
	StatementStatusArchived    StatementStatus = "archived"                  // Statement has been archived (soft delete)
)

// Statement represents a processed (or processing) bank statement.
// This record is typically created after a file upload is confirmed and registered via /statements POST.
type Statement struct {
	SubmissionID       uuid.UUID       `json:"submission_id" db:"submission_id"`                       // Primary Key (renamed from id to match API spec)
	UserID             uuid.UUID       `json:"user_id" db:"user_id"`                                   // FK to users table
	UploadID           uuid.UUID       `json:"upload_id" db:"upload_id"`                               // FK to uploads table
	Description        *string         `json:"description,omitempty" db:"description"`                 // Optional user-provided description
	StatementDate      *time.Time      `json:"statement_date,omitempty" db:"statement_date"`           // Date of the statement (e.g., end of month for a monthly statement)
	BankName           *string         `json:"bank_name,omitempty" db:"bank_name"`                     // Name of the bank, nullable
	Status             StatementStatus `json:"status" db:"status"`                                     // Current status of the statement processing
	ProcessingProgress *int            `json:"processing_progress,omitempty" db:"processing_progress"` // Optional progress percentage (0-100)
	ErrorMessage       *string         `json:"error_message,omitempty" db:"error_message"`             // Error message if status is 'failed'
	InsightsAvailable  bool            `json:"insights_available" db:"insights_available"`             // True if insights have been generated for this statement
	CreatedAt          time.Time       `json:"created_at" db:"created_at"`                             // Timestamp of creation
	UpdatedAt          time.Time       `json:"updated_at" db:"updated_at"`                             // Timestamp of last update
	// UpdatedBy uuid.UUID `json:"updated_by,omitempty" db:"updated_by"` // From spec, FK to users. Consider if EFMS updates this or if it's an event from another service.

	// Tags are handled via a separate StatementTag entity and join table
	// For API responses, tags might be embedded.
	Tags []string `json:"tags,omitempty" db:"-"` // Loaded separately, not a direct DB column in this table
}

// StatementTag represents a tag associated with a statement.
// This corresponds to the statement_tags join table.
type StatementTag struct {
	ID          uuid.UUID `json:"id" db:"id"`                     // Primary Key of the tag entry itself
	StatementID uuid.UUID `json:"statement_id" db:"statement_id"` // FK to statements.submission_id
	Tag         string    `json:"tag" db:"tag"`                   // The tag string
	CreatedAt   time.Time `json:"created_at" db:"created_at"`     // Timestamp of tag creation
}

// CreateStatementRequest mirrors the API spec for POST /statements
type CreateStatementRequest struct {
	UploadID    uuid.UUID `json:"upload_id"`             // Required
	Description *string   `json:"description,omitempty"` // Optional
	// The API spec (2.2) for POST /statements only has upload_id and description.
	// Other fields like bank_name, statement_date, tags are part of the presign metadata (API Spec 2.1)
	// This implies that when POST /statements is called, EFMS should perhaps:
	// 1. Look up the Upload record by upload_id.
	// 2. Retrieve any metadata (like bank_name, statement_date, initial tags) associated with that Upload (e.g. if we decide to store them on the uploads table from presign).
	// 3. Use these to populate the new Statement record.
}

// UpdateStatementRequest mirrors the API spec for PUT /statements/{submission_id}
// Body any of { statement_date, bank_name, tags, description }
type UpdateStatementRequest struct {
	StatementDate *time.Time `json:"statement_date,omitempty"`
	BankName      *string    `json:"bank_name,omitempty"`
	Tags          []string   `json:"tags,omitempty"` // If tags are updated, logic needs to handle add/remove from statement_tags table
	Description   *string    `json:"description,omitempty"`
}
