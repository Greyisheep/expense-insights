// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package db

import (
	"context"
	"database/sql"
	"fmt"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

func Prepare(ctx context.Context, db DBTX) (*Queries, error) {
	q := Queries{db: db}
	var err error
	if q.createRefreshTokenStmt, err = db.PrepareContext(ctx, createRefreshToken); err != nil {
		return nil, fmt.Errorf("error preparing query CreateRefreshToken: %w", err)
	}
	if q.createUserStmt, err = db.PrepareContext(ctx, createUser); err != nil {
		return nil, fmt.Errorf("error preparing query CreateUser: %w", err)
	}
	if q.deleteExpiredRefreshTokensStmt, err = db.PrepareContext(ctx, deleteExpiredRefreshTokens); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteExpiredRefreshTokens: %w", err)
	}
	if q.deleteRefreshTokensByUserIDStmt, err = db.PrepareContext(ctx, deleteRefreshTokensByUserID); err != nil {
		return nil, fmt.Errorf("error preparing query DeleteRefreshTokensByUserID: %w", err)
	}
	if q.getRefreshTokenByIDStmt, err = db.PrepareContext(ctx, getRefreshTokenByID); err != nil {
		return nil, fmt.Errorf("error preparing query GetRefreshTokenByID: %w", err)
	}
	if q.getRefreshTokenByTokenStmt, err = db.PrepareContext(ctx, getRefreshTokenByToken); err != nil {
		return nil, fmt.Errorf("error preparing query GetRefreshTokenByToken: %w", err)
	}
	if q.getRefreshTokensByUserIDStmt, err = db.PrepareContext(ctx, getRefreshTokensByUserID); err != nil {
		return nil, fmt.Errorf("error preparing query GetRefreshTokensByUserID: %w", err)
	}
	if q.getUserByEmailStmt, err = db.PrepareContext(ctx, getUserByEmail); err != nil {
		return nil, fmt.Errorf("error preparing query GetUserByEmail: %w", err)
	}
	if q.getUserByIDStmt, err = db.PrepareContext(ctx, getUserByID); err != nil {
		return nil, fmt.Errorf("error preparing query GetUserByID: %w", err)
	}
	if q.revokeRefreshTokenStmt, err = db.PrepareContext(ctx, revokeRefreshToken); err != nil {
		return nil, fmt.Errorf("error preparing query RevokeRefreshToken: %w", err)
	}
	if q.setRefreshTokenReplacedByStmt, err = db.PrepareContext(ctx, setRefreshTokenReplacedBy); err != nil {
		return nil, fmt.Errorf("error preparing query SetRefreshTokenReplacedBy: %w", err)
	}
	if q.updateUserStmt, err = db.PrepareContext(ctx, updateUser); err != nil {
		return nil, fmt.Errorf("error preparing query UpdateUser: %w", err)
	}
	return &q, nil
}

func (q *Queries) Close() error {
	var err error
	if q.createRefreshTokenStmt != nil {
		if cerr := q.createRefreshTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createRefreshTokenStmt: %w", cerr)
		}
	}
	if q.createUserStmt != nil {
		if cerr := q.createUserStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createUserStmt: %w", cerr)
		}
	}
	if q.deleteExpiredRefreshTokensStmt != nil {
		if cerr := q.deleteExpiredRefreshTokensStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteExpiredRefreshTokensStmt: %w", cerr)
		}
	}
	if q.deleteRefreshTokensByUserIDStmt != nil {
		if cerr := q.deleteRefreshTokensByUserIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deleteRefreshTokensByUserIDStmt: %w", cerr)
		}
	}
	if q.getRefreshTokenByIDStmt != nil {
		if cerr := q.getRefreshTokenByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getRefreshTokenByIDStmt: %w", cerr)
		}
	}
	if q.getRefreshTokenByTokenStmt != nil {
		if cerr := q.getRefreshTokenByTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getRefreshTokenByTokenStmt: %w", cerr)
		}
	}
	if q.getRefreshTokensByUserIDStmt != nil {
		if cerr := q.getRefreshTokensByUserIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getRefreshTokensByUserIDStmt: %w", cerr)
		}
	}
	if q.getUserByEmailStmt != nil {
		if cerr := q.getUserByEmailStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getUserByEmailStmt: %w", cerr)
		}
	}
	if q.getUserByIDStmt != nil {
		if cerr := q.getUserByIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getUserByIDStmt: %w", cerr)
		}
	}
	if q.revokeRefreshTokenStmt != nil {
		if cerr := q.revokeRefreshTokenStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing revokeRefreshTokenStmt: %w", cerr)
		}
	}
	if q.setRefreshTokenReplacedByStmt != nil {
		if cerr := q.setRefreshTokenReplacedByStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing setRefreshTokenReplacedByStmt: %w", cerr)
		}
	}
	if q.updateUserStmt != nil {
		if cerr := q.updateUserStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updateUserStmt: %w", cerr)
		}
	}
	return err
}

func (q *Queries) exec(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (sql.Result, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	case stmt != nil:
		return stmt.ExecContext(ctx, args...)
	default:
		return q.db.ExecContext(ctx, query, args...)
	}
}

func (q *Queries) query(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (*sql.Rows, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryContext(ctx, args...)
	default:
		return q.db.QueryContext(ctx, query, args...)
	}
}

func (q *Queries) queryRow(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) *sql.Row {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryRowContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryRowContext(ctx, args...)
	default:
		return q.db.QueryRowContext(ctx, query, args...)
	}
}

type Queries struct {
	db                              DBTX
	tx                              *sql.Tx
	createRefreshTokenStmt          *sql.Stmt
	createUserStmt                  *sql.Stmt
	deleteExpiredRefreshTokensStmt  *sql.Stmt
	deleteRefreshTokensByUserIDStmt *sql.Stmt
	getRefreshTokenByIDStmt         *sql.Stmt
	getRefreshTokenByTokenStmt      *sql.Stmt
	getRefreshTokensByUserIDStmt    *sql.Stmt
	getUserByEmailStmt              *sql.Stmt
	getUserByIDStmt                 *sql.Stmt
	revokeRefreshTokenStmt          *sql.Stmt
	setRefreshTokenReplacedByStmt   *sql.Stmt
	updateUserStmt                  *sql.Stmt
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db:                              tx,
		tx:                              tx,
		createRefreshTokenStmt:          q.createRefreshTokenStmt,
		createUserStmt:                  q.createUserStmt,
		deleteExpiredRefreshTokensStmt:  q.deleteExpiredRefreshTokensStmt,
		deleteRefreshTokensByUserIDStmt: q.deleteRefreshTokensByUserIDStmt,
		getRefreshTokenByIDStmt:         q.getRefreshTokenByIDStmt,
		getRefreshTokenByTokenStmt:      q.getRefreshTokenByTokenStmt,
		getRefreshTokensByUserIDStmt:    q.getRefreshTokensByUserIDStmt,
		getUserByEmailStmt:              q.getUserByEmailStmt,
		getUserByIDStmt:                 q.getUserByIDStmt,
		revokeRefreshTokenStmt:          q.revokeRefreshTokenStmt,
		setRefreshTokenReplacedByStmt:   q.setRefreshTokenReplacedByStmt,
		updateUserStmt:                  q.updateUserStmt,
	}
}
