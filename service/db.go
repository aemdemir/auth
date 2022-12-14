package service

import (
	"context"
	"database/sql"
	"time"

	"github.com/jmoiron/sqlx"
)

type DB struct {
	*sqlx.DB
}

func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	tx, err := db.BeginTxx(ctx, opts)
	if err != nil {
		return nil, err
	}

	return &Tx{
		Tx:  tx,
		db:  db,
		now: time.Now().Truncate(time.Second),
	}, nil
}

func (db *DB) WithTransaction(ctx context.Context, opts *sql.TxOptions, fnx func(tx *Tx) error) error {
	tx, err := db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := fnx(tx); err != nil {
		return err
	}
	return tx.Commit()
}

type Tx struct {
	*sqlx.Tx
	db  *DB
	now time.Time
}

func (tx *Tx) WithSavepoint(ctx context.Context, fnx func(tx *Tx) error) error {
	_, err := tx.ExecContext(ctx, "SAVEPOINT sp")
	if err != nil {
		return err
	}
	defer tx.ExecContext(ctx, "RELEASE SAVEPOINT sp")

	if err := fnx(tx); err != nil {
		tx.ExecContext(ctx, "ROLLBACK TO SAVEPOINT sp")
		return err
	}
	return nil
}

type DBTX interface {
	// sqlx
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	SelectContext(ctx context.Context, dest any, query string, args ...any) error
	NamedExecContext(ctx context.Context, query string, arg any) (sql.Result, error)
	BindNamed(query string, arg any) (string, []any, error)
	// sql
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}
