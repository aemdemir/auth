package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aemdemir/auth"
)

//
// db
//

type dbToken struct {
	UserID  int             `db:"user_id"`
	Hash    []byte          `db:"hash"`
	Scope   string          `db:"scope"`
	Revoked bool            `db:"revoked"`
	Expiry  time.Time       `db:"expiry"`
	Payload auth.NullString `db:"payload"`
	Created time.Time       `db:"created"`
	Updated time.Time       `db:"updated"`
}

func getToken(ctx context.Context, dbx DBTX, hash []byte, scope string) (*dbToken, error) {
	query := `
	SELECT
		user_id,
		hash,
		scope,
		revoked,
		expiry,
		payload,
		created,
		updated
	FROM  token
	WHERE hash = ? AND scope = ? 
	`

	t := dbToken{}

	err := dbx.GetContext(ctx, &t, query, hash, scope)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching token found"}
		default:
			return nil, err
		}
	}
	return &t, nil
}

type dbTokenInsert struct {
	UserID  int
	Hash    []byte
	Scope   string
	Expiry  time.Time
	Payload auth.NullString
}

func insertToken(ctx context.Context, dbx DBTX, in dbTokenInsert) error {
	query := `
	INSERT INTO token 
	(
		user_id,
		hash,
		scope,
		expiry,
		payload
	)
	VALUES (:user_id, :hash, :scope, :expiry, :payload)
	`

	t := dbToken{
		UserID:  in.UserID,
		Hash:    in.Hash,
		Scope:   in.Scope,
		Expiry:  in.Expiry,
		Payload: in.Payload,
	}

	_, err := dbx.NamedExecContext(ctx, query, t)
	return err
}

func deleteToken(ctx context.Context, dbx DBTX, hash []byte) error {
	query := `DELETE FROM token WHERE hash = ?`

	_, err := dbx.ExecContext(ctx, query, hash)
	return err
}

func deleteTokensByUser(ctx context.Context, dbx DBTX, id int) error {
	query := `DELETE FROM token WHERE user_id = ?`

	_, err := dbx.ExecContext(ctx, query, id)
	return err
}

func deleteTokensByUserAndScope(ctx context.Context, dbx DBTX, id int, scope string) error {
	query := `DELETE FROM token WHERE user_id = ? AND scope = ?`

	_, err := dbx.ExecContext(ctx, query, id, scope)
	return err
}
