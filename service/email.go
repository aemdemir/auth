package service

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/aemdemir/auth"
	"github.com/jackc/pgconn"
)

//
// db
//

type dbEmail struct {
	UserID   int       `db:"user_id"`
	Address  string    `db:"address"`
	Primary  bool      `db:"is_primary"`
	Verified bool      `db:"verified"`
	Created  time.Time `db:"created"`
	Updated  time.Time `db:"updated"`
}

func getEmail(ctx context.Context, dbx DBTX, address string) (*dbEmail, error) {
	query := `
	SELECT 
		user_id, 
		address, 
		is_primary, 
		verified, 
		created, 
		updated
	FROM  user_email
	WHERE address = $1
	`

	e := dbEmail{}

	err := dbx.GetContext(ctx, &e, query, address)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching email found"}
		default:
			return nil, err
		}
	}
	return &e, nil
}

func getEmailByUser(ctx context.Context, dbx DBTX, id int) (*dbEmail, error) {
	query := `
	SELECT 
		user_id, 
		address, 
		is_primary, 
		verified, 
		created, 
		updated
	FROM  user_email
	WHERE user_id = $1
	`

	e := dbEmail{}

	err := dbx.GetContext(ctx, &e, query, id)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching email found"}
		default:
			return nil, err
		}
	}
	return &e, nil
}

func getEmailByValidToken(ctx context.Context, dbx DBTX, hash []byte, scope string) (*dbEmail, error) {
	query := `
	SELECT 
		user_id, 
		address, 
		is_primary, 
		verified, 
		created, 
		updated
	FROM  user_email
	WHERE address = (
		SELECT payload 
		FROM   token 
		WHERE  hash = $1 AND scope = $2 AND revoked = false AND expiry > $3
	)
	`

	e := dbEmail{}

	err := dbx.GetContext(ctx, &e, query, hash, scope, time.Now())
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			return nil, &auth.Error{Code: auth.ENOTFOUND, Message: "no matching email found"}
		default:
			return nil, err
		}
	}
	return &e, nil
}

func getEmailsByUser(ctx context.Context, dbx DBTX, id int) ([]dbEmail, error) {
	query := `
	SELECT 
		user_id, 
		address, 
		is_primary, 
		verified, 
		created, 
		updated
	FROM  user_email 
	WHERE user_id = $1
	`

	e := []dbEmail{}

	err := dbx.SelectContext(ctx, &e, query, id)
	return e, err
}

type dbEmailInsert struct {
	UserID  int
	Address string
	Primary bool
}

func insertEmail(ctx context.Context, dbx DBTX, in dbEmailInsert) error {
	query := `
	INSERT INTO user_email
	(
		user_id,
		address,
		is_primary
	)
	VALUES (:user_id, :address, :is_primary)
	`

	e := dbEmail{
		UserID:  in.UserID,
		Address: in.Address,
		Primary: in.Primary,
	}

	_, err := dbx.NamedExecContext(ctx, query, e)
	if err != nil {
		var dbErr *pgconn.PgError
		switch {
		case errors.As(err, &dbErr) && dbErr.Code == "23505":
			return &auth.Error{Code: auth.EUNPROCESSABLE, Message: "duplicate email address"}
		default:
			return err
		}
	}
	return nil
}

type dbEmailUpdate struct {
	Address  string
	Primary  bool
	Verified bool
}

func updateEmail(ctx context.Context, dbx DBTX, up dbEmailUpdate) error {
	query := `
	UPDATE user_email
	SET
		is_primary = :is_primary,
		verified   = :verified
	WHERE
		address = :address
	`

	e := dbEmail{
		Address:  up.Address,
		Primary:  up.Primary,
		Verified: up.Verified,
	}

	_, err := dbx.NamedExecContext(ctx, query, e)
	return err
}

func resetPrimaryEmail(ctx context.Context, dbx DBTX, userID int) error {
	query := `
	UPDATE user_email
	SET    is_primary = false
	WHERE  user_id = $1
	`

	_, err := dbx.ExecContext(ctx, query, userID)
	return err
}

//
// conversion
//

func toAuthEmail(e *dbEmail) *auth.Email {
	return &auth.Email{
		UserID:   e.UserID,
		Address:  e.Address,
		Primary:  e.Primary,
		Verified: e.Verified,
		Created:  e.Created,
		Updated:  e.Updated,
	}
}

func toAuthEmails(ss []dbEmail) []auth.Email {
	rr := make([]auth.Email, len(ss))
	for i, e := range ss {
		rr[i] = *toAuthEmail(&e)
	}
	return rr
}
